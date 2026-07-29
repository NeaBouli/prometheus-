"""Tests for the non-consuming ThreatHint-v2 verified preflight."""

from __future__ import annotations

import dataclasses
import hashlib
import inspect
import os
import pickle
import shlex
import stat
import threading
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import jaeger.threat_hint_v2_verified_preflight as verified_preflight_module
import pytest
from jaeger.threat_hint_v2_verified_preflight import (
    MAX_VERIFIER_EXECUTABLE_BYTES,
    ThreatHintV2VerifiedPreflightBusyError,
    ThreatHintV2VerifiedPreflightError,
    ThreatHintV2VerifiedPreflightReceipt,
    ThreatHintV2VerifiedPreflightService,
    ThreatHintV2VerifiedPreflightUnavailableError,
)
from tests.test_threat_hint_v2_preflight import _Scenario

pytestmark = pytest.mark.skipif(
    os.name != "posix", reason="verified preflight requires POSIX process controls"
)


def _write_owner_file(path: Path, contents: bytes, mode: int = 0o600) -> Path:
    path.write_bytes(contents)
    path.chmod(mode)
    return path


def _write_verifier(directory: Path, body: str, name: str = "verifier") -> Path:
    wire = f"#!/bin/sh\n{body}\n".encode("ascii")
    return _write_owner_file(directory / name, wire, 0o700)


def _write_config(
    directory: Path,
    executable: Path,
    manifest: Path,
    *,
    executable_sha256: str | None = None,
    timeout_ms: int = 30_000,
    extra: str = "",
    name: str = "verified-preflight.toml",
) -> Path:
    digest = executable_sha256 or hashlib.sha256(executable.read_bytes()).hexdigest()
    wire = "\n".join(
        (
            "schema_version = 1",
            f'verifier_executable_path = "{executable}"',
            f'verifier_executable_sha256 = "{digest}"',
            f'relation_manifest_path = "{manifest}"',
            f"verifier_timeout_ms = {timeout_ms}",
            extra,
        )
    ).encode("ascii")
    return _write_owner_file(directory / name, wire)


def _service(
    scenario: _Scenario,
    body: str = "/bin/cat >/dev/null\nexit 0",
    *,
    timeout_ms: int = 30_000,
    executable_sha256: str | None = None,
) -> tuple[ThreatHintV2VerifiedPreflightService, Path, Path, Path]:
    manifest = _write_owner_file(
        scenario.directory / "relation-manifest-v2.json",
        scenario.manifest_wire,
    )
    executable = _write_verifier(scenario.directory, body)
    config = _write_config(
        scenario.directory,
        executable,
        manifest,
        executable_sha256=executable_sha256,
        timeout_ms=timeout_ms,
    )
    return (
        ThreatHintV2VerifiedPreflightService(config, scenario.policy_path),
        executable,
        manifest,
        config,
    )


def _run(
    service: ThreatHintV2VerifiedPreflightService,
    scenario: _Scenario,
    **changes: Any,
) -> ThreatHintV2VerifiedPreflightReceipt:
    values = {
        "envelope_wire": scenario.envelope_wire,
        "bundle_wire": scenario.bundle_wire,
        "approval_wire": scenario.approval_wire,
        "report_nonce": scenario.report_nonce,
        "current_time": scenario.current_time,
    }
    values.update(changes)
    return service.preflight(
        values["envelope_wire"],
        values["bundle_wire"],
        values["approval_wire"],
        report_nonce=values["report_nonce"],
        current_time=values["current_time"],
    )


def _snapshot(root: Path) -> dict[str, tuple[int, bytes]]:
    result = {}
    for path in sorted(root.rglob("*")):
        if path.is_file() and not path.is_symlink():
            result[str(path.relative_to(root))] = (
                stat.S_IMODE(path.stat().st_mode),
                path.read_bytes(),
            )
    return result


def test_executable_ancestor_allows_only_root_owned_sticky_write_access() -> None:
    safe = (
        verified_preflight_module._is_safe_executable_ancestor
    )  # pylint: disable=protected-access
    directory = stat.S_IFDIR

    assert safe(SimpleNamespace(st_mode=directory | 0o755, st_uid=os.getuid()))
    assert safe(SimpleNamespace(st_mode=directory | 0o1777, st_uid=0))
    assert not safe(SimpleNamespace(st_mode=directory | 0o0777, st_uid=0))
    if os.getuid() != 0:
        assert not safe(SimpleNamespace(st_mode=directory | 0o1777, st_uid=os.getuid()))
    assert not safe(SimpleNamespace(st_mode=stat.S_IFREG | 0o755, st_uid=0))


def test_valid_call_uses_exact_argv_stdin_and_scrubbed_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    scenario = _Scenario(tmp_path)
    args_path = scenario.directory / "args"
    stdin_path = scenario.directory / "stdin"
    meta_path = scenario.directory / "meta"
    body = f"""
printf '%s\\n' "$PWD" > {shlex.quote(str(meta_path))}
for name in PATH LD_PRELOAD DYLD_INSERT_LIBRARIES PYTHONPATH; do
  eval 'value=${{'$name'+x}}'
  printf '%s=%s\\n' "$name" "$value" >> {shlex.quote(str(meta_path))}
done
printf '%s\\n' "$@" > {shlex.quote(str(args_path))}
/bin/cat > {shlex.quote(str(stdin_path))}
exit 0
"""
    service, executable, manifest, _ = _service(scenario, body)
    decoy = scenario.directory / "decoy"
    decoy.mkdir(mode=0o700)
    _write_verifier(decoy, f": > {shlex.quote(str(decoy / 'used'))}", executable.name)
    monkeypatch.setenv("PATH", str(decoy))
    monkeypatch.setenv("LD_PRELOAD", "/untrusted/preload")
    monkeypatch.setenv("DYLD_INSERT_LIBRARIES", "/untrusted/dylib")
    monkeypatch.setenv("PYTHONPATH", "/untrusted/python")
    child_environments: list[dict[str, str]] = []
    original_popen = verified_preflight_module.subprocess.Popen

    def tracking_popen(*args: Any, **kwargs: Any) -> Any:
        child_environments.append(dict(kwargs["env"]))
        return original_popen(*args, **kwargs)

    monkeypatch.setattr(verified_preflight_module.subprocess, "Popen", tracking_popen)

    receipt = _run(service, scenario)

    assert stdin_path.read_bytes() == scenario.envelope_wire
    assert args_path.read_text(encoding="ascii").splitlines() == [
        "verify-v2",
        "--manifest",
        str(manifest),
        "--expected-manifest-sha256",
        scenario.anchor_hex,
        "--network-id",
        scenario.vector["network_id"],
    ]
    assert meta_path.read_text(encoding="ascii").splitlines() == [
        "/",
        "PATH=x",
        "LD_PRELOAD=",
        "DYLD_INSERT_LIBRARIES=",
        "PYTHONPATH=",
    ]
    assert child_environments == [{"LANG": "C", "LC_ALL": "C"}]
    assert not (decoy / "used").exists()
    assert receipt.raw_manifest_sha256_hex == scenario.anchor_hex
    assert (
        receipt.envelope_sha256_hex
        == hashlib.sha256(scenario.envelope_wire).hexdigest()
    )
    assert (
        receipt.verifier_executable_sha256_hex
        == hashlib.sha256(executable.read_bytes()).hexdigest()
    )


def test_invalid_python_preflight_never_spawns_verifier(tmp_path: Path) -> None:
    scenario = _Scenario(tmp_path)
    marker = scenario.directory / "spawned"
    service, _, _, _ = _service(
        scenario,
        f": > {shlex.quote(str(marker))}\n/bin/cat >/dev/null\nexit 0",
    )
    with pytest.raises(
        ThreatHintV2VerifiedPreflightError,
        match=r"^invalid threat-hint v2 verified preflight$",
    ):
        _run(service, scenario, report_nonce=b"\x44" * 32)
    assert not marker.exists()


@pytest.mark.parametrize(
    ("exit_code", "error_type", "message"),
    (
        (1, ThreatHintV2VerifiedPreflightError, "invalid"),
        (2, ThreatHintV2VerifiedPreflightUnavailableError, "unavailable"),
        (3, ThreatHintV2VerifiedPreflightUnavailableError, "unavailable"),
        (42, ThreatHintV2VerifiedPreflightUnavailableError, "unavailable"),
    ),
)
def test_verifier_exit_map_is_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    exit_code: int,
    error_type: type[ValueError],
    message: str,
) -> None:
    scenario = _Scenario(tmp_path)
    service, _, _, _ = _service(scenario, f"/bin/cat >/dev/null\nexit {exit_code}")
    processes: list[Any] = []
    original_popen = verified_preflight_module.subprocess.Popen

    def tracking_popen(*args: Any, **kwargs: Any) -> Any:
        process = original_popen(*args, **kwargs)
        processes.append(process)
        return process

    monkeypatch.setattr(verified_preflight_module.subprocess, "Popen", tracking_popen)
    with pytest.raises(error_type, match=message):
        _run(service, scenario)
    assert len(processes) == 1
    assert processes[0].returncode == exit_code


def test_signal_death_is_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    scenario = _Scenario(tmp_path)
    service, _, _, _ = _service(scenario, "/bin/cat >/dev/null\n/bin/kill -TERM $$")
    processes: list[Any] = []
    original_popen = verified_preflight_module.subprocess.Popen

    def tracking_popen(*args: Any, **kwargs: Any) -> Any:
        process = original_popen(*args, **kwargs)
        processes.append(process)
        return process

    monkeypatch.setattr(verified_preflight_module.subprocess, "Popen", tracking_popen)
    with pytest.raises(ThreatHintV2VerifiedPreflightUnavailableError):
        _run(service, scenario)
    assert len(processes) == 1
    assert processes[0].returncode is not None
    assert processes[0].returncode < 0


def test_timeout_kills_reaps_and_releases_lock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    scenario = _Scenario(tmp_path)
    body = "/bin/sleep 30\nexit 0"
    service, _, _, _ = _service(scenario, body, timeout_ms=1_000)
    child_pids: list[int] = []
    original_popen = verified_preflight_module.subprocess.Popen

    def tracking_popen(*args: Any, **kwargs: Any) -> Any:
        process = original_popen(*args, **kwargs)
        child_pids.append(process.pid)
        return process

    monkeypatch.setattr(verified_preflight_module.subprocess, "Popen", tracking_popen)
    with pytest.raises(ThreatHintV2VerifiedPreflightUnavailableError):
        _run(service, scenario)
    assert len(child_pids) == 1
    with pytest.raises(ProcessLookupError):
        os.kill(child_pids[0], 0)
    with pytest.raises(ThreatHintV2VerifiedPreflightUnavailableError):
        _run(service, scenario)


@pytest.mark.parametrize("exit_code", (0, 1, 3))
def test_closed_stdin_process_is_classified_without_leak(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, exit_code: int
) -> None:
    scenario = _Scenario(tmp_path)
    service, _, _, _ = _service(scenario, f"exec 0<&-\nexit {exit_code}")
    processes: list[Any] = []
    original_popen = verified_preflight_module.subprocess.Popen

    def tracking_popen(*args: Any, **kwargs: Any) -> Any:
        process = original_popen(*args, **kwargs)
        processes.append(process)
        return process

    monkeypatch.setattr(verified_preflight_module.subprocess, "Popen", tracking_popen)
    if exit_code == 0:
        assert _run(service, scenario).raw_manifest_sha256_hex == scenario.anchor_hex
    elif exit_code == 1:
        with pytest.raises(ThreatHintV2VerifiedPreflightError):
            _run(service, scenario)
    else:
        with pytest.raises(ThreatHintV2VerifiedPreflightUnavailableError):
            _run(service, scenario)
    assert len(processes) == 1
    assert processes[0].returncode == exit_code


def test_executable_is_hash_permission_and_symlink_pinned(tmp_path: Path) -> None:
    scenario = _Scenario(tmp_path)
    service, executable, _, _ = _service(scenario, executable_sha256="11" * 32)
    with pytest.raises(ThreatHintV2VerifiedPreflightUnavailableError):
        _run(service, scenario)

    executable.chmod(0o720)
    service, executable, _, _ = _service(scenario, name_collision_body())
    executable.chmod(0o720)
    with pytest.raises(ThreatHintV2VerifiedPreflightUnavailableError):
        _run(service, scenario)

    target = executable
    link = scenario.directory / "verifier-link"
    link.symlink_to(target)
    config = _write_config(
        scenario.directory,
        link,
        scenario.directory / "relation-manifest-v2.json",
        name="symlink-config.toml",
    )
    linked = ThreatHintV2VerifiedPreflightService(config, scenario.policy_path)
    with pytest.raises(ThreatHintV2VerifiedPreflightUnavailableError):
        _run(linked, scenario)


def name_collision_body() -> str:
    return "/bin/cat >/dev/null\nexit 0"


def test_executable_rejects_unsafe_ancestor_and_oversize(tmp_path: Path) -> None:
    scenario = _Scenario(tmp_path)
    unsafe = scenario.directory / "unsafe"
    unsafe.mkdir(mode=0o700)
    executable = _write_verifier(unsafe, name_collision_body())
    manifest = _write_owner_file(
        scenario.directory / "relation-manifest-v2.json", scenario.manifest_wire
    )
    config = _write_config(scenario.directory, executable, manifest)
    service = ThreatHintV2VerifiedPreflightService(config, scenario.policy_path)
    unsafe_modes = [0o777]
    if os.getuid() != 0:
        unsafe_modes.append(0o1777)
    for mode in unsafe_modes:
        unsafe.chmod(mode)
        with pytest.raises(ThreatHintV2VerifiedPreflightUnavailableError):
            _run(service, scenario)
    unsafe.chmod(0o700)

    executable.write_bytes(b"\x00")
    with executable.open("r+b") as executable_file:
        executable_file.truncate(MAX_VERIFIER_EXECUTABLE_BYTES + 1)
    executable.chmod(0o700)
    config = _write_config(
        scenario.directory,
        executable,
        manifest,
        name="oversize-config.toml",
    )
    oversized = ThreatHintV2VerifiedPreflightService(config, scenario.policy_path)
    with pytest.raises(ThreatHintV2VerifiedPreflightUnavailableError):
        _run(oversized, scenario)


@pytest.mark.parametrize(
    "bad_hash",
    ("00" * 32, "AA" * 32, "1" * 63, "g1" * 32),
)
def test_config_rejects_invalid_executable_hash(tmp_path: Path, bad_hash: str) -> None:
    scenario = _Scenario(tmp_path)
    manifest = _write_owner_file(
        scenario.directory / "relation-manifest-v2.json", scenario.manifest_wire
    )
    executable = _write_verifier(scenario.directory, name_collision_body())
    config = _write_config(
        scenario.directory, executable, manifest, executable_sha256=bad_hash
    )
    with pytest.raises(ThreatHintV2VerifiedPreflightUnavailableError):
        ThreatHintV2VerifiedPreflightService(config, scenario.policy_path)


def test_config_requires_exact_owner_only_schema_and_absolute_paths(
    tmp_path: Path,
) -> None:
    scenario = _Scenario(tmp_path)
    manifest = _write_owner_file(
        scenario.directory / "relation-manifest-v2.json", scenario.manifest_wire
    )
    executable = _write_verifier(scenario.directory, name_collision_body())

    extra = _write_config(
        scenario.directory, executable, manifest, extra="unexpected = true"
    )
    with pytest.raises(ThreatHintV2VerifiedPreflightUnavailableError):
        ThreatHintV2VerifiedPreflightService(extra, scenario.policy_path)

    relative = _write_owner_file(
        scenario.directory / "relative.toml",
        (
            "schema_version = 1\n"
            'verifier_executable_path = "verifier"\n'
            f'verifier_executable_sha256 = "{"11" * 32}"\n'
            f'relation_manifest_path = "{manifest}"\n'
            "verifier_timeout_ms = 100\n"
        ).encode("ascii"),
    )
    with pytest.raises(ThreatHintV2VerifiedPreflightUnavailableError):
        ThreatHintV2VerifiedPreflightService(relative, scenario.policy_path)

    extra.chmod(0o644)
    with pytest.raises(ThreatHintV2VerifiedPreflightUnavailableError):
        ThreatHintV2VerifiedPreflightService(extra, scenario.policy_path)

    extra.chmod(0o600)
    link = scenario.directory / "config-link.toml"
    link.symlink_to(extra)
    with pytest.raises(ThreatHintV2VerifiedPreflightUnavailableError):
        ThreatHintV2VerifiedPreflightService(link, scenario.policy_path)


def test_config_rejects_wrong_types_missing_fields_encoding_and_size(
    tmp_path: Path,
) -> None:
    scenario = _Scenario(tmp_path)
    manifest = _write_owner_file(
        scenario.directory / "relation-manifest-v2.json", scenario.manifest_wire
    )
    executable = _write_verifier(scenario.directory, name_collision_body())
    digest = hashlib.sha256(executable.read_bytes()).hexdigest()
    valid_lines = [
        "schema_version = 1",
        f'verifier_executable_path = "{executable}"',
        f'verifier_executable_sha256 = "{digest}"',
        f'relation_manifest_path = "{manifest}"',
        "verifier_timeout_ms = 100",
    ]
    bad_wires = (
        "\n".join(["schema_version = true", *valid_lines[1:]]).encode("ascii"),
        "\n".join([*valid_lines[:-1], "verifier_timeout_ms = true"]).encode("ascii"),
        "\n".join(valid_lines[:-1]).encode("ascii"),
        b"\xff",
        b"#" * 4_097,
    )
    for index, wire in enumerate(bad_wires):
        config = _write_owner_file(
            scenario.directory / f"bad-config-{index}.toml", wire
        )
        with pytest.raises(ThreatHintV2VerifiedPreflightUnavailableError):
            ThreatHintV2VerifiedPreflightService(config, scenario.policy_path)


@pytest.mark.parametrize("timeout", (99, 60_001))
def test_config_rejects_timeout_outside_closed_range(
    tmp_path: Path, timeout: int
) -> None:
    scenario = _Scenario(tmp_path)
    manifest = _write_owner_file(
        scenario.directory / "relation-manifest-v2.json", scenario.manifest_wire
    )
    executable = _write_verifier(scenario.directory, name_collision_body())
    config = _write_config(scenario.directory, executable, manifest, timeout_ms=timeout)
    with pytest.raises(ThreatHintV2VerifiedPreflightUnavailableError):
        ThreatHintV2VerifiedPreflightService(config, scenario.policy_path)


def test_manifest_is_owner_read_and_anchor_pinned_each_call(tmp_path: Path) -> None:
    scenario = _Scenario(tmp_path)
    service, _, manifest, _ = _service(scenario)
    _run(service, scenario)
    manifest.write_bytes(b"{}")
    manifest.chmod(0o600)
    with pytest.raises(ThreatHintV2VerifiedPreflightUnavailableError):
        _run(service, scenario)

    manifest.unlink()
    target = _write_owner_file(
        scenario.directory / "manifest-target.json", scenario.manifest_wire
    )
    manifest.symlink_to(target)
    with pytest.raises(ThreatHintV2VerifiedPreflightUnavailableError):
        _run(service, scenario)


def test_manifest_and_config_parent_permissions_fail_closed(tmp_path: Path) -> None:
    scenario = _Scenario(tmp_path)
    service, _, manifest, config = _service(scenario)
    manifest.chmod(0o644)
    with pytest.raises(ThreatHintV2VerifiedPreflightUnavailableError):
        _run(service, scenario)
    manifest.chmod(0o600)

    scenario.directory.chmod(0o755)
    try:
        with pytest.raises(ThreatHintV2VerifiedPreflightUnavailableError):
            _run(service, scenario)
        with pytest.raises(ThreatHintV2VerifiedPreflightUnavailableError):
            ThreatHintV2VerifiedPreflightService(config, scenario.policy_path)
    finally:
        scenario.directory.chmod(0o700)


def test_busy_is_a_distinct_unavailable_subclass_raised_under_lock(
    tmp_path: Path,
) -> None:
    scenario = _Scenario(tmp_path)
    service, _, _, _ = _service(scenario)
    assert issubclass(
        ThreatHintV2VerifiedPreflightBusyError,
        ThreatHintV2VerifiedPreflightUnavailableError,
    )
    assert issubclass(
        ThreatHintV2VerifiedPreflightBusyError, ThreatHintV2VerifiedPreflightError
    )
    assert service._verifier_lock.acquire(  # pylint: disable=protected-access
        blocking=False
    )
    try:
        with pytest.raises(
            ThreatHintV2VerifiedPreflightBusyError,
            match=r"^threat-hint v2 verified preflight busy$",
        ):
            _run(service, scenario)
    finally:
        service._verifier_lock.release()  # pylint: disable=protected-access
    assert _run(service, scenario).raw_manifest_sha256_hex == scenario.anchor_hex


def test_trusted_identity_accessors_delegate_to_owner_policy(tmp_path: Path) -> None:
    scenario = _Scenario(tmp_path)
    service, _, _, _ = _service(scenario)

    assert service.trusted_network_id == scenario.vector["network_id"]
    assert service.trusted_approver_xonly_public_key == bytes.fromhex(
        scenario.vector["trusted_approver_xonly_public_key_hex"]
    )
    assert service.trusted_recipient_scope == bytes.fromhex(
        scenario.vector["trusted_recipient_scope_hex"]
    )

    with pytest.raises(AttributeError):
        service.trusted_network_id = "testnet-11"  # type: ignore[misc]
    with pytest.raises(AttributeError):
        service.trusted_approver_xonly_public_key = b"\x00" * 32  # type: ignore[misc]
    with pytest.raises(AttributeError):
        service.trusted_recipient_scope = b"\x00" * 32  # type: ignore[misc]


def test_lock_bounds_concurrent_verifier_processes(tmp_path: Path) -> None:
    scenario = _Scenario(tmp_path)
    started = scenario.directory / "started"
    release = scenario.directory / "release"
    body = f"""
printf 'started\\n' >> {shlex.quote(str(started))}
while [ ! -f {shlex.quote(str(release))} ]; do /bin/sleep 0.02; done
/bin/cat >/dev/null
exit 0
"""
    service, _, _, _ = _service(scenario, body, timeout_ms=30_000)
    result: list[ThreatHintV2VerifiedPreflightReceipt] = []
    errors: list[BaseException] = []

    def first_call() -> None:
        try:
            result.append(_run(service, scenario))
        except BaseException as error:  # pragma: no cover - assertion captures
            errors.append(error)

    worker = threading.Thread(target=first_call)
    worker.start()
    deadline = time.monotonic() + 15
    while not started.exists() and time.monotonic() < deadline:
        time.sleep(0.01)
    assert started.exists()
    with pytest.raises(ThreatHintV2VerifiedPreflightUnavailableError):
        _run(service, scenario)
    release.touch(mode=0o600)
    worker.join(timeout=15)
    assert not worker.is_alive()
    assert errors == []
    assert len(result) == 1
    assert started.read_text(encoding="ascii").splitlines() == ["started"]


def test_receipt_is_restricted_data_and_not_pickleable(tmp_path: Path) -> None:
    scenario = _Scenario(tmp_path)
    service, _, _, _ = _service(scenario)
    receipt = _run(service, scenario)

    with pytest.raises(TypeError):
        ThreatHintV2VerifiedPreflightReceipt()
    with pytest.raises(TypeError):
        dataclasses.replace(receipt)
    with pytest.raises(TypeError):
        pickle.dumps(receipt)
    forged = object.__new__(ThreatHintV2VerifiedPreflightReceipt)
    with pytest.raises(AttributeError):
        _ = forged.statement_digest
    with pytest.raises(dataclasses.FrozenInstanceError):
        receipt.statement_digest = b"\x00" * 32  # type: ignore[misc]
    for forbidden in (
        "manifest_path",
        "verifier_path",
        "proof",
        "statement",
        "bundle",
        "approval",
        "consume",
        "verify",
    ):
        assert not hasattr(receipt, forbidden)


def test_api_accepts_no_manifest_anchor_verifier_or_receipt() -> None:
    constructor = inspect.signature(ThreatHintV2VerifiedPreflightService)
    assert set(constructor.parameters) == {"config_path", "preflight_policy_path"}
    call = inspect.signature(ThreatHintV2VerifiedPreflightService.preflight)
    assert set(call.parameters) == {
        "self",
        "envelope_wire",
        "bundle_wire",
        "approval_wire",
        "report_nonce",
        "current_time",
    }
    source = inspect.getsource(
        __import__(
            "jaeger.threat_hint_v2_verified_preflight",
            fromlist=["ThreatHintV2VerifiedPreflightService"],
        )
    )
    assert "sqlite3" not in source
    assert "shell=True" not in source
    assert "tempfile" not in source


def test_runtime_success_and_failure_do_not_mutate_service_files(
    tmp_path: Path,
) -> None:
    scenario = _Scenario(tmp_path)
    service, _, _, _ = _service(scenario)
    before = _snapshot(scenario.directory)
    _run(service, scenario)
    with pytest.raises(ThreatHintV2VerifiedPreflightError):
        _run(service, scenario, report_nonce=b"\x44" * 32)
    assert _snapshot(scenario.directory) == before

"""Adversarial tests for the local owner threat-hint v2 governance loader."""

# Pytest test names provide the scenario descriptions; tests intentionally
# exercise module internals for descriptor and source-boundary coverage and
# assert exact built-in types as protocol requirements.
# pylint: disable=missing-function-docstring,protected-access,too-many-locals
# pylint: disable=unidiomatic-typecheck

from __future__ import annotations

import ast
import dataclasses
import hashlib
import inspect
import os
import pickle
import stat
from pathlib import Path
from types import MappingProxyType
from typing import Callable

import pytest

import jaeger.threat_hint_v2_governance as governance_module
from jaeger.threat_hint_v2_governance import (
    MAX_AUTHORITY_EPOCH,
    MAX_AUTHORITY_INSTANT,
    MAX_GOVERNANCE_POLICY_BYTES,
    ThreatHintV2GovernancePolicy,
    ThreatHintV2GovernancePolicyError,
    load_threat_hint_v2_governance_policy,
)
from jaeger.threat_observable import ObservableKind

pytestmark = pytest.mark.skipif(
    os.name != "posix", reason="governance policy requires POSIX file controls"
)

_NETWORK = "kaspa-mainnet"
_APPROVER = bytes(range(32))
_SCOPE = bytes(range(32, 64))
_APPROVER_HEX = _APPROVER.hex()
_SCOPE_HEX = _SCOPE.hex()
_OTHER_HEX = bytes(range(64, 96)).hex()
_STABLE_MESSAGE = "invalid threat hint v2 governance policy"

_ALLOW_FILE = "allow_local_analysis_corpus_matchable_v1"
_ALLOW_API = "allow_local_analysis_software_fingerprint_v1"
_ALLOW_BYTE = "allow_local_analysis_content_derived_v1"


class _BytesSubclass(bytes):
    pass


class _StrSubclass(str):
    pass


class _IntSubclass(int):
    pass


class _PathSubclass(type(Path())):
    pass


def _policy_lines(**overrides: object) -> list[str]:
    fields: dict[str, object] = {
        "schema_version": "1",
        "network_id": f'"{_NETWORK}"',
        "approver_xonly_public_key": f'"{_APPROVER_HEX}"',
        "recipient_scope": f'"{_SCOPE_HEX}"',
        "authority_epoch": "7",
        "authority_not_before": "1000",
        "authority_not_after": "2000",
        "recipient_purpose": '"guardian_local_analysis_v1"',
        "recipient_boundary": '"same_guardian_owner_v1"',
        "external_disclosure": '"deny_v1"',
    }
    decisions = {
        "file_sha256": f'"{_ALLOW_FILE}"',
        "api_import": '"deny_v1"',
        "byte_pattern": '"deny_v1"',
    }
    include_decisions = True
    for name, value in overrides.items():
        if name == "observable_decisions" and value is None:
            include_decisions = False
        elif value is None:
            fields.pop(name, None)
            decisions.pop(name, None)
        elif name in decisions:
            decisions[name] = value
        else:
            fields[name] = value
    lines = [f"{name} = {value}" for name, value in fields.items()]
    if include_decisions:
        lines.append("[observable_decisions]")
        lines.extend(f"{name} = {value}" for name, value in decisions.items())
    return lines


def _write_owner_file(path: Path, contents: bytes, mode: int = 0o600) -> Path:
    path.write_bytes(contents)
    path.chmod(mode)
    return path


def _write_policy(
    directory: Path,
    *,
    raw: bytes | None = None,
    mode: int = 0o600,
    name: str = "threat-hint-v2-governance-policy.toml",
    **overrides: object,
) -> Path:
    if raw is None:
        raw = ("\n".join(_policy_lines(**overrides)) + "\n").encode("ascii")
    directory.chmod(0o700)
    return _write_owner_file(directory / name, raw, mode)


def _load(path: Path, **expected_overrides: object) -> ThreatHintV2GovernancePolicy:
    expected = {
        "expected_network_id": _NETWORK,
        "expected_approver_xonly_public_key": _APPROVER,
        "expected_recipient_scope": _SCOPE,
    }
    expected.update(expected_overrides)
    return load_threat_hint_v2_governance_policy(path, **expected)  # type: ignore[arg-type]


def _expect_invalid(path: Path, **expected_overrides: object) -> None:
    with pytest.raises(ThreatHintV2GovernancePolicyError) as caught:
        _load(path, **expected_overrides)
    assert str(caught.value) == _STABLE_MESSAGE


def test_valid_policy_parses_into_immutable_shape(tmp_path: Path) -> None:
    path = _write_policy(tmp_path)
    policy = _load(path)
    assert type(policy) is ThreatHintV2GovernancePolicy
    assert policy.network_id == _NETWORK
    assert policy.approver_xonly_public_key == _APPROVER
    assert policy.recipient_scope == _SCOPE
    assert policy.authority_epoch == 7
    assert policy.authority_not_before == 1000
    assert policy.authority_not_after == 2000
    assert policy.recipient_purpose == "guardian_local_analysis_v1"
    assert policy.recipient_boundary == "same_guardian_owner_v1"
    assert policy.external_disclosure == "deny_v1"
    assert type(policy.observable_decisions) is MappingProxyType
    assert dict(policy.observable_decisions) == {
        ObservableKind.FILE_SHA256: _ALLOW_FILE,
        ObservableKind.API_IMPORT: "deny_v1",
        ObservableKind.BYTE_PATTERN: "deny_v1",
    }
    assert all(type(kind) is ObservableKind for kind in policy.observable_decisions)
    assert policy.allowed_observable_kinds == frozenset({ObservableKind.FILE_SHA256})
    assert type(policy.allowed_observable_kinds) is frozenset
    assert type(policy.policy_sha256) is bytes
    assert len(policy.policy_sha256) == 32
    with pytest.raises(dataclasses.FrozenInstanceError):
        policy.network_id = "other"  # type: ignore[misc]
    with pytest.raises(TypeError):
        policy.observable_decisions[ObservableKind.API_IMPORT] = _ALLOW_API  # type: ignore[index]
    with pytest.raises(AttributeError):
        # pylint: disable-next=no-member
        policy.allowed_observable_kinds.add(  # type: ignore[attr-defined]
            ObservableKind.BYTE_PATTERN
        )


def test_valid_policy_accepts_all_allowed_kinds_and_bounds(tmp_path: Path) -> None:
    path = _write_policy(
        tmp_path,
        file_sha256=f'"{_ALLOW_FILE}"',
        api_import=f'"{_ALLOW_API}"',
        byte_pattern=f'"{_ALLOW_BYTE}"',
        authority_epoch=str(MAX_AUTHORITY_EPOCH),
        authority_not_before=str(MAX_AUTHORITY_INSTANT - 1),
        authority_not_after=str(MAX_AUTHORITY_INSTANT),
    )
    policy = _load(path)
    assert policy.allowed_observable_kinds == frozenset(ObservableKind)
    assert all(type(kind) is ObservableKind for kind in policy.allowed_observable_kinds)
    assert policy.authority_epoch == MAX_AUTHORITY_EPOCH
    assert policy.authority_not_before == MAX_AUTHORITY_INSTANT - 1
    assert policy.authority_not_after == MAX_AUTHORITY_INSTANT


@pytest.mark.parametrize(
    "kind,token",
    (
        ("file_sha256", _ALLOW_FILE),
        ("api_import", _ALLOW_API),
        ("byte_pattern", _ALLOW_BYTE),
    ),
)
def test_valid_policy_accepts_each_single_allowed_kind(
    tmp_path: Path, kind: str, token: str
) -> None:
    overrides: dict[str, object] = {
        "file_sha256": '"deny_v1"',
        "api_import": '"deny_v1"',
        "byte_pattern": '"deny_v1"',
    }
    overrides[kind] = f'"{token}"'
    path = _write_policy(tmp_path, **overrides)
    policy = _load(path)
    assert policy.allowed_observable_kinds == frozenset({ObservableKind(kind)})
    assert policy.observable_decisions[ObservableKind(kind)] == token


def test_policy_digest_matches_exact_raw_policy_bytes(tmp_path: Path) -> None:
    path = _write_policy(tmp_path)
    raw = path.read_bytes()
    policy = _load(path)
    assert policy.policy_sha256 == hashlib.sha256(raw).digest()
    other = _write_policy(
        tmp_path, name="other-policy.toml", api_import=f'"{_ALLOW_API}"'
    )
    other_policy = _load(other)
    assert other_policy.policy_sha256 == hashlib.sha256(other.read_bytes()).digest()
    assert other_policy.policy_sha256 != policy.policy_sha256


def test_repr_leaks_no_policy_material(tmp_path: Path) -> None:
    policy = _load(_write_policy(tmp_path))
    rendered = repr(policy)
    assert _APPROVER_HEX not in rendered
    assert _SCOPE_HEX not in rendered
    assert _NETWORK not in rendered
    assert "network_id" not in rendered
    assert policy.policy_sha256.hex() not in rendered


def test_error_is_stable_and_redacted(tmp_path: Path) -> None:
    path = _write_policy(tmp_path, network_id='"other-network"')
    with pytest.raises(ThreatHintV2GovernancePolicyError) as caught:
        _load(path)
    assert str(caught.value) == _STABLE_MESSAGE
    assert (
        repr(caught.value) == f"ThreatHintV2GovernancePolicyError('{_STABLE_MESSAGE}')"
    )
    assert _APPROVER_HEX not in str(caught.value)
    assert str(path) not in str(caught.value)


@pytest.mark.parametrize(
    "overrides",
    (
        {"schema_version": "2"},
        {"schema_version": "0"},
        {"schema_version": '"1"'},
        {"schema_version": "true"},
        {"network_id": "1"},
        {"network_id": f'"{_NETWORK.upper()}"'},
        {"network_id": '"a"'},
        {"network_id": '"-bad-network"'},
        {"network_id": '"bad-network-"'},
        {"network_id": '"bad network"'},
        {"approver_xonly_public_key": "1"},
        {"approver_xonly_public_key": f'"{_APPROVER_HEX.upper()}"'},
        {"approver_xonly_public_key": f'"{_APPROVER_HEX[:-2]}"'},
        {"approver_xonly_public_key": f'"{_APPROVER_HEX}00"'},
        {"approver_xonly_public_key": '"zz" + "' + "00" * 31 + '"'},
        {"recipient_scope": "1"},
        {"recipient_scope": f'"{_SCOPE_HEX.upper()}"'},
        {"recipient_scope": f'"{_SCOPE_HEX[:-2]}"'},
        {"recipient_scope": f'"{_SCOPE_HEX}00"'},
        {"authority_epoch": "0"},
        {"authority_epoch": "-1"},
        {"authority_epoch": str(MAX_AUTHORITY_EPOCH + 1)},
        {"authority_epoch": '"7"'},
        {"authority_epoch": "true"},
        {"authority_epoch": "1.5"},
        {"authority_not_before": "0"},
        {"authority_not_before": "-1"},
        {"authority_not_before": str(MAX_AUTHORITY_INSTANT + 1)},
        {"authority_not_before": '"1000"'},
        {"authority_not_before": "true"},
        {"authority_not_after": "0"},
        {"authority_not_after": str(MAX_AUTHORITY_INSTANT + 1)},
        {"authority_not_after": '"2000"'},
        {"authority_not_after": "false"},
        {"authority_not_before": "2000", "authority_not_after": "1000"},
        {"authority_not_before": "1000", "authority_not_after": "1000"},
        {"authority_not_before": "2000"},
        {"recipient_purpose": '"guardian_local_analysis_v2"'},
        {"recipient_purpose": "1"},
        {"recipient_boundary": '"same_guardian_owner_v2"'},
        {"recipient_boundary": "1"},
        {"external_disclosure": '"allow_v1"'},
        {"external_disclosure": '"deny_v2"'},
        {"external_disclosure": "1"},
        {"file_sha256": "1"},
        {"file_sha256": '"allow_v1"'},
        {"file_sha256": f'"{_ALLOW_API}"'},
        {"file_sha256": f'"{_ALLOW_BYTE}"'},
        {"file_sha256": f'"{_ALLOW_FILE.upper()}"'},
        {"api_import": "1"},
        {"api_import": f'"{_ALLOW_FILE}"'},
        {"api_import": f'"{_ALLOW_BYTE}"'},
        {"byte_pattern": "1"},
        {"byte_pattern": f'"{_ALLOW_FILE}"'},
        {"byte_pattern": f'"{_ALLOW_API}"'},
        {"byte_pattern": '"deny_v1_extra"'},
        {
            "file_sha256": '"deny_v1"',
            "api_import": '"deny_v1"',
            "byte_pattern": '"deny_v1"',
        },
    ),
)
def test_invalid_schema_field_rejected(
    tmp_path: Path, overrides: dict[str, object]
) -> None:
    _expect_invalid(_write_policy(tmp_path, **overrides))


@pytest.mark.parametrize(
    "missing",
    (
        "schema_version",
        "network_id",
        "approver_xonly_public_key",
        "recipient_scope",
        "authority_epoch",
        "authority_not_before",
        "authority_not_after",
        "recipient_purpose",
        "recipient_boundary",
        "external_disclosure",
        "observable_decisions",
        "file_sha256",
        "api_import",
        "byte_pattern",
    ),
)
def test_missing_schema_field_rejected(tmp_path: Path, missing: str) -> None:
    _expect_invalid(_write_policy(tmp_path, **{missing: None}))


def test_extra_top_level_field_rejected(tmp_path: Path) -> None:
    raw = ("\n".join(_policy_lines()) + '\nledger_path = "/tmp/x"\n').encode("ascii")
    _expect_invalid(_write_policy(tmp_path, raw=raw))


def test_extra_nested_decision_field_rejected(tmp_path: Path) -> None:
    raw = ("\n".join(_policy_lines()) + '\nyara_rule = "deny_v1"\n').encode("ascii")
    _expect_invalid(_write_policy(tmp_path, raw=raw))


def test_non_table_observable_decisions_rejected(tmp_path: Path) -> None:
    lines = _policy_lines(observable_decisions=None)
    lines.append('observable_decisions = "deny_v1"')
    raw = ("\n".join(lines) + "\n").encode("ascii")
    _expect_invalid(_write_policy(tmp_path, raw=raw))


def test_duplicate_top_level_scalar_key_rejected(tmp_path: Path) -> None:
    raw = b"schema_version = 1\nschema_version = 1"
    _expect_invalid(_write_policy(tmp_path, raw=raw))


def test_duplicate_top_level_key_rejected(tmp_path: Path) -> None:
    lines = _policy_lines()
    header = lines.index("[observable_decisions]")
    lines.insert(header, f'network_id = "{_NETWORK}"')
    raw = ("\n".join(lines) + "\n").encode("ascii")
    _expect_invalid(_write_policy(tmp_path, raw=raw))


def test_duplicate_nested_decision_key_rejected(tmp_path: Path) -> None:
    raw = ("\n".join(_policy_lines()) + '\nfile_sha256 = "deny_v1"\n').encode("ascii")
    _expect_invalid(_write_policy(tmp_path, raw=raw))


@pytest.mark.parametrize(
    "expected",
    (
        {"expected_network_id": "other-network"},
        {"expected_approver_xonly_public_key": bytes.fromhex(_OTHER_HEX)},
        {"expected_recipient_scope": bytes.fromhex(_OTHER_HEX)},
        {"expected_network_id": 1},
        {"expected_network_id": _StrSubclass(_NETWORK)},
        {"expected_network_id": "INVALID NETWORK"},
        {"expected_network_id": "a"},
        {"expected_approver_xonly_public_key": _APPROVER_HEX},
        {"expected_approver_xonly_public_key": _BytesSubclass(_APPROVER)},
        {"expected_approver_xonly_public_key": _APPROVER[:-1]},
        {"expected_approver_xonly_public_key": _APPROVER + b"\x00"},
        {"expected_recipient_scope": _SCOPE_HEX},
        {"expected_recipient_scope": _BytesSubclass(_SCOPE)},
        {"expected_recipient_scope": _SCOPE[:-1]},
        {"expected_recipient_scope": _SCOPE + b"\x00"},
    ),
)
def test_expected_identity_restriction_enforced(
    tmp_path: Path, expected: dict[str, object]
) -> None:
    _expect_invalid(_write_policy(tmp_path), **expected)


def test_expected_identity_fails_before_file_state(tmp_path: Path) -> None:
    missing = tmp_path / "never-created.toml"
    with pytest.raises(ThreatHintV2GovernancePolicyError):
        _load(missing, expected_approver_xonly_public_key=b"short")
    assert not missing.exists()


def test_expected_identity_fails_before_policy_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _write_policy(tmp_path)

    def fail_if_called(unused_path: Path) -> bytes:
        raise AssertionError("policy reader must not run")

    monkeypatch.setattr(governance_module, "_read_owner_policy_file", fail_if_called)
    with pytest.raises(ThreatHintV2GovernancePolicyError):
        _load(path, expected_recipient_scope=b"short")


@pytest.mark.parametrize(
    "bad_path",
    (
        "policy.toml",
        b"/tmp/policy.toml",
        7,
        None,
        _PathSubclass("/tmp/policy.toml"),
    ),
)
def test_exact_absolute_path_required(bad_path: object) -> None:
    with pytest.raises(ThreatHintV2GovernancePolicyError):
        load_threat_hint_v2_governance_policy(
            bad_path,  # type: ignore[arg-type]
            expected_network_id=_NETWORK,
            expected_approver_xonly_public_key=_APPROVER,
            expected_recipient_scope=_SCOPE,
        )


def test_relative_and_dotdot_paths_rejected(tmp_path: Path) -> None:
    path = _write_policy(tmp_path)
    for bad in (
        Path("relative-policy.toml"),
        path.parent / ".." / path.parent.name / path.name,
        Path("/"),
    ):
        with pytest.raises(ThreatHintV2GovernancePolicyError):
            _load(bad)


def test_embedded_nul_in_path_rejected(tmp_path: Path) -> None:
    with pytest.raises(ThreatHintV2GovernancePolicyError):
        _load(Path(f"{tmp_path}/policy\x00.toml"))


def test_missing_file_rejected(tmp_path: Path) -> None:
    tmp_path.chmod(0o700)
    _expect_invalid(tmp_path / "absent.toml")


def test_directory_as_policy_rejected(tmp_path: Path) -> None:
    sub = tmp_path / "policy-dir"
    sub.mkdir()
    tmp_path.chmod(0o700)
    _expect_invalid(sub)


def test_symlink_policy_file_rejected(tmp_path: Path) -> None:
    target = _write_policy(tmp_path)
    link = tmp_path / "linked-policy.toml"
    link.symlink_to(target)
    _expect_invalid(link)


def test_symlinked_ancestor_rejected(tmp_path: Path) -> None:
    real_dir = tmp_path / "real"
    real_dir.mkdir()
    path = _write_policy(real_dir)
    link_dir = tmp_path / "link"
    link_dir.symlink_to(real_dir, target_is_directory=True)
    _expect_invalid(link_dir / path.name)


@pytest.mark.parametrize(
    "mode",
    (
        0o644,
        0o640,
        0o604,
        0o777,
        0o4000 | 0o600,
        0o2000 | 0o600,
        0o1000 | 0o600,
    ),
)
def test_non_owner_only_or_setid_mode_rejected(tmp_path: Path, mode: int) -> None:
    _expect_invalid(_write_policy(tmp_path, mode=mode))


def test_group_writable_parent_rejected(tmp_path: Path) -> None:
    sub = tmp_path / "group-dir"
    sub.mkdir()
    path = _write_policy(sub)
    sub.chmod(0o770)
    _expect_invalid(path)


def test_empty_and_oversized_files_rejected(tmp_path: Path) -> None:
    _expect_invalid(_write_policy(tmp_path, raw=b""))
    oversized = b"#" * (MAX_GOVERNANCE_POLICY_BYTES + 1)
    _expect_invalid(_write_policy(tmp_path, raw=oversized))


def test_non_ascii_contents_rejected(tmp_path: Path) -> None:
    raw = ("\n".join(_policy_lines()) + "\n").encode("ascii") + "é".encode("utf-8")
    _expect_invalid(_write_policy(tmp_path, raw=raw))


def test_embedded_nul_contents_rejected(tmp_path: Path) -> None:
    raw = ("\n".join(_policy_lines()) + "\n").encode("ascii") + b"\x00"
    _expect_invalid(_write_policy(tmp_path, raw=raw))


@pytest.mark.parametrize(
    "raw",
    (
        b"schema_version = = 1",
        b"schema_version = 1\n[unclosed",
        b"not toml at all {{{",
        b'network_id = "kaspa-mainnet"',
        b"\xef\xbb\xbfschema_version = 1",
    ),
)
def test_malformed_toml_rejected(tmp_path: Path, raw: bytes) -> None:
    _expect_invalid(_write_policy(tmp_path, raw=raw))


def test_toml_recursion_error_is_redacted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _write_policy(tmp_path)

    def recurse(unused_document: str) -> dict:
        raise RecursionError("simulated parser recursion")

    monkeypatch.setattr(governance_module.tomllib, "loads", recurse)
    _expect_invalid(path)


def test_deeply_nested_toml_within_size_limit_is_rejected(tmp_path: Path) -> None:
    depth = 1_200
    raw = b"a = " + b"[" * depth + b"1" + b"]" * depth
    assert len(raw) <= MAX_GOVERNANCE_POLICY_BYTES
    _expect_invalid(_write_policy(tmp_path, raw=raw))


def test_non_posix_platform_fails_before_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _write_policy(tmp_path)
    opened = False
    real_open = os.open

    def track_open(*args: object, **kwargs: object) -> int:
        nonlocal opened
        opened = True
        return real_open(*args, **kwargs)

    monkeypatch.setattr(os, "open", track_open)
    monkeypatch.setattr(os, "name", "nt")
    _expect_invalid(path)
    assert not opened


def test_missing_getuid_fails_before_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _write_policy(tmp_path)
    opened = False
    real_open = os.open

    def track_open(*args: object, **kwargs: object) -> int:
        nonlocal opened
        opened = True
        return real_open(*args, **kwargs)

    monkeypatch.setattr(os, "open", track_open)
    monkeypatch.delattr(os, "getuid")
    _expect_invalid(path)
    assert not opened


def test_missing_no_follow_control_fails_before_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _write_policy(tmp_path)
    opened = False
    real_open = os.open

    def track_open(*args: object, **kwargs: object) -> int:
        nonlocal opened
        opened = True
        return real_open(*args, **kwargs)

    monkeypatch.setattr(os, "open", track_open)
    monkeypatch.delattr(os, "O_NOFOLLOW")
    _expect_invalid(path)
    assert not opened


def _fake_fstat(
    monkeypatch: pytest.MonkeyPatch,
    mutate: Callable[[os.stat_result], os.stat_result],
) -> None:
    real_fstat = os.fstat

    def fake(descriptor: int) -> os.stat_result:
        return mutate(real_fstat(descriptor))

    monkeypatch.setattr(os, "fstat", fake)


def _with_stat_field(current: os.stat_result, index: int, value: int) -> os.stat_result:
    fields = list(current)
    fields[index] = value
    return os.stat_result(fields)


def test_descriptor_inode_swap_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _write_policy(tmp_path)
    _fake_fstat(
        monkeypatch,
        lambda current: _with_stat_field(current, 1, current.st_ino + 1),
    )
    _expect_invalid(path)


def test_descriptor_device_swap_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _write_policy(tmp_path)
    _fake_fstat(
        monkeypatch,
        lambda current: _with_stat_field(current, 2, current.st_dev + 1),
    )
    _expect_invalid(path)


def test_descriptor_size_swap_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _write_policy(tmp_path)
    _fake_fstat(
        monkeypatch,
        lambda current: _with_stat_field(current, 6, current.st_size + 1),
    )
    _expect_invalid(path)


def test_descriptor_mode_swap_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _write_policy(tmp_path)
    _fake_fstat(
        monkeypatch,
        lambda current: _with_stat_field(
            current, 0, stat.S_IFDIR | stat.S_IRUSR | stat.S_IWUSR
        ),
    )
    _expect_invalid(path)


def test_short_read_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = _write_policy(tmp_path)
    real_read = os.read

    def fake(descriptor: int, count: int) -> bytes:
        chunk = real_read(descriptor, count)
        return chunk[:-1] if chunk else chunk

    monkeypatch.setattr(os, "read", fake)
    _expect_invalid(path)


def test_growing_read_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = _write_policy(tmp_path)
    real_read = os.read
    state = {"first": True}

    def fake(descriptor: int, count: int) -> bytes:
        chunk = real_read(descriptor, count)
        if state["first"]:
            state["first"] = False
            return chunk + b"\n# injected growth\n"
        return chunk

    monkeypatch.setattr(os, "read", fake)
    _expect_invalid(path)


def test_open_oserror_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _write_policy(tmp_path)

    def fake_open(*args: object, **kwargs: object) -> int:
        raise OSError("simulated open failure")

    monkeypatch.setattr(os, "open", fake_open)
    _expect_invalid(path)


def test_read_oserror_fails_closed_and_descriptor_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _write_policy(tmp_path)
    closed: list[int] = []
    real_close = os.close

    def fake_read(descriptor: int, count: int) -> bytes:
        raise OSError("simulated read failure")

    def fake_close(descriptor: int) -> None:
        closed.append(descriptor)
        real_close(descriptor)

    monkeypatch.setattr(os, "read", fake_read)
    monkeypatch.setattr(os, "close", fake_close)
    _expect_invalid(path)
    assert closed


def test_direct_construction_replace_and_pickle_rejected(tmp_path: Path) -> None:
    with pytest.raises(TypeError):
        ThreatHintV2GovernancePolicy()
    policy = _load(_write_policy(tmp_path))
    with pytest.raises(TypeError):
        dataclasses.replace(policy)
    with pytest.raises(TypeError):
        pickle.dumps(policy)
    with pytest.raises(TypeError):
        pickle.loads(pickle.dumps(policy))


def test_loader_creates_no_unrelated_files(tmp_path: Path) -> None:
    path = _write_policy(tmp_path)
    before = {entry.relative_to(tmp_path) for entry in tmp_path.rglob("*")}
    _load(path)
    for overrides in ({"network_id": '"other"'}, {"schema_version": "2"}):
        with pytest.raises(ThreatHintV2GovernancePolicyError):
            _load(_write_policy(tmp_path, **overrides))
    after = {entry.relative_to(tmp_path) for entry in tmp_path.rglob("*")}
    assert before == after


def test_source_boundary_has_no_forbidden_integration() -> None:
    source = inspect.getsource(governance_module)
    tree = ast.parse(source)
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add(node.module or "")
    allowed = {
        "__future__",
        "hashlib",
        "hmac",
        "os",
        "stat",
        "tomllib",
        "dataclasses",
        "pathlib",
        "types",
        "typing",
        "jaeger.threat_observable",
    }
    assert imported <= allowed
    for forbidden in (
        "sqlite3",
        "socket",
        "subprocess",
        "urllib",
        "requests",
        "httpx",
    ):
        assert forbidden not in source
    for forbidden_module in (
        "promotion",
        "acceptance",
        "consumption",
        "analyzer",
        "worker",
        "dequeue",
        "transport",
        "disclosure_module",
    ):
        assert not any(forbidden_module in name for name in imported)
    assert ".write" not in source
    assert "os.mkdir" not in source
    assert "open(" not in source.replace("os.open(", "")

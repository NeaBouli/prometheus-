"""Non-consuming composition of ThreatHint-v2 approval and proof checks.

The service reads one owner-pinned manifest, runs the existing Python
approval/privacy preflight, and then sends the exact same envelope bytes to a
hash-pinned Rust ``verify-v2`` executable. It returns data only and performs no
approval consumption, SQLite access, transport, analysis, promotion, wallet,
chain, or rollout action.

The executable is revalidated and rehashed for every invocation. A small
owner-bounded race remains between the final hash check and ``execve`` because
Python cannot portably execute an already-open file descriptor. The executable
and all ancestors are therefore restricted to the current user or root.
Group/world-writable ancestors are rejected except for root-owned sticky
directories such as the standard POSIX temporary root; every descendant and
the executable remain subject to the stricter ownership and write checks.
"""

# Exact built-in types and repeated closed-schema checks are protocol
# requirements; the latter intentionally mirror the canonical preflight.
# pylint: disable=duplicate-code,protected-access,too-many-boolean-expressions,unidiomatic-typecheck

from __future__ import annotations

import hashlib
import hmac
import os
import signal
import stat
import subprocess
import threading
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from jaeger.relation_manifest_v2 import MAX_CANONICAL_V2_MANIFEST_BYTES
from jaeger.threat_hint_v2_preflight import (
    FIXED_HASH_BYTES,
    U64_MAX,
    ThreatHintV2PreflightError,
    ThreatHintV2PreflightReceipt,
    ThreatHintV2PreflightService,
)
from jaeger.threat_hint_v2_proof_envelope import (
    MAX_CANONICAL_V2_PROOF_ENVELOPE_BYTES,
)

VERIFIED_PREFLIGHT_CONFIG_SCHEMA_VERSION: Final[int] = 1
MAX_VERIFIED_PREFLIGHT_CONFIG_BYTES: Final[int] = 4_096
MAX_VERIFIER_EXECUTABLE_BYTES: Final[int] = 64 * 1_024 * 1_024
MIN_VERIFIER_TIMEOUT_MS: Final[int] = 100
MAX_VERIFIER_TIMEOUT_MS: Final[int] = 60_000
_CONFIG_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "schema_version",
        "verifier_executable_path",
        "verifier_executable_sha256",
        "relation_manifest_path",
        "verifier_timeout_ms",
    }
)
_MINIMAL_VERIFIER_ENVIRONMENT: Final[dict[str, str]] = {
    "LANG": "C",
    "LC_ALL": "C",
}


class ThreatHintV2VerifiedPreflightError(ValueError):
    """Stable redacted rejection for invalid candidate data."""

    _MESSAGE = "invalid threat-hint v2 verified preflight"

    def __init__(self) -> None:
        super().__init__(self._MESSAGE)


class ThreatHintV2VerifiedPreflightUnavailableError(ThreatHintV2VerifiedPreflightError):
    """Stable redacted failure for unavailable trusted verifier material."""

    _MESSAGE = "threat-hint v2 verified preflight unavailable"


class ThreatHintV2VerifiedPreflightBusyError(
    ThreatHintV2VerifiedPreflightUnavailableError
):
    """Stable redacted retryable failure while the verifier lock is held."""

    _MESSAGE = "threat-hint v2 verified preflight busy"


@dataclass(frozen=True)
class _VerifiedPreflightConfig:
    verifier_executable_path: Path
    verifier_executable_sha256_hex: str
    relation_manifest_path: Path
    verifier_timeout_ms: int


@dataclass(frozen=True, init=False, repr=False, eq=False)
class ThreatHintV2VerifiedPreflightReceipt:
    """Data-only result; it grants no operational or downstream authority.

    A caller-supplied receipt must never substitute for rerunning this service.
    It is not durable approval, privacy/disclosure authority, transport or
    analyzer admission, promotion, chain acceptance, or rollout evidence.
    """

    statement_digest: bytes
    approval_id: bytes
    observable_commitment: bytes
    raw_manifest_sha256_hex: str
    envelope_sha256_hex: str
    verifier_executable_sha256_hex: str

    def __init__(self) -> None:
        raise TypeError(
            "direct threat-hint v2 verified preflight receipt construction is disabled"
        )

    def __reduce__(self) -> object:
        raise TypeError("threat-hint v2 verified preflight receipt is not serializable")


class ThreatHintV2VerifiedPreflightService:  # pylint: disable=too-few-public-methods
    """Run both local checks without consuming approval or writing state."""

    def __init__(self, config_path: Path, preflight_policy_path: Path) -> None:
        if os.name != "posix":
            raise ThreatHintV2VerifiedPreflightUnavailableError()
        self._config = _load_config(config_path)
        self._preflight_service = ThreatHintV2PreflightService(preflight_policy_path)
        self._verifier_lock = threading.Lock()

    @property
    def trusted_network_id(self) -> str:
        """Return the immutable owner-pinned policy network identifier."""
        return self._preflight_service.trusted_network_id

    @property
    def trusted_approver_xonly_public_key(self) -> bytes:
        """Return the immutable owner-pinned approver x-only public key."""
        return self._preflight_service.trusted_approver_xonly_public_key

    @property
    def trusted_recipient_scope(self) -> bytes:
        """Return the immutable owner-pinned opaque recipient scope."""
        return self._preflight_service.trusted_recipient_scope

    # pylint: disable-next=too-many-arguments
    def preflight(
        self,
        envelope_wire: bytes,
        bundle_wire: bytes,
        approval_wire: bytes,
        *,
        report_nonce: bytes,
        current_time: int,
    ) -> ThreatHintV2VerifiedPreflightReceipt:
        """Require approval/privacy compatibility and a valid Groth16 proof."""
        _validate_call_inputs(
            envelope_wire,
            bundle_wire,
            approval_wire,
            report_nonce,
            current_time,
        )
        manifest_wire = _read_owner_file(
            self._config.relation_manifest_path,
            MAX_CANONICAL_V2_MANIFEST_BYTES,
            require_owner_only_parent=True,
            unavailable=True,
        )
        anchor = self._preflight_service.trusted_relation_manifest_sha256_hex
        if not _constant_time_hex_digest_matches(manifest_wire, anchor):
            raise ThreatHintV2VerifiedPreflightUnavailableError()

        try:
            preflight_receipt = self._preflight_service.preflight(
                envelope_wire,
                manifest_wire,
                bundle_wire,
                approval_wire,
                report_nonce=report_nonce,
                current_time=current_time,
            )
        except ThreatHintV2PreflightError:
            raise ThreatHintV2VerifiedPreflightError() from None

        envelope_sha256_hex = hashlib.sha256(envelope_wire).hexdigest()
        if envelope_sha256_hex != preflight_receipt.envelope_sha256_hex:
            raise ThreatHintV2VerifiedPreflightUnavailableError()

        if not self._verifier_lock.acquire(  # pylint: disable=consider-using-with
            blocking=False
        ):
            raise ThreatHintV2VerifiedPreflightBusyError()
        try:
            executable = _validate_and_hash_executable(
                self._config.verifier_executable_path,
                self._config.verifier_executable_sha256_hex,
            )
            return_code = self._invoke_verifier(executable, envelope_wire)
        finally:
            self._verifier_lock.release()

        if return_code == 1:
            raise ThreatHintV2VerifiedPreflightError()
        if return_code != 0:
            raise ThreatHintV2VerifiedPreflightUnavailableError()
        return _build_receipt(
            preflight_receipt,
            self._config.verifier_executable_sha256_hex,
        )

    def _invoke_verifier(self, executable: Path, envelope_wire: bytes) -> int:
        process: subprocess.Popen[bytes] | None = None
        try:
            process = subprocess.Popen(  # noqa: S603 - pinned absolute binary  # pylint: disable=consider-using-with
                [
                    str(executable),
                    "verify-v2",
                    "--manifest",
                    str(self._config.relation_manifest_path),
                    "--expected-manifest-sha256",
                    self._preflight_service.trusted_relation_manifest_sha256_hex,
                    "--network-id",
                    self._preflight_service.trusted_network_id,
                ],
                stdin=subprocess.PIPE,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                close_fds=True,
                cwd="/",
                env=dict(_MINIMAL_VERIFIER_ENVIRONMENT),
                start_new_session=True,
            )
            process.communicate(
                envelope_wire,
                timeout=self._config.verifier_timeout_ms / 1_000,
            )
        except subprocess.TimeoutExpired:
            if process is not None:
                _kill_and_reap_process_group(process)
            raise ThreatHintV2VerifiedPreflightUnavailableError() from None
        except (BrokenPipeError, OSError, ValueError, subprocess.SubprocessError):
            if process is not None and process.poll() is None:
                _kill_and_reap_process_group(process)
            raise ThreatHintV2VerifiedPreflightUnavailableError() from None
        if process.returncode is None:
            _kill_and_reap_process_group(process)
            raise ThreatHintV2VerifiedPreflightUnavailableError()
        return process.returncode


def _load_config(path: Path) -> _VerifiedPreflightConfig:
    try:
        config_wire = _read_owner_file(
            path,
            MAX_VERIFIED_PREFLIGHT_CONFIG_BYTES,
            require_owner_only_parent=True,
            unavailable=True,
        )
        data = tomllib.loads(config_wire.decode("ascii"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError, RecursionError):
        raise ThreatHintV2VerifiedPreflightUnavailableError() from None
    if not isinstance(data, dict) or set(data) != _CONFIG_FIELDS:
        raise ThreatHintV2VerifiedPreflightUnavailableError()
    if (
        type(data["schema_version"]) is not int
        or data["schema_version"] != VERIFIED_PREFLIGHT_CONFIG_SCHEMA_VERSION
        or type(data["verifier_timeout_ms"]) is not int
        or not MIN_VERIFIER_TIMEOUT_MS
        <= data["verifier_timeout_ms"]
        <= MAX_VERIFIER_TIMEOUT_MS
    ):
        raise ThreatHintV2VerifiedPreflightUnavailableError()

    executable_path = _decode_absolute_path(data["verifier_executable_path"])
    manifest_path = _decode_absolute_path(data["relation_manifest_path"])
    executable_sha256 = _decode_nonzero_lower_sha256(data["verifier_executable_sha256"])
    return _VerifiedPreflightConfig(
        verifier_executable_path=executable_path,
        verifier_executable_sha256_hex=executable_sha256,
        relation_manifest_path=manifest_path,
        verifier_timeout_ms=data["verifier_timeout_ms"],
    )


def _validate_call_inputs(
    envelope_wire: object,
    bundle_wire: object,
    approval_wire: object,
    report_nonce: object,
    current_time: object,
) -> None:
    if (
        type(envelope_wire) is not bytes
        or not 0 < len(envelope_wire) <= MAX_CANONICAL_V2_PROOF_ENVELOPE_BYTES
        or type(bundle_wire) is not bytes
        or type(approval_wire) is not bytes
        or type(report_nonce) is not bytes
        or len(report_nonce) != FIXED_HASH_BYTES
        or type(current_time) is not int
        or not 1 <= current_time <= U64_MAX
    ):
        raise ThreatHintV2VerifiedPreflightError()


def _decode_absolute_path(value: object) -> Path:
    if type(value) is not str or not value or "\x00" in value:
        raise ThreatHintV2VerifiedPreflightUnavailableError()
    path = Path(value)
    if not path.is_absolute() or path.name in {"", ".", ".."} or ".." in path.parts:
        raise ThreatHintV2VerifiedPreflightUnavailableError()
    return path


def _decode_nonzero_lower_sha256(value: object) -> str:
    if (
        type(value) is not str
        or len(value) != FIXED_HASH_BYTES * 2
        or any(character not in "0123456789abcdef" for character in value)
        or not any(character != "0" for character in value)
    ):
        raise ThreatHintV2VerifiedPreflightUnavailableError()
    return value


def _read_owner_file(
    path: Path,
    limit: int,
    *,
    require_owner_only_parent: bool,
    unavailable: bool,
) -> bytes:
    error = (
        ThreatHintV2VerifiedPreflightUnavailableError
        if unavailable
        else ThreatHintV2VerifiedPreflightError
    )
    if (
        not isinstance(path, Path)
        or not path.is_absolute()
        or path.name in {"", ".", ".."}
        or ".." in path.parts
    ):
        raise error()
    try:
        parent = path.parent.resolve(strict=True)
        parent_stat = parent.stat()
        before = path.lstat()
        candidate = parent / path.name
        if (
            candidate != path
            or not stat.S_ISDIR(parent_stat.st_mode)
            or parent_stat.st_uid != os.getuid()
            or (require_owner_only_parent and bool(parent_stat.st_mode & 0o077))
            or not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.getuid()
            or before.st_mode & 0o077
            or before.st_mode & 0o7000
            or not 0 < before.st_size <= limit
        ):
            raise error()
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(candidate, flags)
        try:
            opened = os.fstat(descriptor)
            if (
                before.st_dev != opened.st_dev
                or before.st_ino != opened.st_ino
                or before.st_size != opened.st_size
                or not stat.S_ISREG(opened.st_mode)
            ):
                raise error()
            contents = _read_descriptor(descriptor, limit)
        finally:
            os.close(descriptor)
    except (OSError, ValueError):
        raise error() from None
    if len(contents) != before.st_size:
        raise error()
    return contents


def _validate_and_hash_executable(path: Path, expected_sha256: str) -> Path:
    try:
        resolved = path.resolve(strict=True)
        if resolved != path:
            raise ThreatHintV2VerifiedPreflightUnavailableError()
        for parent in path.parents:
            parent_stat = parent.lstat()
            if not _is_safe_executable_ancestor(parent_stat):
                raise ThreatHintV2VerifiedPreflightUnavailableError()

        before = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid not in {0, os.getuid()}
            or before.st_mode & 0o022
            or before.st_mode & 0o7000
            or not before.st_mode & stat.S_IXUSR
            or not 0 < before.st_size <= MAX_VERIFIER_EXECUTABLE_BYTES
        ):
            raise ThreatHintV2VerifiedPreflightUnavailableError()

        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            opened = os.fstat(descriptor)
            if (
                before.st_dev != opened.st_dev
                or before.st_ino != opened.st_ino
                or before.st_size != opened.st_size
                or not stat.S_ISREG(opened.st_mode)
            ):
                raise ThreatHintV2VerifiedPreflightUnavailableError()
            contents = _read_descriptor(descriptor, MAX_VERIFIER_EXECUTABLE_BYTES)
        finally:
            os.close(descriptor)
    except ThreatHintV2VerifiedPreflightUnavailableError:
        raise
    except (OSError, ValueError):
        raise ThreatHintV2VerifiedPreflightUnavailableError() from None

    if (
        len(contents) != before.st_size
        or hashlib.sha256(contents).hexdigest() != expected_sha256
    ):
        raise ThreatHintV2VerifiedPreflightUnavailableError()
    return resolved


def _is_safe_executable_ancestor(current: os.stat_result) -> bool:
    if not stat.S_ISDIR(current.st_mode) or current.st_uid not in {0, os.getuid()}:
        return False
    if not current.st_mode & 0o022:
        return True
    return current.st_uid == 0 and bool(current.st_mode & stat.S_ISVTX)


def _read_descriptor(descriptor: int, limit: int) -> bytes:
    chunks: list[bytes] = []
    remaining = limit + 1
    while remaining:
        chunk = os.read(descriptor, min(remaining, 64 * 1_024))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    contents = b"".join(chunks)
    if len(contents) > limit:
        raise ThreatHintV2VerifiedPreflightUnavailableError()
    return contents


def _constant_time_hex_digest_matches(contents: bytes, expected_hex: str) -> bool:
    return hmac.compare_digest(
        hashlib.sha256(contents).digest(), bytes.fromhex(expected_hex)
    )


def _kill_and_reap_process_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        try:
            process.kill()
        except OSError:
            pass
    try:
        process.wait(timeout=1)
    except (OSError, subprocess.SubprocessError):
        try:
            process.kill()
            process.wait(timeout=1)
        except (OSError, subprocess.SubprocessError):
            pass


def _build_receipt(
    preflight: ThreatHintV2PreflightReceipt,
    executable_sha256_hex: str,
) -> ThreatHintV2VerifiedPreflightReceipt:
    receipt = object.__new__(ThreatHintV2VerifiedPreflightReceipt)
    object.__setattr__(receipt, "statement_digest", preflight.statement_digest)
    object.__setattr__(receipt, "approval_id", preflight.approval_id)
    object.__setattr__(
        receipt, "observable_commitment", preflight.observable_commitment
    )
    object.__setattr__(
        receipt,
        "raw_manifest_sha256_hex",
        preflight.raw_manifest_sha256_hex,
    )
    object.__setattr__(receipt, "envelope_sha256_hex", preflight.envelope_sha256_hex)
    object.__setattr__(
        receipt,
        "verifier_executable_sha256_hex",
        executable_sha256_hex,
    )
    return receipt

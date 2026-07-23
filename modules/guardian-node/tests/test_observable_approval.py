"""Cross-language tests for local Observable Approval verification."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from coincurve import PublicKeyXOnly

from jaeger.observable_approval import (
    APPROVAL_ID_DOMAIN,
    APPROVAL_SIGNING_DOMAIN,
    MAX_CANONICAL_APPROVAL_BYTES,
    ObservableApprovalContext,
    ObservableApprovalError,
    VerifiedObservableApproval,
    verify_observable_approval,
)
from jaeger.threat_observable import ObservableBundle

_VECTOR_PATH = (
    Path(__file__).resolve().parents[2]
    / "threat-hint"
    / "tests"
    / "vectors"
    / "threat-observable-approval-v1.json"
)


def _unique_object(items: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in items:
        assert key not in result, f"duplicate fixture key: {key}"
        result[key] = value
    return result


def _vector() -> dict:
    vector = json.loads(
        _VECTOR_PATH.read_text(encoding="utf-8"),
        object_pairs_hook=_unique_object,
    )
    assert set(vector) == {
        "vector_schema_version",
        "bundle_wire_hex",
        "report_nonce_hex",
        "network_id",
        "trusted_approver_xonly_public_key_hex",
        "trusted_recipient_scope_hex",
        "current_time",
        "not_before",
        "expires_at",
        "approval_nonce_hex",
        "observable_commitment_hex",
        "signing_body_hex",
        "signing_digest_hex",
        "approval_wire_hex",
        "approval_id_hex",
    }
    assert vector["vector_schema_version"] == 1
    return vector


def _digest(domain: bytes, value: bytes) -> bytes:
    digest = hashlib.sha256()
    digest.update(domain)
    digest.update(len(value).to_bytes(4, byteorder="big", signed=False))
    digest.update(value)
    return digest.digest()


def _context(vector: dict, **changes: object) -> ObservableApprovalContext:
    values = {
        "report_nonce": bytes.fromhex(vector["report_nonce_hex"]),
        "approver_xonly_public_key": bytes.fromhex(
            vector["trusted_approver_xonly_public_key_hex"]
        ),
        "recipient_scope": bytes.fromhex(vector["trusted_recipient_scope_hex"]),
        "network_id": vector["network_id"],
        "current_time": vector["current_time"],
    }
    values.update(changes)
    return ObservableApprovalContext(**values)


def _assert_invalid(
    approval_wire: bytes,
    bundle_wire: bytes,
    context: ObservableApprovalContext,
) -> None:
    with pytest.raises(ObservableApprovalError, match=r"^invalid observable approval$"):
        verify_observable_approval(approval_wire, bundle_wire, context)


def test_fixture_commitment_digest_and_signature_validate_independently() -> None:
    vector = _vector()
    bundle_wire = bytes.fromhex(vector["bundle_wire_hex"])
    approval_wire = bytes.fromhex(vector["approval_wire_hex"])
    signing_body = bytes.fromhex(vector["signing_body_hex"])
    approval = json.loads(
        approval_wire.decode("ascii"), object_pairs_hook=_unique_object
    )

    assert (
        json.dumps(approval, separators=(",", ":"), ensure_ascii=False).encode()
        == approval_wire
    )
    assert approval["observable_commitment"] == vector["observable_commitment_hex"]
    assert (
        approval["approver_xonly_public_key"]
        == vector["trusted_approver_xonly_public_key_hex"]
    )
    assert approval["recipient_scope"] == vector["trusted_recipient_scope_hex"]
    assert approval["network_id"] == vector["network_id"]
    assert approval["not_before"] == vector["not_before"]
    assert approval["expires_at"] == vector["expires_at"]
    assert approval["approval_nonce"] == vector["approval_nonce_hex"]

    expected_signing_body = {
        "schema_version": approval["schema_version"],
        "observable_commitment": approval["observable_commitment"],
        "approver_xonly_public_key": approval["approver_xonly_public_key"],
        "purpose": approval["purpose"],
        "recipient_scope": approval["recipient_scope"],
        "network_id": approval["network_id"],
        "not_before": approval["not_before"],
        "expires_at": approval["expires_at"],
        "approval_nonce": approval["approval_nonce"],
    }
    assert (
        json.dumps(
            expected_signing_body, separators=(",", ":"), ensure_ascii=False
        ).encode()
        == signing_body
    )

    bundle = ObservableBundle.parse_canonical(bundle_wire)
    assert (
        bundle.commitment(vector["network_id"], vector["report_nonce_hex"]).hex()
        == vector["observable_commitment_hex"]
    )

    signing_digest = _digest(APPROVAL_SIGNING_DOMAIN, signing_body)
    assert signing_digest.hex() == vector["signing_digest_hex"]
    assert PublicKeyXOnly(
        bytes.fromhex(vector["trusted_approver_xonly_public_key_hex"])
    ).verify(bytes.fromhex(approval["signature"]), signing_digest)
    assert _digest(APPROVAL_ID_DOMAIN, approval_wire).hex() == vector["approval_id_hex"]


@pytest.mark.parametrize("time_field", ["not_before", "current_time", "expires_at"])
def test_fixture_verifies_at_inclusive_time_boundaries(time_field: str) -> None:
    vector = _vector()
    verified = verify_observable_approval(
        bytes.fromhex(vector["approval_wire_hex"]),
        bytes.fromhex(vector["bundle_wire_hex"]),
        _context(vector, current_time=vector[time_field]),
    )

    assert verified.approval_id.hex() == vector["approval_id_hex"]
    assert verified.observable_commitment.hex() == vector["observable_commitment_hex"]
    assert (
        verified.approver_xonly_public_key.hex()
        == vector["trusted_approver_xonly_public_key_hex"]
    )
    assert verified.recipient_scope.hex() == vector["trusted_recipient_scope_hex"]
    assert verified.approval_nonce.hex() == vector["approval_nonce_hex"]
    assert verified.network_id == vector["network_id"]
    assert verified.not_before == vector["not_before"]
    assert verified.expires_at == vector["expires_at"]


def test_expired_and_mismatched_trusted_contexts_are_rejected() -> None:
    vector = _vector()
    approval_wire = bytes.fromhex(vector["approval_wire_hex"])
    bundle_wire = bytes.fromhex(vector["bundle_wire_hex"])

    contexts = [
        _context(vector, current_time=vector["not_before"] - 1),
        _context(vector, current_time=vector["expires_at"] + 1),
        _context(vector, report_nonce=b"\x44" * 32),
        _context(vector, approver_xonly_public_key=b"\x55" * 32),
        _context(vector, recipient_scope=b"\x66" * 32),
        _context(vector, network_id="mainnet"),
    ]
    for context in contexts:
        _assert_invalid(approval_wire, bundle_wire, context)


def test_tampering_noncanonical_input_and_public_auto_bundle_are_rejected() -> None:
    vector = _vector()
    approval_wire = bytes.fromhex(vector["approval_wire_hex"])
    bundle_wire = bytes.fromhex(vector["bundle_wire_hex"])
    context = _context(vector)
    approval = json.loads(approval_wire.decode("ascii"))

    first = approval["signature"][0]
    approval["signature"] = ("1" if first == "0" else "0") + approval["signature"][1:]
    tampered_signature = json.dumps(approval, separators=(",", ":")).encode()

    canonical_approval = json.loads(approval_wire.decode("ascii"))
    reordered = json.dumps(
        dict(reversed(list(canonical_approval.items()))), separators=(",", ":")
    ).encode()
    duplicate = approval_wire.replace(b"{", b'{"schema_version":1,', 1)
    unknown = approval_wire[:-1] + b',"unexpected":true}'
    public_auto = (
        b'{"schema_version":1,"disclosure_policy":"public_auto_v1",'
        b'"scope":{"platform":"linux","format":"elf"},'
        b'"observables":[{"kind":"api_import","value":"mmap"}]}'
    )
    rejected_wires = [
        tampered_signature,
        approval_wire + b"\n",
        reordered,
        duplicate,
        unknown,
        b"{" * (MAX_CANONICAL_APPROVAL_BYTES + 1),
    ]
    for rejected in rejected_wires:
        _assert_invalid(rejected, bundle_wire, context)
    _assert_invalid(approval_wire, public_auto, context)


def test_result_construction_and_error_details_are_closed() -> None:
    with pytest.raises(TypeError):
        VerifiedObservableApproval()

    marker = "secret$context-marker"
    invalid_context = ObservableApprovalContext(
        report_nonce=b"\x11" * 32,
        approver_xonly_public_key=b"\x22" * 32,
        recipient_scope=b"\x33" * 32,
        network_id=marker,
        current_time=1,
    )
    with pytest.raises(ObservableApprovalError) as exc_info:
        invalid_context.validate()
    assert str(exc_info.value) == "invalid observable approval"
    assert marker not in str(exc_info.value)

    oversized_time = ObservableApprovalContext(
        report_nonce=b"\x11" * 32,
        approver_xonly_public_key=b"\x22" * 32,
        recipient_scope=b"\x33" * 32,
        network_id="testnet-10",
        current_time=1 << 64,
    )
    with pytest.raises(ObservableApprovalError):
        oversized_time.validate()


def test_context_subclass_cannot_override_validation_or_time_comparisons() -> None:
    vector = _vector()

    class AlwaysInsideWindow:
        def __lt__(self, other: object) -> bool:
            del other
            return False

        def __gt__(self, other: object) -> bool:
            del other
            return False

    class BypassContext(ObservableApprovalContext):
        def validate(self) -> None:
            return

    bypass = BypassContext(
        report_nonce=bytes.fromhex(vector["report_nonce_hex"]),
        approver_xonly_public_key=bytes.fromhex(
            vector["trusted_approver_xonly_public_key_hex"]
        ),
        recipient_scope=bytes.fromhex(vector["trusted_recipient_scope_hex"]),
        network_id=vector["network_id"],
        current_time=AlwaysInsideWindow(),
    )

    _assert_invalid(
        bytes.fromhex(vector["approval_wire_hex"]),
        bytes.fromhex(vector["bundle_wire_hex"]),
        bypass,
    )

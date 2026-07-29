"""Tests for the local data-only non-consuming ThreatHint-v2 preflight."""

# Pytest test names provide the scenario descriptions.
# pylint: disable=missing-function-docstring,too-many-locals

from __future__ import annotations

import dataclasses
import hashlib
import inspect
import json
import os
import pickle
import stat
from pathlib import Path
from typing import Any, Dict, Iterable

import pytest
from coincurve import PrivateKey, PublicKeyXOnly

from jaeger.observable_approval import APPROVAL_SIGNING_DOMAIN
from jaeger.threat_hint_v2_preflight import (
    MAX_PREFLIGHT_POLICY_BYTES,
    ThreatHintV2PreflightError,
    ThreatHintV2PreflightReceipt,
    ThreatHintV2PreflightService,
)
from jaeger.threat_hint_v2_statement import STATEMENT_DIGEST_DOMAIN
from jaeger.threat_observable import ObservableBundle

_BINDING_VECTOR_PATH = (
    Path(__file__).resolve().parents[2]
    / "threat-proof"
    / "tests"
    / "vectors"
    / "threat-hint-v2-proof-binding-v1.json"
)
_APPROVAL_VECTOR_PATH = (
    Path(__file__).resolve().parents[2]
    / "threat-hint"
    / "tests"
    / "vectors"
    / "threat-observable-approval-v1.json"
)

_PUBLIC_AUTO_BUNDLE = (
    b'{"schema_version":1,"disclosure_policy":"public_auto_v1",'
    b'"scope":{"platform":"linux","format":"elf"},'
    b'"observables":[{"kind":"api_import","value":"mmap"}]}'
)
_DEEPLY_NESTED_JSON = b"[" * 2_000 + b"]" * 2_000


def _unique_object(items: Iterable[tuple[str, Any]]) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for key, value in items:
        assert key not in result, f"duplicate fixture key: {key}"
        result[key] = value
    return result


def _binding_case(name: str = "base_testnet") -> dict:
    corpus = json.loads(
        _BINDING_VECTOR_PATH.read_text(encoding="utf-8"),
        object_pairs_hook=_unique_object,
    )
    cases = {case["name"]: case for case in corpus["valid_cases"]}
    return cases[name]


def _approval_vector() -> dict:
    return json.loads(
        _APPROVAL_VECTOR_PATH.read_text(encoding="utf-8"),
        object_pairs_hook=_unique_object,
    )


def _owner_directory(tmp_path: Path, name: str = "policy") -> Path:
    directory = tmp_path / name
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    return directory


def _write_raw_policy(directory: Path, text: str, name: str = "policy.toml") -> Path:
    policy_path = directory / name
    policy_path.write_text(text, encoding="ascii")
    policy_path.chmod(0o600)
    return policy_path


# pylint: disable-next=too-many-arguments
def _write_policy(
    directory: Path,
    vector: dict,
    anchor_hex: str,
    *,
    key_hex: str | None = None,
    scope_hex: str | None = None,
    network_id: str | None = None,
    name: str = "policy.toml",
) -> Path:
    return _write_raw_policy(
        directory,
        "\n".join(
            (
                "schema_version = 1",
                f'network_id = "{network_id or vector["network_id"]}"',
                "approver_xonly_public_key = "
                f'"{key_hex or vector["trusted_approver_xonly_public_key_hex"]}"',
                f'recipient_scope = "{scope_hex or vector["trusted_recipient_scope_hex"]}"',
                f'relation_manifest_sha256 = "{anchor_hex}"',
                "",
            )
        ),
        name,
    )


def _statement_wire(
    commitment_hex: str,
    nonce_hex: str,
    network_id: str,
    disclosure_class: str = "review_required_v1",
) -> bytes:
    payload = {
        "schema_version": 2,
        "artifact_hash": "aa" * 32,
        "observable_commitment": commitment_hex,
        "confidence_bps": 7500,
        "disclosure_class": disclosure_class,
        "report_nonce": nonce_hex,
        "observed_at": 1_700_000_000,
        "network_id": network_id,
    }
    return json.dumps(payload, separators=(",", ":")).encode("ascii")


def _envelope_wire(statement_wire: bytes, proof_hex: str = "aa" * 16) -> bytes:
    digest = hashlib.sha256()
    digest.update(STATEMENT_DIGEST_DOMAIN)
    digest.update(len(statement_wire).to_bytes(4, byteorder="big", signed=False))
    digest.update(statement_wire)
    payload = {
        "schema_version": 2,
        "protocol_id": "/prometheus/threat-hint/2.0.0",
        "relation_id": "prometheus-threat-hint-v2",
        "statement": statement_wire.decode("ascii"),
        "statement_digest": digest.hexdigest(),
        "proof": proof_hex,
    }
    return json.dumps(payload, separators=(",", ":")).encode("ascii")


# pylint: disable-next=too-many-instance-attributes,too-few-public-methods
class _Scenario:
    def __init__(
        self,
        tmp_path: Path,
        directory_name: str = "scenario",
        **policy_changes: object,
    ) -> None:
        vector = _approval_vector()
        case = _binding_case()
        self.manifest_wire = bytes.fromhex(case["manifest_wire_hex"])
        self.anchor_hex = case["manifest_sha256_hex"]
        self.bundle_wire = bytes.fromhex(vector["bundle_wire_hex"])
        self.approval_wire = bytes.fromhex(vector["approval_wire_hex"])
        self.report_nonce = bytes.fromhex(vector["report_nonce_hex"])
        self.current_time = vector["current_time"]
        self.statement_wire = _statement_wire(
            vector["observable_commitment_hex"],
            vector["report_nonce_hex"],
            vector["network_id"],
        )
        self.envelope_wire = _envelope_wire(self.statement_wire)
        self.directory = _owner_directory(tmp_path, directory_name)
        self.policy_path = _write_policy(
            self.directory, vector, self.anchor_hex, **policy_changes
        )
        self.vector = vector


def _preflight(
    service: ThreatHintV2PreflightService,
    scenario: _Scenario,
    **changes: object,
) -> ThreatHintV2PreflightReceipt:
    inputs = {
        "envelope_wire": scenario.envelope_wire,
        "manifest_wire": scenario.manifest_wire,
        "bundle_wire": scenario.bundle_wire,
        "approval_wire": scenario.approval_wire,
        "report_nonce": scenario.report_nonce,
        "current_time": scenario.current_time,
    }
    inputs.update(changes)
    return service.preflight(
        inputs["envelope_wire"],
        inputs["manifest_wire"],
        inputs["bundle_wire"],
        inputs["approval_wire"],
        report_nonce=inputs["report_nonce"],
        current_time=inputs["current_time"],
    )


def _assert_invalid(
    service: ThreatHintV2PreflightService, scenario: _Scenario, **changes: object
) -> None:
    with pytest.raises(
        ThreatHintV2PreflightError, match=r"^invalid threat-hint v2 preflight$"
    ):
        _preflight(service, scenario, **changes)


def _snapshot(root: Path) -> dict:
    result = {}
    for path in sorted(root.rglob("*")):
        relative = str(path.relative_to(root))
        if path.is_symlink():
            result[relative] = ("symlink", os.readlink(path))
        elif path.is_dir():
            result[relative] = ("dir", stat.S_IMODE(path.stat().st_mode))
        else:
            file_stat = path.stat()
            result[relative] = (
                "file",
                stat.S_IMODE(file_stat.st_mode),
                file_stat.st_size,
                hashlib.sha256(path.read_bytes()).hexdigest(),
            )
    return result


def _domain_digest(domain: bytes, value: bytes) -> bytes:
    digest = hashlib.sha256()
    digest.update(domain)
    digest.update(len(value).to_bytes(4, byteorder="big", signed=False))
    digest.update(value)
    return digest.digest()


def _signed_approval(scenario: _Scenario, key: PrivateKey) -> bytes:
    vector = scenario.vector
    bundle = ObservableBundle.parse_canonical(scenario.bundle_wire)
    body = {
        "schema_version": 1,
        "observable_commitment": bundle.commitment(
            vector["network_id"], vector["report_nonce_hex"]
        ).hex(),
        "approver_xonly_public_key": PublicKeyXOnly.from_secret(key.secret)
        .format()
        .hex(),
        "purpose": "guardian_analysis_v1",
        "recipient_scope": vector["trusted_recipient_scope_hex"],
        "network_id": vector["network_id"],
        "not_before": vector["not_before"],
        "expires_at": vector["expires_at"],
        "approval_nonce": vector["approval_nonce_hex"],
    }
    body_wire = json.dumps(body, separators=(",", ":")).encode("ascii")
    signature = key.sign_schnorr(_domain_digest(APPROVAL_SIGNING_DOMAIN, body_wire))
    return json.dumps(
        {**body, "signature": signature.hex()}, separators=(",", ":")
    ).encode("ascii")


def test_valid_preflight_returns_exact_data_only_receipt(tmp_path: Path) -> None:
    scenario = _Scenario(tmp_path)
    service = ThreatHintV2PreflightService(scenario.policy_path)

    receipt = _preflight(service, scenario)

    vector = scenario.vector
    expected_digest = hashlib.sha256()
    expected_digest.update(STATEMENT_DIGEST_DOMAIN)
    expected_digest.update(
        len(scenario.statement_wire).to_bytes(4, byteorder="big", signed=False)
    )
    expected_digest.update(scenario.statement_wire)
    assert receipt.statement_digest == expected_digest.digest()
    assert receipt.approval_id.hex() == vector["approval_id_hex"]
    assert receipt.observable_commitment.hex() == vector["observable_commitment_hex"]
    assert receipt.raw_manifest_sha256_hex == scenario.anchor_hex
    assert (
        receipt.envelope_sha256_hex
        == hashlib.sha256(scenario.envelope_wire).hexdigest()
    )
    assert {field.name for field in dataclasses.fields(receipt)} == {
        "statement_digest",
        "approval_id",
        "observable_commitment",
        "raw_manifest_sha256_hex",
        "envelope_sha256_hex",
    }


def test_public_api_has_no_statement_or_trusted_anchor_parameters() -> None:
    init_parameters = set(
        inspect.signature(ThreatHintV2PreflightService.__init__).parameters
    )
    assert init_parameters == {"self", "policy_path"}

    parameters = set(
        inspect.signature(ThreatHintV2PreflightService.preflight).parameters
    )
    assert parameters == {
        "self",
        "envelope_wire",
        "manifest_wire",
        "bundle_wire",
        "approval_wire",
        "report_nonce",
        "current_time",
    }
    for forbidden in (
        "statement",
        "statement_wire",
        "trusted_network_id",
        "network_id",
        "trusted_manifest_sha256_hex",
        "relation_manifest_sha256",
        "approver_xonly_public_key",
        "recipient_scope",
        "verified",
        "ledger_path",
    ):
        assert forbidden not in parameters


def test_policy_rejects_non_exact_schema_and_malformed_values(tmp_path: Path) -> None:
    vector = _approval_vector()
    anchor = _binding_case()["manifest_sha256_hex"]
    valid_lines = (
        "schema_version = 1",
        f'network_id = "{vector["network_id"]}"',
        f"approver_xonly_public_key = "
        f'"{vector["trusted_approver_xonly_public_key_hex"]}"',
        f'recipient_scope = "{vector["trusted_recipient_scope_hex"]}"',
        f'relation_manifest_sha256 = "{anchor}"',
        "",
    )
    valid_text = "\n".join(valid_lines)
    replacements = [
        valid_text.replace("schema_version = 1", "schema_version = 2"),
        valid_text.replace("schema_version = 1", 'schema_version = "1"'),
        valid_text.replace(
            "schema_version = 1", "schema_version = 1\nunexpected = true"
        ),
        valid_text.replace(f'relation_manifest_sha256 = "{anchor}"\n', ""),
        valid_text + 'ledger_path = "/tmp/ledger.sqlite3"\n',
        valid_text.replace(f'"{vector["network_id"]}"', "10"),
        valid_text.replace(vector["network_id"], "INVALID!"),
        valid_text.replace(
            vector["trusted_approver_xonly_public_key_hex"],
            vector["trusted_approver_xonly_public_key_hex"].upper(),
        ),
        valid_text.replace(vector["trusted_approver_xonly_public_key_hex"], "ab" * 16),
        valid_text.replace(f'"{vector["trusted_recipient_scope_hex"]}"', "true"),
        valid_text.replace(anchor, "00" * 32),
        valid_text.replace(anchor, anchor.upper()),
        valid_text.replace(
            f'relation_manifest_sha256 = "{anchor}"', "relation_manifest_sha256 = 1"
        ),
    ]
    for index, text in enumerate(replacements):
        directory = _owner_directory(tmp_path, f"case-{index}")
        policy_path = _write_raw_policy(directory, text)
        with pytest.raises(
            ThreatHintV2PreflightError,
            match=r"^invalid threat-hint v2 preflight$",
        ):
            ThreatHintV2PreflightService(policy_path)


@pytest.mark.skipif(os.name != "posix", reason="POSIX file modes are required")
def test_policy_requires_owner_only_regular_absolute_file(tmp_path: Path) -> None:
    scenario = _Scenario(tmp_path)

    with pytest.raises(ThreatHintV2PreflightError):
        ThreatHintV2PreflightService(Path("relative-policy.toml"))
    with pytest.raises(ThreatHintV2PreflightError):
        ThreatHintV2PreflightService(str(scenario.policy_path))  # type: ignore[arg-type]
    with pytest.raises(ThreatHintV2PreflightError):
        ThreatHintV2PreflightService(scenario.directory / "missing.toml")
    with pytest.raises(ThreatHintV2PreflightError):
        ThreatHintV2PreflightService(scenario.directory)

    target = _write_raw_policy(
        scenario.directory, "schema_version = 1\n", "target.toml"
    )
    link = scenario.directory / "policy-link.toml"
    link.symlink_to(target)
    with pytest.raises(ThreatHintV2PreflightError):
        ThreatHintV2PreflightService(link)

    mode_path = _write_raw_policy(
        scenario.directory, "schema_version = 1\n", "mode.toml"
    )
    mode_path.chmod(0o640)
    with pytest.raises(ThreatHintV2PreflightError):
        ThreatHintV2PreflightService(mode_path)

    empty_path = _write_raw_policy(scenario.directory, "", "empty.toml")
    with pytest.raises(ThreatHintV2PreflightError):
        ThreatHintV2PreflightService(empty_path)

    oversized_path = _write_raw_policy(
        scenario.directory,
        "#" * (MAX_PREFLIGHT_POLICY_BYTES + 1),
        "oversized.toml",
    )
    with pytest.raises(ThreatHintV2PreflightError):
        ThreatHintV2PreflightService(oversized_path)

    non_ascii_path = scenario.directory / "non-ascii.toml"
    non_ascii_path.write_bytes(b"schema_version = 1\n# \xff\n")
    non_ascii_path.chmod(0o600)
    with pytest.raises(ThreatHintV2PreflightError):
        ThreatHintV2PreflightService(non_ascii_path)

    shared = tmp_path / "shared"
    shared.mkdir(mode=0o755)
    shared.chmod(0o755)
    shared_policy = _write_policy(shared, scenario.vector, scenario.anchor_hex)
    with pytest.raises(ThreatHintV2PreflightError):
        ThreatHintV2PreflightService(shared_policy)


def test_policy_loading_performs_no_writes(tmp_path: Path) -> None:
    scenario = _Scenario(tmp_path)
    before = _snapshot(tmp_path)
    ThreatHintV2PreflightService(scenario.policy_path)
    assert _snapshot(tmp_path) == before
    assert not [path for path in tmp_path.rglob("*") if "sqlite" in path.name]


def test_same_statement_different_proof_is_a_separate_data_only_preflight(
    tmp_path: Path,
) -> None:
    scenario = _Scenario(tmp_path)
    service = ThreatHintV2PreflightService(scenario.policy_path)
    alternate_envelope = _envelope_wire(scenario.statement_wire, proof_hex="bb" * 16)
    assert alternate_envelope != scenario.envelope_wire

    first = _preflight(service, scenario)
    second = _preflight(service, scenario, envelope_wire=alternate_envelope)

    # The opaque proof bytes are never verified: the same statement with
    # different proof bytes is a separate data-only preflight result.
    assert second.statement_digest == first.statement_digest
    assert second.approval_id == first.approval_id
    assert second.observable_commitment == first.observable_commitment
    assert second.raw_manifest_sha256_hex == first.raw_manifest_sha256_hex
    assert second.envelope_sha256_hex != first.envelope_sha256_hex
    assert second.envelope_sha256_hex == hashlib.sha256(alternate_envelope).hexdigest()


def test_anchor_network_nonce_and_commitment_mismatches_fail_closed(
    tmp_path: Path,
) -> None:
    scenario = _Scenario(tmp_path)
    service = ThreatHintV2PreflightService(scenario.policy_path)

    anchor_directory = _owner_directory(tmp_path, "anchor")
    anchor_policy = _write_policy(anchor_directory, scenario.vector, "11" * 32)
    _assert_invalid(ThreatHintV2PreflightService(anchor_policy), scenario)

    network_directory = _owner_directory(tmp_path, "network")
    network_policy = _write_policy(
        network_directory,
        scenario.vector,
        scenario.anchor_hex,
        network_id="testnet-11",
    )
    _assert_invalid(ThreatHintV2PreflightService(network_policy), scenario)

    _assert_invalid(service, scenario, report_nonce=b"\x44" * 32)

    wrong_commitment_statement = _statement_wire(
        "ee" * 32,
        scenario.vector["report_nonce_hex"],
        scenario.vector["network_id"],
    )
    _assert_invalid(
        service,
        scenario,
        envelope_wire=_envelope_wire(wrong_commitment_statement),
    )


def test_disclosure_signature_time_and_key_binding_fail_closed(tmp_path: Path) -> None:
    scenario = _Scenario(tmp_path)
    service = ThreatHintV2PreflightService(scenario.policy_path)
    vector = scenario.vector

    public_auto_statement = _statement_wire(
        vector["observable_commitment_hex"],
        vector["report_nonce_hex"],
        vector["network_id"],
        disclosure_class="public_auto_v1",
    )
    _assert_invalid(
        service,
        scenario,
        envelope_wire=_envelope_wire(public_auto_statement),
    )
    _assert_invalid(service, scenario, bundle_wire=_PUBLIC_AUTO_BUNDLE)

    approval = json.loads(scenario.approval_wire.decode("ascii"))
    first = approval["signature"][0]
    approval["signature"] = ("1" if first == "0" else "0") + approval["signature"][1:]
    tampered = json.dumps(approval, separators=(",", ":")).encode("ascii")
    _assert_invalid(service, scenario, approval_wire=tampered)

    _assert_invalid(service, scenario, current_time=vector["expires_at"] + 1)
    _assert_invalid(service, scenario, current_time=vector["not_before"] - 1)

    # An approval signed by an ephemeral test-only key verifies against a
    # policy pinned to that key and fails against the fixture-key policy.
    key = PrivateKey()
    ephemeral_approval = _signed_approval(scenario, key)
    ephemeral_directory = _owner_directory(tmp_path, "ephemeral")
    ephemeral_policy = _write_policy(
        ephemeral_directory,
        vector,
        scenario.anchor_hex,
        key_hex=PublicKeyXOnly.from_secret(key.secret).format().hex(),
    )
    ephemeral_service = ThreatHintV2PreflightService(ephemeral_policy)
    receipt = _preflight(ephemeral_service, scenario, approval_wire=ephemeral_approval)
    assert receipt.observable_commitment.hex() == vector["observable_commitment_hex"]
    _assert_invalid(service, scenario, approval_wire=ephemeral_approval)


@pytest.mark.parametrize(
    "changes",
    [
        {"envelope_wire": b"not json"},
        {"manifest_wire": b"not json"},
        {"bundle_wire": b'{"schema_version":1}'},
        {"approval_wire": b"not json"},
        {"envelope_wire": _DEEPLY_NESTED_JSON},
        {"bundle_wire": _DEEPLY_NESTED_JSON},
        {"approval_wire": _DEEPLY_NESTED_JSON},
        {"envelope_wire": "text"},
        {"manifest_wire": 123},
        {"bundle_wire": None},
        {"approval_wire": True},
        {"report_nonce": b"\x11" * 31},
        {"report_nonce": "aa" * 32},
        {"report_nonce": None},
        {"current_time": 0},
        {"current_time": -1},
        {"current_time": True},
        {"current_time": 1 << 64},
        {"current_time": "1700000300"},
    ],
)
def test_invalid_wires_types_nonce_and_time_fail_closed(
    tmp_path: Path, changes: dict
) -> None:
    scenario = _Scenario(tmp_path)
    service = ThreatHintV2PreflightService(scenario.policy_path)
    _assert_invalid(service, scenario, **changes)


def test_bytearray_wires_are_rejected(tmp_path: Path) -> None:
    scenario = _Scenario(tmp_path)
    service = ThreatHintV2PreflightService(scenario.policy_path)
    _assert_invalid(service, scenario, envelope_wire=bytearray(scenario.envelope_wire))
    _assert_invalid(service, scenario, approval_wire=bytearray(scenario.approval_wire))
    _assert_invalid(service, scenario, report_nonce=bytearray(scenario.report_nonce))


def test_error_is_one_stable_redacted_message(tmp_path: Path) -> None:
    marker = "secret$preflight-marker"
    directory = _owner_directory(tmp_path)
    policy_path = _write_raw_policy(directory, marker)
    with pytest.raises(ThreatHintV2PreflightError) as policy_error:
        ThreatHintV2PreflightService(policy_path)
    assert str(policy_error.value) == "invalid threat-hint v2 preflight"
    assert marker not in str(policy_error.value)

    scenario = _Scenario(tmp_path, directory_name="other")
    service = ThreatHintV2PreflightService(scenario.policy_path)
    with pytest.raises(ThreatHintV2PreflightError) as preflight_error:
        _preflight(service, scenario, report_nonce=b"\x44" * 32)
    message = str(preflight_error.value)
    assert message == "invalid threat-hint v2 preflight"
    for sensitive in (
        scenario.vector["trusted_approver_xonly_public_key_hex"],
        scenario.vector["trusted_recipient_scope_hex"],
        scenario.vector["report_nonce_hex"],
        scenario.anchor_hex,
    ):
        assert sensitive not in message


def test_no_files_created_or_changed_on_success_and_failure(tmp_path: Path) -> None:
    scenario = _Scenario(tmp_path)
    before = _snapshot(tmp_path)

    service = ThreatHintV2PreflightService(scenario.policy_path)
    _preflight(service, scenario)
    _assert_invalid(service, scenario, report_nonce=b"\x44" * 32)

    assert _snapshot(tmp_path) == before
    sqlite_files = [
        path for path in tmp_path.rglob("*") if "sqlite" in path.name.lower()
    ]
    assert sqlite_files == []


def test_trusted_anchor_accessors_are_read_only_and_policy_pinned(
    tmp_path: Path,
) -> None:
    scenario = _Scenario(tmp_path)
    service = ThreatHintV2PreflightService(scenario.policy_path)

    assert service.trusted_network_id == scenario.vector["network_id"]
    assert service.trusted_relation_manifest_sha256_hex == scenario.anchor_hex

    with pytest.raises(AttributeError):
        service.trusted_network_id = "testnet-11"  # type: ignore[misc]
    with pytest.raises(AttributeError):
        service.trusted_relation_manifest_sha256_hex = "11" * 32  # type: ignore[misc]


def test_trusted_identity_accessors_are_read_only_and_policy_pinned(
    tmp_path: Path,
) -> None:
    scenario = _Scenario(tmp_path)
    service = ThreatHintV2PreflightService(scenario.policy_path)

    assert service.trusted_approver_xonly_public_key == bytes.fromhex(
        scenario.vector["trusted_approver_xonly_public_key_hex"]
    )
    assert service.trusted_recipient_scope == bytes.fromhex(
        scenario.vector["trusted_recipient_scope_hex"]
    )

    with pytest.raises(AttributeError):
        service.trusted_approver_xonly_public_key = b"\x00" * 32  # type: ignore[misc]
    with pytest.raises(AttributeError):
        service.trusted_recipient_scope = b"\x00" * 32  # type: ignore[misc]


def test_direct_and_forged_receipts_grant_no_authority(tmp_path: Path) -> None:
    scenario = _Scenario(tmp_path)
    service = ThreatHintV2PreflightService(scenario.policy_path)
    receipt = _preflight(service, scenario)

    with pytest.raises(TypeError):
        ThreatHintV2PreflightReceipt()
    with pytest.raises(TypeError):
        dataclasses.replace(receipt)
    with pytest.raises(TypeError):
        pickle.dumps(receipt)

    forged = object.__new__(ThreatHintV2PreflightReceipt)
    with pytest.raises(AttributeError):
        _ = forged.statement_digest
    with pytest.raises(AttributeError):
        _ = forged.approval_id

    with pytest.raises(dataclasses.FrozenInstanceError):
        receipt.statement_digest = b"\x00" * 32  # type: ignore[misc]

    # The receipt exposes digests only; it carries no verification,
    # consumption, proof, or policy surface that could confer authority.
    for surface in (
        "consume",
        "verify",
        "proof",
        "statement",
        "bundle",
        "approval",
        "approver_xonly_public_key",
        "recipient_scope",
        "observables",
    ):
        assert not hasattr(receipt, surface)

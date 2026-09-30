#!/usr/bin/env python3
"""Fail closed when the GH-267 pre-producer privacy threat model drifts.

This gate is repository review and drift control only. It compares three
committed JSON artifacts: the versioned GH-267 threat model, the canonical
public claim status, and the shared Rust/Python endpoint-observation corpus.
It cannot prove that arbitrary code lacks a hidden sensor or covert collection
path, and it does not authorize endpoint collection, transport, or any runtime
action. It performs no source substring scanning and no host, network, wallet,
or production access. Error output is limited to stable data-minimal
categories and never echoes artifact, status, or corpus content values.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

ARTIFACT_PATH = Path("docs/evidence/endpoint-producer-privacy-threat-model-v1.json")
STATUS_PATH = Path("docs/evidence/public-claim-status-2026-08-14.json")
VECTORS_PATH = Path("modules/threat-hint/tests/vectors/endpoint-observation-v1.json")

EXPECTED_SCHEMA_VERSION = 1
EXPECTED_ISSUE = 267
EXPECTED_AS_OF = "2026-09-13"
EXPECTED_CLASSIFICATION = "pre_producer_privacy_threat_model_gate"
EXPECTED_SCOPE = "repository_review_and_drift_control_only"

EXPECTED_THREAT_ACTORS = [
    "remote_attacker_or_resource_conscription_controller",
    "curious_or_compromised_operator_with_host_access",
    "malicious_or_compromised_software_supply_chain_dependency",
    "network_observer_or_interceptor",
    "data_broker_or_third_party_recipient",
    "compromised_or_malicious_future_producer_component",
]

EXPECTED_ABUSE_CASES = [
    "default_on_or_coerced_collection_without_informed_per_host_opt_in",
    "raw_or_high_cardinality_host_data_smuggled_into_an_observation",
    "cross_window_or_cross_device_linkability_from_counts_time_nonce_or_network_context",
    "forged_or_poisoned_observations_treated_as_event_truth_or_maliciousness",
    "covert_retention_or_egress_before_local_aggregation_and_redaction",
    "repository_or_public_claim_drift_used_to_imply_unearned_authority",
    "observation_data_reused_for_automatic_response_identity_reputation_or_rewards",
]

EXPECTED_PROTECTED_DATA_CLASSES = [
    "process_names_and_command_lines",
    "file_paths_and_file_contents",
    "host_device_and_user_identifiers",
    "network_addresses_and_peer_identifiers",
    "credentials_keys_tokens_and_secret_material",
    "prompts_model_io_and_tool_payloads",
    "usage_patterns_and_behavioral_timelines",
    "linkability_from_counts_timestamps_nonces_and_network_context",
]

ALLOWED_STATEMENT_FIELDS = [
    "schema_version",
    "domain",
    "signal",
    "event_count",
    "window_seconds",
    "report_nonce",
    "observed_at",
    "network_id",
]

EXPECTED_PROHIBITED_RAW_DATA_CLASSES = [
    "process_name",
    "command_line",
    "file_path",
    "file_content",
    "host_or_device_identifier",
    "user_account_identifier",
    "network_address",
    "credential_or_secret_material",
    "prompt_or_model_payload",
    "free_text_or_arbitrary_label",
]

EXPECTED_PRIVACY_REJECTION_CASES = [
    {"vector": "privacy_process_name_field", "forbidden_wire_key": "process_name"},
    {"vector": "privacy_path_field", "forbidden_wire_key": "path"},
    {"vector": "privacy_host_identifier_field", "forbidden_wire_key": "host_id"},
    {"vector": "privacy_command_line_field", "forbidden_wire_key": "command_line"},
]

EXPECTED_TRUST_BOUNDARIES = [
    "repository_review_boundary: this gate compares committed artifacts only and trusts nothing at runtime",
    "producer_host_boundary: any future producer runs on the observed host under local OS permissions only",
    "aggregation_boundary: any future aggregation or redaction must complete locally before any disclosure",
    "transport_boundary: no network transport exists today; any future transport is a separately gated trust crossing",
    "status_boundary: the public claim status and the shared Rust/Python corpus are the canonical cross-check inputs",
]

EXPECTED_FUTURE_REQUIREMENTS = [
    "default_off_explicit_informed_per_host_opt_in_before_any_collection",
    "local_revocation_without_remote_dependency",
    "least_privilege_os_access_scoped_to_declared_domains",
    "bounded_aggregate_counts_only_no_raw_event_payload",
    "local_only_aggregation_and_redaction_before_any_disclosure",
    "data_minimization_limited_to_the_eight_allowed_statement_fields",
    "linkability_review_for_count_time_nonce_and_network_context",
    "explicit_bounded_retention_and_local_erasure_policy_before_collection",
    "independent_privacy_review_before_any_producer_implementation",
    "separate_transport_and_recipient_authorization_before_any_network_egress",
    "no_observation_reuse_for_identity_reputation_rewards_or_automatic_action",
]

EXPECTED_CURRENT_STATE = {
    "endpoint_producer": "not_implemented",
    "data_retention": "none",
    "network_transport": "none",
    "runtime_collection_authorized": False,
}

EXPECTED_PROMOTION_GATES = [
    "gh_264_observe_only_statement_remains_the_canonical_output_boundary",
    "shared_rust_python_corpus_must_keep_required_privacy_field_rejections",
    "public_status_capabilities_must_remain_false_until_a_dated_promotion_record",
    "owner_approved_privacy_threat_model_update_required_before_any_producer",
    "protected_pr_with_full_ci_required_for_any_change",
]

EXPECTED_LIMITATIONS = [
    "repository review and drift control only; no runtime authority",
    "cannot prove arbitrary code lacks a hidden sensor or covert collection path",
    "does not authorize endpoint collection, transport, or any runtime action",
    "does not prove event truth, maliciousness, attribution, or privacy safety",
    "does not constitute independent legal privacy or security certification",
    "does not inspect secrets, wallets, operator, or infrastructure material",
]

EXPECTED_CAPABILITIES = {
    "endpoint_producer_implemented": False,
    "endpoint_collection": False,
    "os_sensor": False,
    "event_truth_or_maliciousness_proven": False,
    "privacy_safety_proven": False,
    "ai_actor_or_intent_attribution_proven": False,
    "disclosure_authority": False,
    "proof_generation": False,
    "correlation": False,
    "warning": False,
    "transport": False,
    "response_authority": False,
    "automation": False,
    "production_authority": False,
}

EXPECTED_TOP_LEVEL_KEYS = {
    "schema_version",
    "issue",
    "as_of",
    "classification",
    "scope",
    "threat_actors",
    "abuse_cases",
    "protected_data_classes",
    "allowed_statement_fields",
    "prohibited_raw_data_classes",
    "required_privacy_rejection_cases",
    "trust_boundaries",
    "future_requirements",
    "current_state",
    "promotion_gates",
    "limitations",
    "capabilities",
}

EXPECTED_VALID_CASE_COUNT = 20
EXPECTED_INVALID_CASE_COUNT = 42
EXPECTED_DOMAIN_COUNT = 7
EXPECTED_SIGNAL_COUNT = 15
EXPECTED_MAX_CANONICAL_BYTES = 512

GH258_FALSE_FIELDS = (
    "real_time_endpoint_sensor",
    "response_engine",
    "resource_conscription_detection_implemented",
    "ai_or_actor_attribution_proven",
    "automatic_endpoint_actions_authorized",
    "automatic_process_termination_authorized",
    "automatic_quarantine_authorized",
    "automatic_firewall_mutation_authorized",
    "automatic_credential_rotation_authorized",
    "automatic_remote_commands_authorized",
    "automatic_deletion_authorized",
    "automatic_host_isolation_authorized",
    "production_authority",
)

GH264_FALSE_FIELDS = (
    "endpoint_collection",
    "os_sensor",
    "event_truth_or_maliciousness_proven",
    "privacy_safety_proven",
    "ai_actor_or_intent_attribution_proven",
    "correlation",
    "warning",
    "transport",
    "response_authority",
    "production_authority",
)

GH267_FALSE_FIELDS = (
    "endpoint_producer_implemented",
    "endpoint_collection",
    "runtime_collection_authorized",
    "privacy_safety_proven",
    "hidden_sensor_absence_proven",
    "transport",
    "response_authority",
    "production_authority",
)

ENDPOINT_FALSE_FIELDS = (
    "real_time_sensor_implemented",
    "response_engine_implemented",
    "resource_conscription_detection_implemented",
    "automatic_endpoint_actions_authorized",
    "automatic_process_termination_authorized",
    "automatic_quarantine_authorized",
    "automatic_firewall_mutation_authorized",
    "automatic_credential_rotation_authorized",
    "automatic_remote_commands_authorized",
    "automatic_deletion_authorized",
    "automatic_host_isolation_authorized",
    "runtime_collection_authorized",
    "hidden_sensor_absence_proven",
)


def load_json(path: Path) -> tuple[Any, str | None]:
    """Load one JSON file or return a stable error category."""
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None, "missing or unreadable"
    try:
        return json.loads(text), None
    except json.JSONDecodeError:
        return None, "malformed JSON"


def is_int(value: Any) -> bool:
    """Require a real JSON integer, rejecting booleans."""
    return type(value) is int


def parse_wire_object(wire: bytes) -> list[tuple[str, Any]] | None:
    """Parse a wire as a JSON object, preserving field order and duplicates."""
    try:
        pairs = json.loads(
            wire.decode("utf-8"), object_pairs_hook=lambda items: [("__pairs__", items)]
        )
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if (
        not isinstance(pairs, list)
        or len(pairs) != 1
        or not isinstance(pairs[0], tuple)
        or len(pairs[0]) != 2
        or pairs[0][0] != "__pairs__"
        or not isinstance(pairs[0][1], list)
    ):
        return None
    fields = pairs[0][1]
    if any(
        not isinstance(item, tuple) or len(item) != 2 or not isinstance(item[0], str)
        for item in fields
    ):
        return None
    return fields


def wire_fields(case: Any) -> tuple[list[tuple[str, Any]] | None, int]:
    """Decode one corpus case into ordered fields and a wire byte length."""
    if not isinstance(case, dict) or not isinstance(case.get("wire_hex"), str):
        return None, -1
    try:
        wire = bytes.fromhex(case["wire_hex"])
    except ValueError:
        return None, -1
    return parse_wire_object(wire), len(wire)


def validate_artifact(data: Any) -> list[str]:
    """Return stable category errors for the GH-267 threat-model artifact."""
    errors: list[str] = []
    if not isinstance(data, dict):
        return ["top-level value must be an object"]
    if set(data) != EXPECTED_TOP_LEVEL_KEYS:
        errors.append("top-level keys drifted")
    if not is_int(data.get("schema_version")) or data.get("schema_version") != (
        EXPECTED_SCHEMA_VERSION
    ):
        errors.append("schema version drifted")
    if not is_int(data.get("issue")) or data.get("issue") != EXPECTED_ISSUE:
        errors.append("issue identity drifted")
    if data.get("as_of") != EXPECTED_AS_OF or not isinstance(data.get("as_of"), str):
        errors.append("as_of drifted")
    if data.get("classification") != EXPECTED_CLASSIFICATION:
        errors.append("classification drifted")
    if data.get("scope") != EXPECTED_SCOPE:
        errors.append("scope drifted")
    if data.get("threat_actors") != EXPECTED_THREAT_ACTORS:
        errors.append("threat actors weakened or drifted")
    if data.get("abuse_cases") != EXPECTED_ABUSE_CASES:
        errors.append("abuse cases weakened or drifted")
    if data.get("protected_data_classes") != EXPECTED_PROTECTED_DATA_CLASSES:
        errors.append("protected data classes weakened or drifted")
    if data.get("allowed_statement_fields") != ALLOWED_STATEMENT_FIELDS:
        errors.append("allowed statement fields drifted")
    if data.get("prohibited_raw_data_classes") != EXPECTED_PROHIBITED_RAW_DATA_CLASSES:
        errors.append("prohibited raw data classes weakened or drifted")
    if data.get("required_privacy_rejection_cases") != EXPECTED_PRIVACY_REJECTION_CASES:
        errors.append("privacy rejection cases drifted")
    if data.get("trust_boundaries") != EXPECTED_TRUST_BOUNDARIES:
        errors.append("trust boundaries weakened or drifted")
    if data.get("future_requirements") != EXPECTED_FUTURE_REQUIREMENTS:
        errors.append("future requirements weakened or drifted")
    if data.get("current_state") != EXPECTED_CURRENT_STATE:
        errors.append("current state weakened or drifted")
    if data.get("promotion_gates") != EXPECTED_PROMOTION_GATES:
        errors.append("promotion gates weakened or drifted")
    if data.get("limitations") != EXPECTED_LIMITATIONS:
        errors.append("limitations weakened or drifted")
    capabilities = data.get("capabilities")
    if not isinstance(capabilities, dict) or set(capabilities) != set(
        EXPECTED_CAPABILITIES
    ):
        errors.append("capabilities drifted")
    elif any(capabilities[name] is not False for name in EXPECTED_CAPABILITIES):
        errors.append("capabilities must all remain false")
    return errors


def validate_status(data: Any) -> list[str]:
    """Confirm GH-258/GH-264/endpoint status stays non-collecting/non-actioning."""
    errors: list[str] = []
    if not isinstance(data, dict):
        return ["top-level value must be an object"]
    updates = data.get("post_audit_updates")
    if not isinstance(updates, dict):
        return ["post-audit updates missing or invalid"]
    gh_258 = updates.get("gh_258")
    gh_264 = updates.get("gh_264")
    gh_267 = updates.get("gh_267")
    classifications = data.get("classifications")
    endpoint = (
        classifications.get("endpoint_detection_and_response")
        if isinstance(classifications, dict)
        else None
    )
    if not isinstance(gh_258, dict):
        errors.append("GH-258 status record missing or invalid")
    else:
        if (
            gh_258.get("status") != "planned_documentation_only"
            or gh_258.get("classification")
            != "behavior_based_endpoint_detection_and_safe_response_target"
        ):
            errors.append("GH-258 must remain planned documentation only")
        if any(gh_258.get(field) is not False for field in GH258_FALSE_FIELDS):
            errors.append("GH-258 must remain non-collecting and non-actioning")
    if not isinstance(gh_264, dict):
        errors.append("GH-264 status record missing or invalid")
    else:
        if (
            gh_264.get("status")
            != "repository_candidate_implemented_and_locally_tested"
            or gh_264.get("classification")
            != "canonical_observe_only_endpoint_statement"
            or not is_int(gh_264.get("schema_version"))
            or gh_264.get("schema_version") != 1
        ):
            errors.append("GH-264 must remain an observe-only schema candidate")
        if any(gh_264.get(field) is not False for field in GH264_FALSE_FIELDS):
            errors.append("GH-264 must remain non-collecting and non-actioning")
        if not is_int(gh_264.get("closed_domains")):
            errors.append("GH-264 closed domain count missing or invalid")
        elif gh_264.get("closed_domains") != EXPECTED_DOMAIN_COUNT:
            errors.append("GH-264 closed domain count drifted")
        if not is_int(gh_264.get("closed_signals")):
            errors.append("GH-264 closed signal count missing or invalid")
        elif gh_264.get("closed_signals") != EXPECTED_SIGNAL_COUNT:
            errors.append("GH-264 closed signal count drifted")
        if not is_int(gh_264.get("max_canonical_bytes")):
            errors.append("GH-264 maximum wire size missing or invalid")
        elif gh_264.get("max_canonical_bytes") != EXPECTED_MAX_CANONICAL_BYTES:
            errors.append("GH-264 maximum wire size drifted")
    if not isinstance(gh_267, dict):
        errors.append("GH-267 status record missing or invalid")
    else:
        if (
            gh_267.get("as_of") != EXPECTED_AS_OF
            or gh_267.get("issue") != EXPECTED_ISSUE
            or gh_267.get("status")
            != "repository_candidate_implemented_and_locally_tested"
            or gh_267.get("classification") != EXPECTED_CLASSIFICATION
            or gh_267.get("artifact") != str(ARTIFACT_PATH)
            or gh_267.get("security_ci_enforced") is not True
        ):
            errors.append("GH-267 repository privacy gate identity drifted")
        if any(gh_267.get(field) is not False for field in GH267_FALSE_FIELDS):
            errors.append("GH-267 capabilities must remain false")
    if not isinstance(endpoint, dict):
        errors.append("endpoint classification record missing or invalid")
    else:
        if (
            endpoint.get("status") != "observe_only_schema_candidate_no_sensor"
            or endpoint.get("endpoint_collection") != "not_implemented"
            or endpoint.get("canonical_observation_statement")
            != "implemented_and_locally_tested"
            or endpoint.get("pre_producer_privacy_gate")
            != "repository_candidate_implemented_and_locally_tested"
        ):
            errors.append("endpoint classification must remain observe-only")
        if any(endpoint.get(field) is not False for field in ENDPOINT_FALSE_FIELDS):
            errors.append("endpoint classification must remain non-actioning")
    return errors


def validate_vectors(data: Any, status: Any) -> list[str]:
    """Cross-check the shared corpus against the declared GH-264 boundary."""
    errors: list[str] = []
    if not isinstance(data, dict):
        return ["top-level value must be an object"]
    if not is_int(data.get("vector_schema_version")) or (
        data.get("vector_schema_version") != 1
    ):
        errors.append("vector schema version drifted")
    valid_cases = data.get("valid_cases")
    invalid_cases = data.get("invalid_cases")
    if not isinstance(valid_cases, list):
        return ["valid corpus missing or invalid"]
    if not isinstance(invalid_cases, list):
        return ["invalid corpus missing or invalid"]
    if len(valid_cases) != EXPECTED_VALID_CASE_COUNT:
        errors.append("valid corpus count drifted")
    if len(invalid_cases) != EXPECTED_INVALID_CASE_COUNT:
        errors.append("invalid corpus count drifted")

    status_max_bytes: int | None = None
    status_domains: int | None = None
    status_signals: int | None = None
    if isinstance(status, dict):
        gh_264 = status.get("post_audit_updates", {})
        if isinstance(gh_264, dict):
            gh_264 = gh_264.get("gh_264", {})
        if isinstance(gh_264, dict):
            if is_int(gh_264.get("max_canonical_bytes")):
                status_max_bytes = gh_264["max_canonical_bytes"]
            if is_int(gh_264.get("closed_domains")):
                status_domains = gh_264["closed_domains"]
            if is_int(gh_264.get("closed_signals")):
                status_signals = gh_264["closed_signals"]

    domains: set[str] = set()
    signals: set[str] = set()
    max_wire_bytes = 0
    allowed_keys = list(ALLOWED_STATEMENT_FIELDS)
    for case in valid_cases:
        fields, wire_length = wire_fields(case)
        if fields is None:
            errors.append("valid wire malformed")
            continue
        keys = [name for name, _ in fields]
        if keys != allowed_keys:
            errors.append("valid wire fields drifted")
            continue
        max_wire_bytes = max(max_wire_bytes, wire_length)
        values = dict(fields)
        if isinstance(values.get("domain"), str):
            domains.add(values["domain"])
        if isinstance(values.get("signal"), str):
            signals.add(values["signal"])
    if status_domains is not None and len(domains) != status_domains:
        errors.append("derived domains diverge from status")
    if status_signals is not None and len(signals) != status_signals:
        errors.append("derived signals diverge from status")
    if status_max_bytes is not None and max_wire_bytes > status_max_bytes:
        errors.append("wire size exceeds status maximum")

    invalid_by_name: dict[str, Any] = {}
    for case in invalid_cases:
        if isinstance(case, dict) and isinstance(case.get("name"), str):
            invalid_by_name[case["name"]] = case
    for expected in EXPECTED_PRIVACY_REJECTION_CASES:
        case = invalid_by_name.get(expected["vector"])
        if case is None:
            errors.append("privacy rejection case missing")
            continue
        fields, _ = wire_fields(case)
        if fields is None:
            errors.append("privacy rejection case malformed")
            continue
        keys = [name for name, _ in fields]
        extra = [name for name in keys if name not in ALLOWED_STATEMENT_FIELDS]
        if (
            len(keys) != len(ALLOWED_STATEMENT_FIELDS) + 1
            or len(keys) != len(set(keys))
            or extra != [expected["forbidden_wire_key"]]
        ):
            errors.append("privacy rejection case fields drifted")
    return errors


def verify(root: Path) -> list[str]:
    """Verify the GH-267 artifact, public status, and shared corpus."""
    errors: list[str] = []
    artifact, artifact_error = load_json(root / ARTIFACT_PATH)
    if artifact_error is not None:
        errors.append(f"{ARTIFACT_PATH}: {artifact_error}")
    else:
        errors.extend(
            f"{ARTIFACT_PATH}: {item}" for item in validate_artifact(artifact)
        )
    status, status_error = load_json(root / STATUS_PATH)
    if status_error is not None:
        errors.append(f"{STATUS_PATH}: {status_error}")
    else:
        errors.extend(f"{STATUS_PATH}: {item}" for item in validate_status(status))
    vectors, vectors_error = load_json(root / VECTORS_PATH)
    if vectors_error is not None:
        errors.append(f"{VECTORS_PATH}: {vectors_error}")
    else:
        errors.extend(
            f"{VECTORS_PATH}: {item}" for item in validate_vectors(vectors, status)
        )
    return errors


def main() -> int:
    """Run the gate against the repository root."""
    root = Path(__file__).resolve().parents[1]
    errors = verify(root)
    if errors:
        for error in errors:
            print(f"ERROR: {error}")
        return 1
    print("GH-267 endpoint producer privacy gate: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())

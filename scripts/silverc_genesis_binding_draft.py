#!/usr/bin/env python3
"""D5 genesis/instance binding: non-executable draft validator (design block).

Validates a versioned draft binding document that ties network, release
bundle, contract role, constructor authority key, genesis funding outpoint and
covenant ID to verifiable evidence. It has no CLI, writes nothing, exports no
deployment material and never upgrades a v2-draft bundle to a deployable state.

Covenant IDs are hashes of the funding outpoint plus the authorized genesis
output (value, script); see docs/architecture/d5-genesis-binding-design.md.
This module does not recompute them (no new crypto): every result stays
blocked on recomputation with the existing kaspa_consensus_core helper.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from hashlib import sha256
from typing import Any

from silverc_bundles import Bundle

SCHEMA = "prometheus.silverc.genesis-binding"
SCHEMA_VERSION = "1-draft"
ALLOWED_NETWORKS = ("testnet-10",)
# D5 evidence candidates are produced by the Rust deployer
# (`observe --d5-evidence-candidate-out`); these constants mirror lib.rs and
# are pinned against the cross-language fixture in the tests.
CANDIDATE_KIND = "prometheus.silverc.d5.genesis_evidence_candidate"
CANDIDATE_SCHEMA_VERSION = 1
CANDIDATE_STATUS = "OBSERVED_NOT_INDEPENDENTLY_CONFIRMED"
CANDIDATE_CLASSIFICATION = [
    "NOT_CHAIN_PROOF",
    "NOT_D5_ACCEPTANCE",
    "NOT_DEPLOYMENT_AUTHORIZATION",
]
CANDIDATE_TRUST_SOURCE = "single_operator_configured_node"
CANDIDATE_SNAPSHOT_SOURCE = "configured_node_get_utxos_by_addresses_typed_entry"
CANDIDATE_PREPARATION_SOURCE = "validated_preparation_inputs_not_chain_proof"
CANDIDATE_SNAPSHOT_NOTE = (
    "normalized allowlisted snapshot of the typed UTXO entry, not the complete raw "
    "wire response; its hash proves integrity and internal consistency only, not "
    "provider provenance, network identity, or consensus"
)
CANDIDATE_MISSING_CHECKS = [
    "second independently operated node or explorer",
    "reviewer-captured response independent of the operator",
    "block hash and header cross-check for the genesis DAA score",
    "network identity independent of the configured endpoint",
]
CANDIDATE_RELATIONSHIPS = [
    "preparation.calculated_covenant_id == covenant_id(preparation.funding_outpoint, "
    "[(preparation.contract_output_index, preparation.genesis_output_value, "
    "preparation.contract_script_public_key)])",
    "observed.outpoint == (preparation.expected_deploy_tx_id, preparation.contract_output_index)",
    "observed.amount == preparation.genesis_output_value",
    "observed.script_public_key == preparation.contract_script_public_key",
    "observed.covenant_id == preparation.calculated_covenant_id",
    "observed.is_coinbase == false",
    "observed_snapshot_sha256 == sha256(canonical_json(observed))",
]
CONTRACT_OUTPUT_INDEX = 0

STATUS_PLAN_NOT_EXECUTABLE = "D5_PLAN_CONSISTENT_NOT_EXECUTABLE"
STATUS_PLAN_PENDING_RECOMPUTE = "D5_PLAN_CONSISTENT_COVENANT_ID_RECOMPUTE_BLOCKED"
STATUS_BLOCKED_EVIDENCE = "D5_BLOCKED_MISSING_GENESIS_EVIDENCE"
STATUS_EVIDENCE_PENDING_RECOMPUTE = (
    "D5_EVIDENCE_CONSISTENT_COVENANT_ID_RECOMPUTE_BLOCKED"
)
TRUST_BLOCKER = (
    "evidence candidates are OBSERVED_NOT_INDEPENDENTLY_CONFIRMED (single configured "
    "node); acceptance requires the D5 trusted-source model and independent confirmation"
)
RECOMPUTE_BLOCKER = (
    "predicted covenant ids are not recomputed: requires the existing "
    "kaspa_consensus_core covenant_id helper (deployer calculate-covenant-id); "
    "this draft does not call it, and evidence acceptance needs a trusted-source model"
)


@dataclass(frozen=True)
class Role:
    contract_name: str
    key_kind: str
    key_param: str
    key_arg_index: int


# Closed role table for the six state contracts. ValidatorStakingH001 is the
# frozen canary and is not part of a v2 binding.
ROLES: dict[str, Role] = {
    "validator_staking": Role(
        "ValidatorStakingState", "validator", "init_validator_pk", 0
    ),
    "guardian_reputation": Role(
        "GuardianReputationState", "governance", "init_governance_pk", 1
    ),
    "rule_storage": Role("RuleStorageState", "governance", "init_governance_pk", 0),
    "community_donations": Role(
        "CommunityDonationsState", "governance", "init_governance_pk", 0
    ),
    "dev_incentive_pool": Role(
        "DevIncentivePoolState", "governance", "init_governance_pk", 0
    ),
    "governance_auto_tuning": Role(
        "GovernanceAutoTuningState", "metrics_oracle", "init_metrics_oracle_pk", 0
    ),
}

HEX32 = re.compile(r"^[0-9a-f]{64}$")
OUTPOINT = re.compile(r"^([0-9a-f]{64}):(0|[1-9][0-9]{0,9})$")
PLAN_KEYS = {
    "schema",
    "schema_version",
    "network_id",
    "release",
    "authority_keys",
    "contracts",
    "deployment_order",
}
RELEASE_KEYS = {"bundle_id", "bundle_manifest_sha256", "silverscript_commit"}
ENTRY_KEYS = {
    "role",
    "contract_name",
    "script_sha256",
    "constructor_args_sha256",
    "authority_key",
    "genesis_value_sompi",
    "funding_outpoint",
    "trusted_roles",
    "predicted_covenant_id",
}
CANDIDATE_KEYS = {
    "schema_version",
    "kind",
    "status",
    "classification",
    "trust_model",
    "preparation",
    "observed",
    "observed_snapshot_sha256",
    "observed_virtual_daa_score",
    "daa_depth",
    "relationships",
    "candidate_sha256",
}
TRUST_KEYS = {
    "source",
    "independent_confirmation",
    "snapshot_note",
    "missing_independent_checks",
}
PREPARATION_KEYS = {
    "source",
    "network_id",
    "contract_name",
    "request_sha256",
    "signing_request_sha256",
    "funding_outpoint",
    "genesis_output_value",
    "contract_output_index",
    "contract_script_public_key",
    "calculated_covenant_id",
    "expected_deploy_tx_id",
}
OBSERVED_KEYS = {
    "source",
    "outpoint",
    "amount",
    "script_public_key",
    "covenant_id",
    "block_daa_score",
    "is_coinbase",
}
OUTPOINT_KEYS = {"transaction_id", "index"}
SCRIPT_KEYS = {"version", "script_hex"}


class BindingError(ValueError):
    """Rejection with a stable code for the validation matrix."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def canonical_sha256(value: Any) -> str:
    return sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise BindingError(code, message)


def _exact_keys(value: Any, keys: set[str], code: str, label: str) -> dict[str, Any]:
    _require(isinstance(value, dict), code, f"{label}: expected object")
    _require(set(value) == keys, code, f"{label}: unexpected or missing fields")
    checked: dict[str, Any] = value
    return checked


def constructor_key_hex(bundle: Bundle, contract_name: str, index: int) -> str:
    for fixture in bundle.fixtures:
        if fixture.contract_name == contract_name:
            arg = fixture.args[index]
            data = arg.get("data") if isinstance(arg, dict) else None
            if (
                arg.get("kind") != "array"
                or not isinstance(data, list)
                or len(data) != 32
            ):
                raise BindingError(
                    "KEY_ARG",
                    f"{contract_name}: constructor arg {index} is not a 32-byte key",
                )
            return bytes(int(item["data"]) for item in data).hex()
    raise BindingError(
        "ROLE_CONTRACT", f"{contract_name}: not in bundle {bundle.bundle_id}"
    )


def _check_acyclic(entries: dict[str, dict[str, Any]], order: list[str]) -> None:
    for role, entry in entries.items():
        trusted = entry["trusted_roles"]
        _require(
            isinstance(trusted, list),
            "TRUST_GRAPH",
            f"{role}: trusted_roles must be a list",
        )
        _require(
            len(set(trusted)) == len(trusted),
            "TRUST_GRAPH",
            f"{role}: duplicate trusted role",
        )
        for other in trusted:
            _require(other in entries, "TRUST_GRAPH", f"{role}: unknown trusted role")
            _require(other != role, "CIRCULAR_DEPENDENCY", f"{role}: trusts itself")
    state = dict.fromkeys(entries, 0)

    def visit(role: str) -> None:
        state[role] = 1
        for other in entries[role]["trusted_roles"]:
            _require(
                state[other] != 1,
                "CIRCULAR_DEPENDENCY",
                f"cycle through {role} and {other}",
            )
            if state[other] == 0:
                visit(other)
        state[role] = 2

    for role in sorted(entries):
        if state[role] == 0:
            visit(role)
    _require(
        sorted(order) == sorted(entries),
        "DEPLOYMENT_ORDER",
        "deployment_order must list every role once",
    )
    position = {role: index for index, role in enumerate(order)}
    for role, entry in entries.items():
        for other in entry["trusted_roles"]:
            _require(
                position[other] < position[role],
                "DEPLOYMENT_ORDER",
                f"{role} must be deployed after the trusted role {other}",
            )


def _validate_plan(
    plan: dict[str, Any], bundle: Bundle, compiled: dict[str, dict[str, Any]]
) -> dict[str, dict[str, Any]]:
    _exact_keys(plan, PLAN_KEYS, "SHAPE", "plan")
    _require(
        plan["schema"] == SCHEMA and plan["schema_version"] == SCHEMA_VERSION,
        "SCHEMA",
        "unsupported schema",
    )
    _require(
        plan["network_id"] in ALLOWED_NETWORKS,
        "NETWORK",
        "network not allowed for a draft binding",
    )

    release = _exact_keys(plan["release"], RELEASE_KEYS, "SHAPE", "release")
    _require(
        release["bundle_id"] == bundle.bundle_id,
        "BUNDLE",
        "release bundle id does not match the selected bundle",
    )
    _require(
        release["bundle_manifest_sha256"] == bundle.manifest_sha256,
        "BUNDLE",
        "release manifest hash does not match the hardcoded bundle pin",
    )
    _require(
        isinstance(release["silverscript_commit"], str),
        "SHAPE",
        "release: silverscript_commit",
    )

    keys = plan["authority_keys"]
    _require(
        isinstance(keys, dict) and bool(keys),
        "SHAPE",
        "authority_keys: expected non-empty object",
    )
    for name, key in keys.items():
        _exact_keys(key, {"kind", "xonly_pubkey"}, "SHAPE", f"authority_keys.{name}")
        _require(
            isinstance(key["xonly_pubkey"], str)
            and HEX32.fullmatch(key["xonly_pubkey"]) is not None,
            "KEY_FORMAT",
            f"authority_keys.{name}: expected 32-byte lowercase hex",
        )

    contracts = plan["contracts"]
    _require(isinstance(contracts, list), "SHAPE", "contracts: expected list")
    entries: dict[str, dict[str, Any]] = {}
    for raw in contracts:
        entry = _exact_keys(raw, ENTRY_KEYS, "SHAPE", "contract entry")
        role = entry["role"]
        _require(role in ROLES, "ROLE_UNKNOWN", "unknown contract role")
        _require(role not in entries, "DUPLICATE_ROLE", f"{role}: listed twice")
        entries[role] = entry
    _require(
        set(entries) == set(ROLES),
        "ROLE_SET",
        "binding must cover every state-contract role exactly once",
    )

    used_keys: set[str] = set()
    for role, entry in entries.items():
        spec = ROLES[role]
        _require(
            entry["contract_name"] == spec.contract_name,
            "ROLE_CONTRACT",
            f"{role}: contract substitution",
        )
        reference = compiled.get(spec.contract_name)
        _require(
            reference is not None,
            "ROLE_CONTRACT",
            f"{role}: contract missing from compiled release",
        )
        assert reference is not None
        for field in ("script_sha256", "constructor_args_sha256"):
            _require(
                entry[field] == reference[field],
                "COMPILED_IDENTITY",
                f"{role}: {field} differs from release",
            )
        key_name = entry["authority_key"]
        _require(key_name in keys, "KEY_UNKNOWN", f"{role}: unknown authority key")
        key = keys[key_name]
        _require(
            key["kind"] == spec.key_kind,
            "KEY_KIND",
            f"{role}: authority key kind must be {spec.key_kind}",
        )
        _require(
            key["xonly_pubkey"]
            == constructor_key_hex(bundle, spec.contract_name, spec.key_arg_index),
            "KEY_CONSTRUCTOR",
            f"{role}: authority key is not the {spec.key_param} constructor argument",
        )
        used_keys.add(key_name)
        value = entry["genesis_value_sompi"]
        _require(
            isinstance(value, int) and not isinstance(value, bool) and value > 0,
            "GENESIS_VALUE",
            role,
        )
        match = OUTPOINT.fullmatch(str(entry["funding_outpoint"]))
        _require(
            match is not None and int(match.group(2)) <= 0xFFFFFFFF,
            "OUTPOINT",
            f"{role}: funding outpoint",
        )
        _require(
            isinstance(entry["predicted_covenant_id"], str)
            and HEX32.fullmatch(entry["predicted_covenant_id"]) is not None,
            "COVENANT_ID",
            role,
        )
    _require(
        used_keys == set(keys), "KEY_UNUSED", "authority_keys lists a key no role uses"
    )

    outpoints = [entry["funding_outpoint"] for entry in entries.values()]
    _require(
        len(set(outpoints)) == len(outpoints),
        "DUPLICATE_OUTPOINT",
        "funding outpoints must be unique",
    )
    covenant_ids = [entry["predicted_covenant_id"] for entry in entries.values()]
    _require(
        len(set(covenant_ids)) == len(covenant_ids),
        "DUPLICATE_COVENANT_ID",
        "covenant ids must be unique",
    )

    order = plan["deployment_order"]
    _require(
        isinstance(order, list), "DEPLOYMENT_ORDER", "deployment_order: expected list"
    )
    _check_acyclic(entries, order)
    return entries


def _uint(value: Any, code: str, label: str, maximum: int = 2**64 - 1) -> int:
    _require(
        isinstance(value, int)
        and not isinstance(value, bool)
        and 0 <= value <= maximum,
        code,
        f"{label}: expected unsigned integer",
    )
    return int(value)


def _hex32(value: Any, code: str, label: str) -> str:
    _require(isinstance(value, str) and HEX32.fullmatch(value) is not None, code, label)
    return str(value)


def _outpoint(value: Any, label: str) -> str:
    item = _exact_keys(value, OUTPOINT_KEYS, "SHAPE", label)
    txid = _hex32(item["transaction_id"], "EVIDENCE_ANCHOR", f"{label}: transaction id")
    index = _uint(item["index"], "EVIDENCE_ANCHOR", f"{label}: index", 0xFFFFFFFF)
    return f"{txid}:{index}"


def _script(value: Any, label: str) -> dict[str, Any]:
    item = _exact_keys(value, SCRIPT_KEYS, "SHAPE", label)
    _uint(item["version"], "SHAPE", f"{label}: version", 0xFFFF)
    _require(
        isinstance(item["script_hex"], str)
        and re.fullmatch(r"(?:[0-9a-f]{2})+", item["script_hex"]) is not None,
        "SHAPE",
        f"{label}: script_hex",
    )
    return item


def verify_candidate_document(
    candidate: Any, label: str = "candidate"
) -> dict[str, Any]:
    """Structural, constant, hash and relationship checks of one Rust candidate.

    This is internal consistency only; plan/context binding is separate.
    """
    item = _exact_keys(candidate, CANDIDATE_KEYS, "SHAPE", label)
    _require(
        item["schema_version"] == CANDIDATE_SCHEMA_VERSION
        and item["kind"] == CANDIDATE_KIND
        and item["status"] == CANDIDATE_STATUS
        and item["classification"] == CANDIDATE_CLASSIFICATION
        and item["relationships"] == CANDIDATE_RELATIONSHIPS,
        "CANDIDATE_SCHEMA",
        f"{label}: unsupported schema, status, classification or relationships",
    )
    trust = _exact_keys(
        item["trust_model"], TRUST_KEYS, "SHAPE", f"{label}.trust_model"
    )
    _require(
        trust["source"] == CANDIDATE_TRUST_SOURCE
        and trust["independent_confirmation"] is False
        and trust["snapshot_note"] == CANDIDATE_SNAPSHOT_NOTE
        and trust["missing_independent_checks"] == CANDIDATE_MISSING_CHECKS,
        "CANDIDATE_TRUST",
        f"{label}: trust model must stay single-source and unconfirmed",
    )
    prep = _exact_keys(
        item["preparation"], PREPARATION_KEYS, "SHAPE", f"{label}.preparation"
    )
    obs = _exact_keys(item["observed"], OBSERVED_KEYS, "SHAPE", f"{label}.observed")
    _require(
        prep["source"] == CANDIDATE_PREPARATION_SOURCE
        and obs["source"] == CANDIDATE_SNAPSHOT_SOURCE,
        "CANDIDATE_SOURCE",
        f"{label}: field sources are not the documented sources",
    )
    for field in (
        "request_sha256",
        "signing_request_sha256",
        "calculated_covenant_id",
        "expected_deploy_tx_id",
    ):
        _hex32(prep[field], "SHAPE", f"{label}.preparation.{field}")
    _hex32(obs["covenant_id"], "SHAPE", f"{label}.observed.covenant_id")
    _hex32(
        item["observed_snapshot_sha256"], "SHAPE", f"{label}: observed_snapshot_sha256"
    )
    _hex32(item["candidate_sha256"], "SHAPE", f"{label}: candidate_sha256")
    _require(isinstance(prep["network_id"], str), "SHAPE", f"{label}: network_id")
    _require(isinstance(prep["contract_name"], str), "SHAPE", f"{label}: contract_name")
    value = _uint(
        prep["genesis_output_value"], "SHAPE", f"{label}: genesis_output_value"
    )
    _require(value > 0, "GENESIS_VALUE", f"{label}: genesis value must be nonzero")
    index = _uint(
        prep["contract_output_index"], "SHAPE", f"{label}: output index", 0xFFFFFFFF
    )
    _require(
        index == CONTRACT_OUTPUT_INDEX,
        "EVIDENCE_ANCHOR",
        f"{label}: fixed genesis output index",
    )
    funding = _outpoint(
        prep["funding_outpoint"], f"{label}.preparation.funding_outpoint"
    )
    prep_script = _script(
        prep["contract_script_public_key"], f"{label}.preparation.script"
    )
    observed_outpoint = _outpoint(obs["outpoint"], f"{label}.observed.outpoint")
    obs_script = _script(obs["script_public_key"], f"{label}.observed.script")
    amount = _uint(obs["amount"], "SHAPE", f"{label}.observed.amount")
    block = _uint(obs["block_daa_score"], "SHAPE", f"{label}.observed.block_daa_score")
    virtual = _uint(
        item["observed_virtual_daa_score"], "SHAPE", f"{label}: virtual DAA score"
    )
    depth = _uint(item["daa_depth"], "SHAPE", f"{label}: daa_depth")
    _require(isinstance(obs["is_coinbase"], bool), "SHAPE", f"{label}: is_coinbase")

    _require(
        observed_outpoint == f"{prep['expected_deploy_tx_id']}:{CONTRACT_OUTPUT_INDEX}",
        "EVIDENCE_ANCHOR",
        f"{label}: observed outpoint is not the expected genesis outpoint",
    )
    _require(
        prep["expected_deploy_tx_id"] != funding.split(":")[0],
        "EVIDENCE_ANCHOR",
        f"{label}: genesis transaction must spend, not equal, the funding outpoint",
    )
    _require(
        amount == value, "EVIDENCE_INCONSISTENT", f"{label}: observed value differs"
    )
    _require(
        obs_script == prep_script,
        "EVIDENCE_INCONSISTENT",
        f"{label}: observed script differs",
    )
    _require(
        obs["covenant_id"] == prep["calculated_covenant_id"],
        "COVENANT_MISMATCH",
        f"{label}: observed covenant id differs from the calculated id",
    )
    _require(
        obs["is_coinbase"] is False, "EVIDENCE_ANCHOR", f"{label}: coinbase output"
    )
    _require(
        block <= virtual,
        "EVIDENCE_ANCHOR",
        f"{label}: genesis DAA score above virtual DAA score",
    )
    _require(depth == virtual - block, "EVIDENCE_INCONSISTENT", f"{label}: DAA depth")
    _require(
        canonical_sha256(obs) == item["observed_snapshot_sha256"],
        "EVIDENCE_HASH",
        f"{label}: observed snapshot hash",
    )
    unhashed = {key: val for key, val in item.items() if key != "candidate_sha256"}
    _require(
        canonical_sha256(unhashed) == item["candidate_sha256"],
        "EVIDENCE_HASH",
        f"{label}: candidate hash",
    )
    return item


def _bind_candidate(
    entry: dict[str, Any], candidate: Any, network: str, role: str
) -> None:
    """Bind a candidate to its reviewed plan entry (context binding)."""
    item = verify_candidate_document(candidate, f"evidence.{role}")
    prep = item["preparation"]
    _require(
        prep["network_id"] == network,
        "EVIDENCE_NETWORK",
        f"{role}: evidence from another network",
    )
    _require(
        prep["contract_name"] == ROLES[role].contract_name,
        "ROLE_CONTRACT",
        f"{role}: candidate for another contract",
    )
    funding = f"{prep['funding_outpoint']['transaction_id']}:{prep['funding_outpoint']['index']}"
    _require(
        funding == entry["funding_outpoint"],
        "EVIDENCE_CONTEXT",
        f"{role}: funding outpoint differs from plan",
    )
    _require(
        prep["genesis_output_value"] == entry["genesis_value_sompi"],
        "EVIDENCE_CONTEXT",
        f"{role}: genesis value differs from plan",
    )
    _require(
        prep["calculated_covenant_id"] == entry["predicted_covenant_id"],
        "COVENANT_MISMATCH",
        f"{role}: calculated covenant id differs from the planned id",
    )


def validate_genesis_binding(
    document: Any,
    *,
    expected_plan_sha256: str,
    bundle: Bundle,
    compiled: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """Validate a draft binding in a fixed order; raise BindingError on rejection.

    ``expected_plan_sha256`` is the reviewed pin supplied out of band; the
    document never carries its own trusted hash. ``compiled`` maps contract
    names to entries of the already validated release manifest.
    """
    _require(
        isinstance(document, dict)
        and set(document) in ({"plan"}, {"plan", "evidence"}),
        "SHAPE",
        "document must contain plan and optional evidence",
    )
    plan = document["plan"]
    plan_sha256 = canonical_sha256(plan)
    _require(
        plan_sha256 == expected_plan_sha256,
        "PLAN_PIN",
        "plan does not match the reviewed plan hash",
    )
    entries = _validate_plan(plan, bundle, compiled)
    shared = (
        len(
            {
                entries[r]["authority_key"]
                for r in entries
                if ROLES[r].key_kind == "governance"
            }
        )
        == 1
    )
    result: dict[str, Any] = {
        "plan_sha256": plan_sha256,
        "bundle_id": bundle.bundle_id,
        "network_id": plan["network_id"],
        "shared_governance_key": shared,
        "executable": False,
        "independently_confirmed": False,
        "blockers": [RECOMPUTE_BLOCKER],
    }
    if "evidence" not in document:
        result["status"] = (
            STATUS_PLAN_PENDING_RECOMPUTE
            if bundle.promotable
            else STATUS_PLAN_NOT_EXECUTABLE
        )
        if not bundle.promotable:
            result["blockers"].append(
                f"bundle {bundle.bundle_id} is a non-promotable draft"
            )
        return result

    _require(
        bundle.promotable,
        "NON_PROMOTABLE",
        f"bundle {bundle.bundle_id} is a non-promotable draft; deployment identity is refused",
    )
    evidence = document["evidence"]
    _require(
        isinstance(evidence, dict), "SHAPE", "evidence: expected object keyed by role"
    )
    _require(
        set(evidence) <= set(entries), "ROLE_UNKNOWN", "evidence for an unknown role"
    )
    missing = sorted(set(entries) - set(evidence))
    for role in sorted(evidence):
        _bind_candidate(entries[role], evidence[role], plan["network_id"], role)
    observed_ids = [evidence[role]["observed"]["covenant_id"] for role in evidence]
    result["blockers"].append(TRUST_BLOCKER)
    _require(
        len(set(observed_ids)) == len(observed_ids),
        "DUPLICATE_COVENANT_ID",
        "evidence reuses a covenant id",
    )
    if missing:
        result["status"] = STATUS_BLOCKED_EVIDENCE
        result["blockers"].append(
            "missing public genesis evidence for: " + ", ".join(missing)
        )
        return result
    result["status"] = STATUS_EVIDENCE_PENDING_RECOMPUTE
    result["covenant_ids"] = {
        role: entries[role]["predicted_covenant_id"] for role in sorted(entries)
    }
    return result


def accept_state(result: dict[str, Any], observed: dict[str, Any]) -> str:
    """Off-chain acceptance: map an observed state to its role or reject it.

    Only a result with complete, consistent and independently confirmed
    evidence can accept a state. This draft never sets
    ``independently_confirmed``, so every real result is refused until the
    trusted-source model exists. A covenant id that is not in the binding
    (lookalike) is rejected.
    """
    _require(
        result.get("status") == STATUS_EVIDENCE_PENDING_RECOMPUTE
        and result.get("independently_confirmed") is True,
        "NOT_CONFIRMED",
        "no independently confirmed deployment identity to accept states against",
    )
    _require(
        observed.get("network_id") == result["network_id"],
        "EVIDENCE_NETWORK",
        "state from another network",
    )
    roles = [
        role
        for role, cid in result["covenant_ids"].items()
        if cid == observed.get("covenant_id")
    ]
    _require(
        len(roles) == 1,
        "LOOKALIKE",
        "covenant id is not bound by the deployment identity",
    )
    claimed = observed.get("role")
    _require(
        claimed in (None, roles[0]),
        "ROLE_SUBSTITUTION",
        "state claims a different role",
    )
    return str(roles[0])

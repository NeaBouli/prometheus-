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
PUBLIC_EVIDENCE_KINDS = ("public_node_utxo", "public_explorer_utxo")
MIN_CONFIRMATIONS = 10

STATUS_PLAN_NOT_EXECUTABLE = "D5_PLAN_CONSISTENT_NOT_EXECUTABLE"
STATUS_PLAN_PENDING_RECOMPUTE = "D5_PLAN_CONSISTENT_COVENANT_ID_RECOMPUTE_BLOCKED"
STATUS_BLOCKED_EVIDENCE = "D5_BLOCKED_MISSING_GENESIS_EVIDENCE"
STATUS_EVIDENCE_PENDING_RECOMPUTE = (
    "D5_EVIDENCE_CONSISTENT_COVENANT_ID_RECOMPUTE_BLOCKED"
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
EVIDENCE_KEYS = {
    "source_kind",
    "network_id",
    "deploy_tx_id",
    "deployed_instance_id",
    "covenant_id",
    "amount_sompi",
    "block_hash",
    "block_daa_score",
    "confirmations",
    "raw_response",
    "raw_response_sha256",
}


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


def _validate_evidence(
    entry: dict[str, Any], evidence: Any, network: str, role: str
) -> None:
    item = _exact_keys(evidence, EVIDENCE_KEYS, "SHAPE", f"evidence.{role}")
    _require(
        item["source_kind"] in PUBLIC_EVIDENCE_KINDS,
        "EVIDENCE_SOURCE",
        f"{role}: operator records or claims are not chain evidence",
    )
    _require(
        item["network_id"] == network,
        "EVIDENCE_NETWORK",
        f"{role}: evidence from another network",
    )
    raw = item["raw_response"]
    _require(
        isinstance(raw, dict),
        "EVIDENCE_RAW",
        f"{role}: raw_response must be the stored node response",
    )
    _require(
        canonical_sha256(raw) == item["raw_response_sha256"],
        "EVIDENCE_RAW",
        f"{role}: raw response hash",
    )
    try:
        outpoint = raw["outpoint"]
        utxo = raw["utxoEntry"]
        observed = {
            "deploy_tx_id": outpoint["transactionId"],
            "index": outpoint["index"],
            "amount_sompi": int(utxo["amount"]),
            "covenant_id": utxo["covenantId"],
            "block_daa_score": int(utxo["blockDaaScore"]),
            "is_coinbase": utxo["isCoinbase"],
        }
    except (KeyError, TypeError, ValueError) as exc:
        raise BindingError(
            "EVIDENCE_RAW", f"{role}: malformed raw node response"
        ) from exc
    _require(
        observed["is_coinbase"] is False, "EVIDENCE_ANCHOR", f"{role}: coinbase output"
    )
    _require(
        observed["index"] == 0,
        "EVIDENCE_ANCHOR",
        f"{role}: genesis contract output must be index 0",
    )
    for field in ("deploy_tx_id", "amount_sompi", "covenant_id", "block_daa_score"):
        _require(
            item[field] == observed[field],
            "EVIDENCE_INCONSISTENT",
            f"{role}: {field} differs from raw response",
        )
    _require(
        HEX32.fullmatch(str(item["deploy_tx_id"])) is not None,
        "EVIDENCE_ANCHOR",
        f"{role}: deploy tx id",
    )
    _require(
        item["deployed_instance_id"] == f"{item['deploy_tx_id']}:0",
        "EVIDENCE_ANCHOR",
        f"{role}: instance id",
    )
    _require(
        item["deploy_tx_id"] != entry["funding_outpoint"].split(":")[0],
        "EVIDENCE_ANCHOR",
        f"{role}: genesis transaction must spend, not equal, the funding outpoint",
    )
    _require(
        HEX32.fullmatch(str(item["block_hash"])) is not None,
        "EVIDENCE_ANCHOR",
        f"{role}: block hash",
    )
    confirmations = item["confirmations"]
    _require(
        isinstance(confirmations, int) and confirmations >= MIN_CONFIRMATIONS,
        "EVIDENCE_ANCHOR",
        f"{role}: insufficient confirmations",
    )
    _require(
        item["covenant_id"] == entry["predicted_covenant_id"],
        "COVENANT_MISMATCH",
        f"{role}: observed covenant id differs from the planned id",
    )
    _require(
        item["amount_sompi"] == entry["genesis_value_sompi"],
        "EVIDENCE_INCONSISTENT",
        f"{role}: genesis value differs from plan",
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
        _validate_evidence(entries[role], evidence[role], plan["network_id"], role)
    observed_ids = [evidence[role]["covenant_id"] for role in evidence]
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

    Only a result with complete, consistent public evidence can accept a state.
    A covenant id that is not in the binding (lookalike) is rejected.
    """
    _require(
        result.get("status") == STATUS_EVIDENCE_PENDING_RECOMPUTE,
        "NOT_CONFIRMED",
        "no evidenced deployment identity to accept states against",
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

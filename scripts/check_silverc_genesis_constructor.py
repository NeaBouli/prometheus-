#!/usr/bin/env python3
"""Machine-checkable MS-B genesis constructor checklist for the v2 state contracts.

The checker reads a constructor-values JSON file for the six v2 state contracts and
rejects every value set that violates a genesis invariant derived from the
current-silverc sources in ``modules/contracts/silverc``. Constructor parameter
names, order and types as well as the bound constants are parsed from the ``.sil``
files themselves, so a source change without a checklist update fails closed.

This is a pre-deployment gate only. It never accepts a deployment set: the best
possible verdict is ``NOT_ACCEPTED_OWNER_DECISIONS_PENDING``. Contract v2 stays
non-promotable and the D5 genesis-binding ``accept_state`` gate stays closed.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONTRACTS_DIR = REPO_ROOT / "modules" / "contracts" / "silverc"
SCHEMA_VERSION = "prometheus.silverc.genesis-constructor.v1"
REPORT_SCHEMA_VERSION = "prometheus.silverc.genesis-constructor-report.v1"

VERDICT_REJECT = "REJECT"
VERDICT_NOT_ACCEPTED = "NOT_ACCEPTED_OWNER_DECISIONS_PENDING"
VERDICTS = (VERDICT_REJECT, VERDICT_NOT_ACCEPTED)

SEVERITY_VIOLATION = "VIOLATION"
SEVERITY_OWNER_DECISION = "OWNER_DECISION_REQUIRED"

I64_MAX = 2**63 - 1
I64_MIN = -(2**63)
OUT_OF_SCOPE_CONTRACTS = ("ValidatorStakingH001",)

# Rule kinds:
#   zero             int must be 0
#   false            bool must be false
#   zero_bytes       byte[N] must be all-zero
#   role_key         role-bound key: valid, non-zero, not the placeholder
#   placeholder_key  no proposal/donor yet: must equal the declared placeholder
#   participant_key  participant-chosen key: format only
#   free             free metadata / policy value: type and non-negativity only
#   custom           contract-specific rule implemented below
RULES: dict[str, dict[str, str]] = {
    "ValidatorStakingState": {
        "init_validator_pk": "role_key",
        "init_stake_kas": "custom",
        "init_active": "custom",
        "init_joined_at": "free",
        "init_reputation": "free",
        "init_slashing_count": "zero",
        "init_last_vote_block": "zero",
        "init_commitment": "zero_bytes",
        "init_bond_kas": "zero",
        "init_committed_at_block": "zero",
        "init_withdraw_request_block": "zero",
    },
    "GuardianReputationState": {
        "init_guardian_pk": "participant_key",
        "init_governance_pk": "role_key",
        "init_compute_power_gflops": "zero",
        "init_reputation": "custom",
        "init_proposals_submitted": "zero",
        "init_proposals_accepted": "zero",
        "init_registered_at": "zero",
        "init_model_type": "custom",
    },
    "RuleStorageState": {
        "init_governance_pk": "role_key",
        "init_next_proposal_id": "zero",
        "init_proposal_id": "zero",
        "init_guardian_pk": "placeholder_key",
        "init_threat_hash": "zero_bytes",
        "init_rule_type": "zero",
        "init_rule_content_ipfs": "zero_bytes",
        "init_confidence": "zero",
        "init_submitted_at_block": "zero",
        "init_votes_for": "zero",
        "init_votes_against": "zero",
        "init_voting_end_block": "zero",
        "init_status": "zero",
        "init_rule_count": "zero",
        "init_count_in_window": "zero",
        "init_last_count_reset_block": "zero",
        "init_consensus_score": "zero",
        "init_stored_at_block": "zero",
        "init_active": "false",
        "init_guardian_reputation_event": "zero",
    },
    "CommunityDonationsState": {
        "init_governance_pk": "role_key",
        "init_donation_count": "zero",
        "init_total_donated_kas": "zero",
        "init_pool_balance_kas": "custom",
        "init_next_disbursement_id": "zero",
        "init_disbursement_id": "zero",
        "init_recipient_pk": "placeholder_key",
        "init_amount_kas": "zero",
        "init_purpose_hash": "zero_bytes",
        "init_votes_for": "zero",
        "init_votes_against": "zero",
        "init_voting_end_block": "zero",
        "init_status": "zero",
        "init_executed": "false",
        "init_last_donor_pk": "placeholder_key",
        "init_last_message_hash": "zero_bytes",
        "init_last_donation_block": "zero",
    },
    "DevIncentivePoolState": {
        "init_governance_pk": "role_key",
        "init_next_grant_id": "zero",
        "init_pool_balance_prom": "custom",
        "init_grant_id": "zero",
        "init_developer_pk": "placeholder_key",
        "init_contribution_hash": "zero_bytes",
        "init_description_hash": "zero_bytes",
        "init_lines_of_code": "zero",
        "init_complexity": "custom",
        "init_requested_amount_prom": "zero",
        "init_votes_for": "zero",
        "init_votes_against": "zero",
        "init_voting_end_block": "zero",
        "init_executed": "false",
        "init_paid": "false",
        "init_status": "zero",
        "init_last_proposer_pk": "placeholder_key",
    },
    "GovernanceAutoTuningState": {
        "init_metrics_oracle_pk": "role_key",
        "init_min_stake_kas": "custom",
        "init_min_guardian_rep": "free",
        "init_min_confidence_ki": "custom",
        "init_validator_consensus": "free",
        "init_reward_base": "custom",
        "init_last_tuning_block": "custom",
        "init_active_validators": "zero",
        "init_active_guardians": "zero",
        "init_proposals_per_day": "zero",
        "init_fp_rate": "custom",
        "init_last_metrics_block": "zero",
    },
}

ABBREVIATIONS = {
    "ValidatorStakingState": "VS",
    "GuardianReputationState": "GR",
    "RuleStorageState": "RS",
    "CommunityDonationsState": "CD",
    "DevIncentivePoolState": "DP",
    "GovernanceAutoTuningState": "AT",
}

ROLE_KINDS = {
    ("ValidatorStakingState", "init_validator_pk"): "validator",
    ("GuardianReputationState", "init_governance_pk"): "governance",
    ("RuleStorageState", "init_governance_pk"): "governance",
    ("CommunityDonationsState", "init_governance_pk"): "governance",
    ("DevIncentivePoolState", "init_governance_pk"): "governance",
    ("GovernanceAutoTuningState", "init_metrics_oracle_pk"): "metrics_oracle",
}

VALUE_BACKED = {
    "ValidatorStakingState": "init_stake_kas",
    "CommunityDonationsState": "init_pool_balance_kas",
}

# Extra (non-constructor) per-contract fields allowed in the values file.
EXTRA_FIELDS = {
    "ValidatorStakingState": {"genesis_value_sompi"},
    "CommunityDonationsState": {"genesis_value_sompi"},
    "GovernanceAutoTuningState": {"observed_tuning_anchor_daa"},
    "DevIncentivePoolState": {"pool_balance_owner_decision"},
}

NON_NEGATIVE = {
    ("ValidatorStakingState", "init_stake_kas"),
    ("CommunityDonationsState", "init_pool_balance_kas"),
}

# Allowed genesis values as constant names ("0" = literal zero) plus the reason.
ALLOWED_SETS: dict[tuple[str, str], tuple[tuple[str, ...], str]] = {
    ("GuardianReputationState", "init_reputation"): (
        ("0", "REPUTATION_START"),
        "no pre-set reputation",
    ),
    ("GuardianReputationState", "init_model_type"): (
        ("MODEL_TYPE_70B", "MODEL_TYPE_8B"),
        "known model type",
    ),
    ("DevIncentivePoolState", "init_complexity"): (
        ("0", "MIN_COMPLEXITY"),
        "no pending grant",
    ),
}

CONTRACT_RE = re.compile(r"\bcontract\s+(\w+)\s*\((.*?)\)\s*\{", re.DOTALL)
CONSTANT_RE = re.compile(r"\bint\s+constant\s+(\w+)\s*=\s*(-?\d+)\s*;")
BYTES_TYPE_RE = re.compile(r"^byte\[(\d+)\]$")
HEX_RE = re.compile(r"^[0-9a-f]*$")


@dataclass(frozen=True)
class Param:
    """One constructor parameter as declared in a ``.sil`` source."""

    name: str
    type: str


@dataclass(frozen=True)
class ContractSpec:
    """Constructor parameters and integer constants parsed from a ``.sil`` file."""

    name: str
    params: tuple[Param, ...]
    constants: dict[str, int]


def rule_id(contract: str, param: str) -> str:
    """Return the stable rule id for a constructor parameter."""
    stem = param.removeprefix("init_").upper().replace("_", "-")
    return f"G-{ABBREVIATIONS[contract]}-{stem}"


def all_rule_ids() -> list[str]:
    """List every parameter rule id plus the cross-field rule ids."""
    ids = [rule_id(c, p) for c, params in RULES.items() for p in params]
    ids += [f"G-{ABBREVIATIONS[c]}-VALUE-BACKING" for c in VALUE_BACKED]
    ids += ["G-ROLE-KEY-REUSE", "G-ROLE-SHARED-GOVERNANCE-KEY"]
    return ids


def parse_contract(path: Path) -> ContractSpec:
    """Parse the constructor signature and integer constants of one ``.sil`` file."""
    text = path.read_text(encoding="utf-8")
    match = CONTRACT_RE.search(text)
    if match is None:
        raise ValueError(f"{path}: no contract declaration found")
    params: list[Param] = []
    for raw in match.group(2).split(","):
        raw = raw.strip()
        if not raw:
            continue
        parts = raw.split()
        if len(parts) != 2:
            raise ValueError(f"{path}: cannot parse constructor parameter {raw!r}")
        params.append(Param(name=parts[1], type=parts[0]))
    constants = {name: int(value) for name, value in CONSTANT_RE.findall(text)}
    return ContractSpec(name=match.group(1), params=tuple(params), constants=constants)


def load_specs(contracts_dir: Path) -> dict[str, ContractSpec]:
    """Load the specs of the six in-scope v2 state contracts."""
    specs: dict[str, ContractSpec] = {}
    for name in RULES:
        spec = parse_contract(contracts_dir / f"{name}.sil")
        if spec.name != name:
            raise ValueError(f"{name}.sil declares contract {spec.name}")
        specs[name] = spec
    return specs


class Checker:
    """Collects findings for one constructor-values document."""

    def __init__(self, specs: dict[str, ContractSpec]) -> None:
        self.specs = specs
        self.findings: list[dict[str, Any]] = []
        self.placeholder = ""

    def add(
        self,
        rule: str,
        message: str,
        contract: str = "",
        param: str = "",
        severity: str = SEVERITY_VIOLATION,
    ) -> None:
        """Record one finding."""
        self.findings.append(
            {
                "rule_id": rule,
                "severity": severity,
                "contract": contract,
                "parameter": param,
                "message": message,
            }
        )

    # -- type validation -------------------------------------------------

    def type_ok(self, contract: str, param: Param, value: Any) -> bool:
        """Check a value against its declared SilverScript type."""
        ok: bool
        if param.type == "int":
            ok = isinstance(value, int) and not isinstance(value, bool)
            ok = ok and I64_MIN <= value <= I64_MAX
        elif param.type == "bool":
            ok = isinstance(value, bool)
        elif param.type == "pubkey":
            ok = is_hex(value, 32)
        else:
            bytes_match = BYTES_TYPE_RE.match(param.type)
            if bytes_match is None:
                self.add(
                    "G-PARSE-TYPE",
                    f"unsupported type {param.type}",
                    contract,
                    param.name,
                )
                return False
            ok = is_hex(value, int(bytes_match.group(1)))
        if not ok:
            self.add(
                "G-PARSE-TYPE",
                f"value {value!r} is not a valid {param.type}",
                contract,
                param.name,
            )
        return ok

    # -- top level --------------------------------------------------------

    def check(self, doc: Any) -> None:
        """Run every structural and invariant check."""
        if not isinstance(doc, dict) or doc.get("schema_version") != SCHEMA_VERSION:
            self.add("G-PARSE-SCHEMA", f"schema_version must be {SCHEMA_VERSION}")
            return
        unknown_top = set(doc) - {
            "schema_version",
            "description",
            "synthetic",
            "placeholder_pubkey",
            "contracts",
        }
        if unknown_top:
            self.add(
                "G-PARSE-SCHEMA", f"unknown top-level fields {sorted(unknown_top)}"
            )
        placeholder = doc.get("placeholder_pubkey")
        if not is_hex(placeholder, 32):
            self.add(
                "G-PARSE-SCHEMA", "placeholder_pubkey must be 32-byte lowercase hex"
            )
            return
        self.placeholder = str(placeholder)
        contracts = doc.get("contracts")
        if not isinstance(contracts, dict):
            self.add("G-PARSE-SCHEMA", "contracts must be an object")
            return
        for name in OUT_OF_SCOPE_CONTRACTS:
            if name in contracts:
                self.add(
                    "G-PARSE-H001-OUT-OF-SCOPE",
                    "frozen v1 canary is not part of a v2 genesis set",
                    name,
                )
        extra = set(contracts) - set(RULES) - set(OUT_OF_SCOPE_CONTRACTS)
        for name in sorted(extra):
            self.add("G-PARSE-CONTRACT-SET", "unknown contract", name)
        missing = [name for name in RULES if name not in contracts]
        for name in missing:
            self.add("G-PARSE-CONTRACT-SET", "contract missing", name)
        values_by_contract: dict[str, dict[str, Any]] = {}
        for name in RULES:
            if name in contracts:
                checked = self.check_contract(name, contracts[name])
                if checked is not None:
                    values_by_contract[name] = checked
        self.check_role_keys(values_by_contract)

    def check_contract(self, name: str, entry: Any) -> dict[str, Any] | None:
        """Validate one contract entry; returns typed constructor values when parseable."""
        if not isinstance(entry, dict) or not isinstance(
            entry.get("constructor"), dict
        ):
            self.add("G-PARSE-SCHEMA", "entry must contain a constructor object", name)
            return None
        unknown = set(entry) - {"constructor"} - EXTRA_FIELDS.get(name, set())
        if unknown:
            self.add("G-PARSE-SCHEMA", f"unknown fields {sorted(unknown)}", name)
        spec = self.specs[name]
        values: dict[str, Any] = entry["constructor"]
        declared = [p.name for p in spec.params]
        uncovered = [p for p in declared if p not in RULES[name]]
        for missing_rule in uncovered:
            self.add(
                "G-PARSE-UNCOVERED",
                "parameter has no checklist rule",
                name,
                missing_rule,
            )
        if list(values) != declared:
            missing = [p for p in declared if p not in values]
            extra = [p for p in values if p not in declared]
            detail = f"missing={missing} extra={extra}"
            if not missing and not extra:
                detail = "parameters out of constructor order"
            self.add("G-PARSE-PARAMS", detail, name)
            return None
        if uncovered:
            return None
        if not all(self.type_ok(name, p, values[p.name]) for p in spec.params):
            return None
        for param in spec.params:
            self.check_param(name, param, values[param.name], values, entry)
        if name in VALUE_BACKED:
            self.check_value_backing(name, values[VALUE_BACKED[name]], entry)
        return values

    # -- per parameter -----------------------------------------------------

    def check_param(
        self,
        contract: str,
        param: Param,
        value: Any,
        values: dict[str, Any],
        entry: dict[str, Any],
    ) -> None:
        """Apply the rule bound to one parameter."""
        kind = RULES[contract][param.name]
        rid = rule_id(contract, param.name)
        if kind == "zero" and value != 0:
            self.add(rid, f"must be 0 at genesis, got {value}", contract, param.name)
        elif kind == "false" and value is not False:
            self.add(rid, "must be false at genesis", contract, param.name)
        elif kind == "zero_bytes" and set(value) != {"0"}:
            self.add(rid, "must be all-zero bytes at genesis", contract, param.name)
        elif kind == "placeholder_key" and value != self.placeholder:
            self.add(
                rid,
                "must equal placeholder_pubkey (no pending entry at genesis)",
                contract,
                param.name,
            )
        elif kind == "role_key":
            if set(value) == {"0"} or value == self.placeholder:
                self.add(
                    rid,
                    "role key must be a real key, not zero/placeholder",
                    contract,
                    param.name,
                )
        elif kind == "free" and isinstance(value, int) and value < 0:
            self.add(rid, "must not be negative", contract, param.name)
        elif kind == "custom":
            self.check_custom(contract, param.name, value, values, entry)

    def check_custom(
        self,
        contract: str,
        param: str,
        value: Any,
        values: dict[str, Any],
        entry: dict[str, Any],
    ) -> None:
        """Contract-specific invariants."""
        rid = rule_id(contract, param)
        const = self.specs[contract].constants
        key = (contract, param)
        if key in NON_NEGATIVE:
            if value < 0:
                self.add(rid, "must not be negative", contract, param)
        elif key in ALLOWED_SETS:
            names, reason = ALLOWED_SETS[key]
            allowed = {0 if n == "0" else const[n] for n in names}
            if value not in allowed:
                self.add(rid, f"must be one of {names} ({reason})", contract, param)
        elif key == ("ValidatorStakingState", "init_active"):
            expected = values["init_stake_kas"] >= const["MIN_STAKE_KAS"]
            if value is not expected:
                self.add(
                    rid,
                    f"must equal init_stake_kas >= MIN_STAKE_KAS ({expected})",
                    contract,
                    param,
                )
        elif key == ("DevIncentivePoolState", "init_pool_balance_prom"):
            self.check_prom_pool(contract, param, value, entry)
        elif contract == "GovernanceAutoTuningState":
            self.check_tuning(param, value, entry)

    def check_prom_pool(
        self,
        contract: str,
        param: str,
        value: int,
        entry: dict[str, Any],
    ) -> None:
        """PROM pool accounting is unbacked; non-zero needs an owner decision."""
        rid = rule_id(contract, param)
        decision = entry.get("pool_balance_owner_decision")
        if value < 0:
            self.add(rid, "must not be negative", contract, param)
        elif value != 0 and not (isinstance(decision, str) and decision.strip()):
            self.add(
                rid,
                "non-zero unbacked PROM accounting requires "
                "pool_balance_owner_decision",
                contract,
                param,
            )
        elif value != 0:
            self.add(
                rid,
                f"non-zero PROM pool referenced to owner decision {decision!r}; "
                "not accepted by this checker",
                contract,
                param,
                severity=SEVERITY_OWNER_DECISION,
            )

    def check_tuning(self, param: str, value: int, entry: dict[str, Any]) -> None:
        """GovernanceAutoTuning floors/ceilings, anchor and FP-rate bounds."""
        contract = "GovernanceAutoTuningState"
        rid = rule_id(contract, param)
        const = self.specs[contract].constants
        bounds = {
            "init_min_stake_kas": ("MIN_STAKE_KAS_FLOOR", "MIN_STAKE_KAS_CEILING"),
            "init_min_confidence_ki": ("CONFIDENCE_FLOOR", "CONFIDENCE_CEILING"),
            "init_reward_base": ("REWARD_FLOOR", "REWARD_CEILING"),
        }
        if param in bounds:
            low, high = (const[n] for n in bounds[param])
            if not low <= value <= high:
                self.add(rid, f"must be within [{low}, {high}]", contract, param)
        elif param == "init_fp_rate":
            if not 0 <= value <= const["MAX_FP_RATE"]:
                self.add(
                    rid, f"must be within [0, {const['MAX_FP_RATE']}]", contract, param
                )
        elif param == "init_last_tuning_block":
            anchor = entry.get("observed_tuning_anchor_daa")
            if anchor is None:
                if value != 0:
                    self.add(
                        rid,
                        "must be 0 (anchor pending) unless "
                        "observed_tuning_anchor_daa is supplied",
                        contract,
                        param,
                    )
            elif not (
                isinstance(anchor, int) and not isinstance(anchor, bool) and anchor > 0
            ):
                self.add(
                    rid,
                    "observed_tuning_anchor_daa must be a positive int",
                    contract,
                    param,
                )
            elif value != anchor:
                self.add(rid, "must equal observed_tuning_anchor_daa", contract, param)

    # -- cross-field ---------------------------------------------------------

    def check_value_backing(
        self, contract: str, kas: int, entry: dict[str, Any]
    ) -> None:
        """Genesis covenant value must equal the constructor KAS amount in sompi."""
        rid = f"G-{ABBREVIATIONS[contract]}-VALUE-BACKING"
        sompi_per_kas = self.specs[contract].constants["SOMPI_PER_KAS"]
        declared = entry.get("genesis_value_sompi")
        expected = kas * sompi_per_kas
        if not (isinstance(declared, int) and not isinstance(declared, bool)):
            self.add(rid, "genesis_value_sompi (int) is required", contract)
        elif expected > I64_MAX:
            self.add(rid, "KAS amount * SOMPI_PER_KAS exceeds i64", contract)
        elif declared != expected:
            self.add(rid, f"genesis_value_sompi {declared} != {expected}", contract)

    def check_role_keys(self, values_by_contract: dict[str, dict[str, Any]]) -> None:
        """Detect key reuse across role slots."""
        by_key: dict[str, list[tuple[str, str]]] = {}
        for (contract, param), kind in ROLE_KINDS.items():
            if contract in values_by_contract:
                key = values_by_contract[contract][param]
                by_key.setdefault(key, []).append((contract, kind))
        for slots in by_key.values():
            if len(slots) < 2:
                continue
            kinds = {kind for _, kind in slots}
            names = ", ".join(c for c, _ in slots)
            if kinds == {"governance"}:
                self.add(
                    "G-ROLE-SHARED-GOVERNANCE-KEY",
                    f"one governance key shared by {names}",
                    severity=SEVERITY_OWNER_DECISION,
                )
            else:
                self.add(
                    "G-ROLE-KEY-REUSE",
                    f"one key bound to different roles {sorted(kinds)} in {names}",
                )


def is_hex(value: Any, n_bytes: int) -> bool:
    """True when value is lowercase hex of exactly ``n_bytes`` bytes."""
    return (
        isinstance(value, str)
        and len(value) == 2 * n_bytes
        and HEX_RE.fullmatch(value) is not None
    )


def evaluate(doc: Any, contracts_dir: Path = DEFAULT_CONTRACTS_DIR) -> dict[str, Any]:
    """Evaluate a constructor-values document and return the JSON report."""
    checker = Checker(load_specs(contracts_dir))
    checker.check(doc)
    violations = [f for f in checker.findings if f["severity"] == SEVERITY_VIOLATION]
    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "verdict": VERDICT_REJECT if violations else VERDICT_NOT_ACCEPTED,
        "acceptance": "closed: v2 non-promotable, D5 accept_state closed, "
        "owner decisions pending",
        "findings": checker.findings,
    }


def main(argv: list[str] | None = None) -> int:
    """CLI entry point; exit 1 on any violation, 0 for clean-but-not-accepted."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--values", required=True, type=Path)
    parser.add_argument("--contracts-dir", type=Path, default=DEFAULT_CONTRACTS_DIR)
    args = parser.parse_args(argv)
    try:
        doc = json.loads(args.values.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        report: dict[str, Any] = {
            "schema_version": REPORT_SCHEMA_VERSION,
            "verdict": VERDICT_REJECT,
            "findings": [
                {
                    "rule_id": "G-PARSE-SCHEMA",
                    "severity": SEVERITY_VIOLATION,
                    "contract": "",
                    "parameter": "",
                    "message": str(exc),
                }
            ],
        }
    else:
        report = evaluate(doc, args.contracts_dir)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 1 if report["verdict"] == VERDICT_REJECT else 0


if __name__ == "__main__":
    sys.exit(main())

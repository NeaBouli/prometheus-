#!/usr/bin/env python3
"""Fail closed when public Prometheus status claims drift from evidence."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

STATUS_PATH = Path("docs/evidence/public-claim-status-2026-08-14.json")
PUBLIC_FILES = (
    Path("README.md"),
    Path("WHITEPAPER.md"),
    Path("docs/roadmap.md"),
    Path("docs/faq.md"),
    Path("memory/STATUS.md"),
    Path("index.html"),
    Path("roadmap.html"),
    Path("whitepaper.html"),
    Path("faq.html"),
    Path("guardian-economics.html"),
    Path("llms.txt"),
    Path("modules/client/README.md"),
    Path("modules/guardian-node/README.md"),
)

GH234_PUBLIC_FILES = tuple(
    path
    for path in PUBLIC_FILES
    if path
    not in {
        Path("guardian-economics.html"),
        Path("modules/guardian-node/README.md"),
    }
)

GH238_PUBLIC_FILES = (
    Path("README.md"),
    Path("WHITEPAPER.md"),
    Path("docs/roadmap.md"),
    Path("docs/faq.md"),
    Path("memory/STATUS.md"),
    Path("roadmap.html"),
    Path("whitepaper.html"),
    Path("faq.html"),
    Path("llms.txt"),
    Path("modules/client/README.md"),
)

GH242_PUBLIC_FILES = (
    Path("README.md"),
    Path("WHITEPAPER.md"),
    Path("docs/roadmap.md"),
    Path("docs/faq.md"),
    Path("memory/STATUS.md"),
    Path("index.html"),
    Path("roadmap.html"),
    Path("whitepaper.html"),
    Path("faq.html"),
    Path("llms.txt"),
    Path("modules/guardian-node/README.md"),
)

REQUIRED_FRAGMENTS = {
    Path("README.md"): (
        "no production Prometheus network",
        "stake KAS, never PROM",
        "fail-closed safe-default stub",
        "single static loopback Guardian peer",
        "GH-234 Light Client ThreatHint-v2 submission",
    ),
    Path("WHITEPAPER.md"): (
        "no ONNX session",
        "rule content is stored",
        "fail-closed safe-default stub",
        "exactly one canonical static literal-loopback QUIC peer",
        "GH-234/PR #235",
    ),
    Path("docs/roadmap.md"): (
        "scope-weighted engineering estimates",
        "NO OPERATED VALIDATOR NETWORK",
        "Phi-3 fail-closed safe-default stub",
        "Development-only Light Client v1 ThreatHint sender",
        "Development/Testnet-10-only Light Client ThreatHint-v2 sender",
    ),
    Path("docs/faq.md"): (
        "No PROM minting, emission, pool, or",
        "development placeholder",
        "fail-closed safe-default stub",
        "Development-only v1 submission path",
        "Development/Testnet-10-only Light Client v2 submission command",
    ),
    Path("memory/STATUS.md"): (
        "Production-deployed: no Prometheus protocol component",
        "stake KAS, never PROM",
        "GH-223 fail-closed safe-default stub",
        "GH-226 one-shot v1 sender",
        "GH-234 one-shot v2 sender",
    ),
    Path("index.html"): (
        "No production protocol network or PROM emission is active",
        "Target: on-chain in under 60 seconds",
        "bounded fail-closed safe-default stub",
        "one static literal-loopback Guardian peer",
        "GH-234 ThreatHint-v2 submission",
    ),
    Path("roadmap.html"): (
        "not production evidence",
        "no ONNX session",
        "fail-closed safe-default stub",
        "GH-226 implements one Development-only Light Client v1 ThreatHint sender",
        "GH-234/PR #235",
    ),
    Path("whitepaper.html"): (
        "Current Phi-3 and proof generation are development stubs",
        "content on IPFS",
        "fail-closed safe-default stub",
        "GH-226 adds one Development-only v1 ThreatHint sender",
        "GH-234/PR #235",
    ),
    Path("faq.html"): (
        "not implemented, deployed, or active",
        "No completed fine-tuning",
        "fail-closed safe-default stub",
        "GH-226 adds one Development-only Light Client v1 sender",
        "GH-234/PR #235",
    ),
    Path("guardian-economics.html"): (
        "not active network economics",
        "PROM minting, emission, liquidity and trading are not implemented, deployed or active",
    ),
    Path("llms.txt"): (
        "Production protocol status: none proven deployed",
        "validators stake KAS, never PROM",
        "fail-closed safe-default stub",
        "GH-226 adds one Development-only v1 ThreatHint sender",
        "GH-234/PR #235",
    ),
    Path("modules/client/README.md"): (
        "development foundation",
        "creates no ONNX Runtime session",
        "safe default",
        "threat-hint preflight|submit",
        "threat-hint-v2 preflight|submit",
    ),
    Path("modules/guardian-node/README.md"): (
        "No actionable rule is authorized",
        "completed real-model run",
    ),
}

BANNED_CLAIMS = {
    "prom-cannot-be-purchased": re.compile(
        r"PROM (?:can never|cannot|can not) be purchased", re.I
    ),
    "rules-never-removed": re.compile(
        r"rules? can never be (?:removed|deleted|suppressed)", re.I
    ),
    "absolute-censorship": re.compile(
        r"no (?:organization|corporation) can (?:modify|censor|suppress)", re.I
    ),
    "commercial-outperformance": re.compile(
        r"(?:outperforms?|better than) commercial (?:models|systems)", re.I
    ),
    "stale-launch-date": re.compile(
        r"(?:Mainnet|Testnet)(?: target| launch| Launch| Ziel)?:? (?:May|Mai) (?:5, )?2026",
        re.I,
    ),
    "stale-phi3-heuristic": re.compile(
        r"Phi-3(?:-mini)?[^\n]{0,200}(?:placeholder/|development(?:-only)? )?heuristic(?:/stub)?",
        re.I,
    ),
}


def validate_status(data: dict[str, Any]) -> list[str]:
    """Return invariant errors for the canonical machine-readable status."""
    errors: list[str] = []
    classes = data.get("classifications", {})
    validators = classes.get("validators", {})
    prom = classes.get("prom", {})
    deployment = classes.get("deployment", {})
    performance = classes.get("performance", {})
    light = classes.get("light_client", {})
    economics = classes.get("guardian_economics", {})
    gh_234 = data.get("post_audit_updates", {}).get("gh_234", {})
    gh_238 = data.get("post_audit_updates", {}).get("gh_238", {})
    gh_242 = data.get("post_audit_updates", {}).get("gh_242", {})

    if (
        validators.get("stake_asset") != "KAS"
        or validators.get("prom_staking") is not False
    ):
        errors.append("validators must stake KAS and PROM staking must be false")
    if any(
        prom.get(field) is not False
        for field in ("minting_implemented", "deployed", "active")
    ):
        errors.append("PROM minting, deployment, and activity must remain false")
    shares = prom.get("year_one_allocation_percent", {})
    if set(shares) != {"validators", "guardians", "reporters", "dev_pool", "community"}:
        errors.append("PROM allocation categories are incomplete")
    elif sum(shares.values()) != 100:
        errors.append("PROM allocation must total 100 percent")
    if deployment.get("production_protocol_components") != "none_proven":
        errors.append("production protocol deployment must remain none proven")
    if deployment.get("mainnet_ready") is not False:
        errors.append("Mainnet readiness must remain false")
    if deployment.get("testnet_10_h001_canary") != "confirmed_non_promotable":
        errors.append("H-001 must remain confirmed and non-promotable")
    if performance.get("under_60_seconds") != "target_only":
        errors.append("under-60-second lifecycle must remain target-only")
    if light.get("phi3_onnx_inference") != "not_implemented":
        errors.append("Phi-3 ONNX inference must remain not implemented")
    if light.get("phi3_stub_authority") != "safe_default_only_no_quarantine_authority":
        errors.append(
            "Phi-3 stub must remain safe-default without quarantine authority"
        )
    if light.get("p2p_reporting") != "not_operated":
        errors.append("Light Client P2P reporting must remain not operated")
    if light.get("p2p_v1_submission") != "development_only_same_host_loopback_verified":
        errors.append(
            "Light Client v1 submission must remain development-only same-host evidence"
        )
    if gh_234.get("classification") != "development_only_same_host_loopback_verified":
        errors.append(
            "GH-234 v2 submission must remain development-only same-host evidence"
        )
    if gh_234.get("status") != "merged_and_exact_main_verified":
        errors.append("GH-234 must retain merged exact-main verification status")
    merge_commit = gh_234.get("merge_commit")
    if (
        not isinstance(merge_commit, str)
        or re.fullmatch(r"[0-9a-f]{40}", merge_commit) is None
    ):
        errors.append("GH-234 merge commit must be one full lowercase SHA-1")
    exact_main_runs = gh_234.get("exact_main_runs", {})
    if set(exact_main_runs) != {"prometheus_ci", "security_audit", "pages"}:
        errors.append("GH-234 exact-main run evidence is incomplete")
    elif not all(
        isinstance(run_id, int) and run_id > 0 for run_id in exact_main_runs.values()
    ):
        errors.append("GH-234 exact-main run IDs must be positive integers")
    if gh_234.get("public_or_multihost_v2") is not False:
        errors.append("GH-234 must not claim public or multi-host v2 operation")
    if gh_234.get("production_authority") is not False:
        errors.append("GH-234 production authority must remain false")
    if gh_238.get("issue") != 238 or gh_238.get("pull_request") != 239:
        errors.append("GH-238 machine status identity is invalid")
    if gh_238.get("status") != "merged_and_exact_main_verified":
        errors.append("GH-238 must retain merged exact-main verification status")
    if (
        gh_238.get("classification") != "development_testnet10_repository_only"
        or gh_238.get("transport") != "direct-quic-v1"
        or gh_238.get("protocol") != "/prometheus/threat-hint/2.0.0"
    ):
        errors.append(
            "GH-238 must remain repository-only Development/Testnet-10 preparation"
        )
    gh_238_merge_commit = gh_238.get("merge_commit")
    if (
        not isinstance(gh_238_merge_commit, str)
        or re.fullmatch(r"[0-9a-f]{40}", gh_238_merge_commit) is None
    ):
        errors.append("GH-238 merge commit must be one full lowercase SHA-1")
    gh_238_exact_main_runs = gh_238.get("exact_main_runs", {})
    if set(gh_238_exact_main_runs) != {"prometheus_ci", "security_audit", "pages"}:
        errors.append("GH-238 exact-main run evidence is incomplete")
    elif not all(
        type(run_id) is int and run_id > 0 for run_id in gh_238_exact_main_runs.values()
    ):
        errors.append("GH-238 exact-main run IDs must be positive integers")
    for field in (
        "remote_run",
        "evidence_record",
        "independent_host_proof",
        "network_or_infrastructure_action",
        "production_authority",
    ):
        if gh_238.get(field) is not False:
            errors.append(f"GH-238 {field} must remain false")
    if gh_242.get("issue") != 242:
        errors.append("GH-242 machine status identity is invalid")
    if (
        gh_242.get("status") != "implemented_and_locally_tested_repository_boundary"
        or gh_242.get("classification") != "owner_local_membership_bound_ballot_session"
        or gh_242.get("canonical_source_loaded_once") is not True
    ):
        errors.append("GH-242 repository boundary classification is invalid")
    for field in (
        "caller_supplied_committee_or_signers",
        "ballot_wire_or_ensemble_formula_changed",
        "external_membership_authority",
        "key_ownership_or_rotation_proven",
        "sybil_resistance_proven",
        "on_chain_attestation",
        "production_authority",
    ):
        if gh_242.get(field) is not False:
            errors.append(f"GH-242 {field} must remain false")
    if economics.get("status") != "illustrative_planning_only":
        errors.append("Guardian economics must remain illustrative planning only")
    if economics.get("active_rewards_or_market_price") is not False:
        errors.append("Guardian rewards and market price must remain inactive")
    return errors


def find_banned_claims(text: str) -> list[str]:
    """Return category names only, avoiding matched-value disclosure."""
    return [name for name, pattern in BANNED_CLAIMS.items() if pattern.search(text)]


def validate_json_ld(text: str) -> list[str]:
    """Validate every JSON-LD script body in an HTML document."""
    bodies = re.findall(
        r'<script[^>]+type=["\']application/ld\+json["\'][^>]*>(.*?)</script>',
        text,
        flags=re.I | re.S,
    )
    errors: list[str] = []
    if not bodies:
        return ["missing JSON-LD"]
    for index, body in enumerate(bodies, start=1):
        try:
            json.loads(body)
        except json.JSONDecodeError:
            errors.append(f"invalid JSON-LD block {index}")
    return errors


def verify(root: Path) -> list[str]:
    """Verify canonical status and synchronized public surfaces."""
    errors: list[str] = []
    status_file = root / STATUS_PATH
    try:
        status = json.loads(status_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return [f"{STATUS_PATH}: missing or invalid canonical status"]
    errors.extend(f"{STATUS_PATH}: {item}" for item in validate_status(status))
    gh_234 = status.get("post_audit_updates", {}).get("gh_234", {})
    merge_commit = gh_234.get("merge_commit", "")
    run_ids = gh_234.get("exact_main_runs", {})
    gh_234_evidence_fragments = (
        merge_commit[:7] if isinstance(merge_commit, str) else "",
        *(
            str(run_ids.get(name, ""))
            for name in ("prometheus_ci", "security_audit", "pages")
        ),
    )
    gh_238 = status.get("post_audit_updates", {}).get("gh_238", {})
    gh_238_merge_commit = gh_238.get("merge_commit", "")
    gh_238_run_ids = gh_238.get("exact_main_runs", {})
    gh_238_evidence_fragments = (
        gh_238_merge_commit[:7] if isinstance(gh_238_merge_commit, str) else "",
        *(
            str(gh_238_run_ids.get(name, ""))
            for name in ("prometheus_ci", "security_audit", "pages")
        ),
    )

    for relative in PUBLIC_FILES:
        path = root / relative
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            errors.append(f"{relative}: missing public status surface")
            continue
        for fragment in REQUIRED_FRAGMENTS.get(relative, ()):
            if fragment.casefold() not in text.casefold():
                errors.append(f"{relative}: required status boundary missing")
        if relative in GH234_PUBLIC_FILES:
            for fragment in gh_234_evidence_fragments:
                if not fragment or fragment not in text:
                    errors.append(f"{relative}: GH-234 exact-main evidence missing")
                    break
        if relative in GH238_PUBLIC_FILES:
            normalized_text = " ".join(text.split()).casefold()
            for fragment in (
                "GH-238",
                "No real GH-238 remote run has occurred",
                "no GH-238 evidence record exists",
            ):
                if fragment.casefold() not in normalized_text:
                    errors.append(
                        f"{relative}: GH-238 repository-only boundary missing"
                    )
                    break
            for fragment in gh_238_evidence_fragments:
                if not fragment or fragment not in text:
                    errors.append(f"{relative}: GH-238 exact-main evidence missing")
                    break
        if relative in GH242_PUBLIC_FILES and "GH-242" not in text:
            errors.append(f"{relative}: GH-242 membership-bound status missing")
        if relative.suffix == ".html" and "5cd13bf" not in text:
            errors.append(f"{relative}: exact reconciliation baseline missing")
        for category in find_banned_claims(text):
            errors.append(f"{relative}: prohibited claim category {category}")
        if relative.suffix == ".html":
            errors.extend(f"{relative}: {item}" for item in validate_json_ld(text))
    return errors


def main() -> int:
    """Run the repository check and print data-minimal diagnostics."""
    root = Path(__file__).resolve().parents[1]
    errors = verify(root)
    if errors:
        for error in errors:
            print(f"ERROR: {error}")
        return 1
    print(f"Public claim consistency PASS ({len(PUBLIC_FILES)} synchronized surfaces).")
    return 0


if __name__ == "__main__":
    sys.exit(main())

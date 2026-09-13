#!/usr/bin/env python3
"""Fail closed when public Prometheus status claims drift from evidence."""

from __future__ import annotations

import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

STATUS_PATH = Path("docs/evidence/public-claim-status-2026-08-14.json")
SITEMAP_PATH = Path("sitemap.xml")
AUDIT_BASELINE_DATE = "2026-08-14"
LATEST_PROJECT_UPDATE = "2026-09-13"
GH253_AS_OF = "2026-09-06"
GH253_MERGE_COMMIT = "5920cb4bb737376977f762beb0d5e3108519c7a0"
GH253_EXACT_MAIN_RUNS = {
    "prometheus_ci": 34031999904,
    "security_audit": 34031999907,
    "pages": 34031999575,
}
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

LATEST_METADATA_FRAGMENTS = {
    Path(
        "README.md"
    ): "Public project status was reviewed through 2026-09-13. The immutable claim-audit baseline remains 2026-08-14",
    Path(
        "WHITEPAPER.md"
    ): "Project status reviewed through 2026-09-13; immutable public claim-audit baseline: 2026-08-14",
    Path(
        "docs/roadmap.md"
    ): "Project status reviewed through 2026-09-13. The immutable public claim-audit baseline remains 2026-08-14",
    Path(
        "docs/faq.md"
    ): "Project status reviewed through 2026-09-13; immutable public claim-audit baseline: 2026-08-14",
    Path(
        "memory/STATUS.md"
    ): "Latest project/public status review: 2026-09-13. The section date and exact evidence below remain the immutable 2026-08-14 audit baseline",
    Path(
        "index.html"
    ): 'Project status reviewed 2026-09-13 · immutable <a href="docs/claim-audit-2026-08-14.md">claim-audit baseline</a> 2026-08-14',
    Path(
        "roadmap.html"
    ): 'Project status reviewed 2026-09-13 · immutable <a href="docs/claim-audit-2026-08-14.md">claim-audit baseline</a> 2026-08-14',
    Path(
        "whitepaper.html"
    ): 'Project status reviewed 2026-09-13 · immutable <a href="docs/claim-audit-2026-08-14.md">claim-audit baseline</a> 2026-08-14',
    Path(
        "faq.html"
    ): 'Project status reviewed 2026-09-13 · immutable <a href="docs/claim-audit-2026-08-14.md">claim-audit baseline</a> 2026-08-14',
    Path(
        "guardian-economics.html"
    ): 'Project status reviewed 2026-09-13 · immutable <a href="docs/claim-audit-2026-08-14.md">claim-audit baseline</a> 2026-08-14',
    Path(
        "llms.txt"
    ): "project status reviewed through 2026-09-13; immutable dated audit baseline remains 2026-08-14",
}

STALE_METADATA_PATTERNS = (
    re.compile(r"Status reconciled 2026-08-14", re.I),
    re.compile(r"Current repository status refreshed 2026-08-23", re.I),
    re.compile(r"Last Updated: 2026-08-31", re.I),
    re.compile(r"Current public status \(reviewed 2026-09-01", re.I),
    re.compile(
        r"(?:Public )?[Pp]roject status (?:was )?reviewed through 2026-09-06", re.I
    ),
    re.compile(r"Current public status \(reviewed 2026-09-06", re.I),
    re.compile(r"Deploy verification active", re.I),
)

CURRENT_PUBLIC_URLS = {
    "https://neabouli.github.io/prometheus-/",
    "https://neabouli.github.io/prometheus-/whitepaper.html",
    "https://neabouli.github.io/prometheus-/faq.html",
    "https://neabouli.github.io/prometheus-/roadmap.html",
    "https://neabouli.github.io/prometheus-/guardian-economics.html",
}

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

GH246_PUBLIC_FILES = GH242_PUBLIC_FILES

GH246_REQUIRED_FRAGMENTS = {
    Path("README.md"): (
        "no signer/private-key path",
        "no external or decentralized membership authority",
        "production trust",
    ),
    Path("WHITEPAPER.md"): (
        "contains no signing/private-key API",
        "does not establish external authority",
        "deployment, or production trust",
    ),
    Path("docs/roadmap.md"): (
        "owner-pinned public verification only",
        "external/decentralized authority",
        "production trust remain open",
    ),
    Path("docs/faq.md"): (
        "does not answer who should control the pinned public authority key",
        "decentralized or production operation",
    ),
    Path("memory/STATUS.md"): (
        "Authority: public verification only; no signer/private-key API",
        "external/decentralized authority",
        "production trust",
    ),
    Path("index.html"): (
        "owner-only durable current source",
        "no external authority",
        "deployment or production claim",
    ),
    Path("roadmap.html"): (
        "owner-pinned public verification only",
        "not external authority",
        "multi-host or production trust",
    ),
    Path("whitepaper.html"): (
        "contains no signer/private-key path",
        "proves no external authority",
        "deployment or production trust",
    ),
    Path("faq.html"): (
        "does not establish who should control the pinned key",
        "decentralized or production operation",
    ),
    Path("llms.txt"): (
        "no signer/private-key path",
        "no external/decentralized authority",
        "deployment or production trust",
    ),
    Path("modules/guardian-node/README.md"): (
        "There is no signing/private-key API",
        "external or decentralized authority",
        "deployment, or production claim",
    ),
}

GH246_PROHIBITED_CLAIMS = (
    re.compile(
        r"GH-246[^\n]{0,500}(?:provides|establishes|proves|uses|enables|"
        r"authorizes|confers) (?:an? )?"
        r"(?:external|decentralized) (?:membership )?authority",
        re.I,
    ),
    re.compile(
        r"GH-246[^\n]{0,500}(?:is|provides|establishes|proves|supports|enables|"
        r"authorizes|confers) "
        r"(?:now )?(?:production[- ]ready|production support|production authority)",
        re.I,
    ),
)

GH253_PUBLIC_FILES = GH242_PUBLIC_FILES + (Path("guardian-economics.html"),)

GH253_REQUIRED_FRAGMENTS = {
    path: (
        "owner-local",
        "real-world key ownership",
        "production",
    )
    for path in GH253_PUBLIC_FILES
}

GH253_PROHIBITED_CLAIMS = (
    re.compile(
        r"GH-253[^\n]{0,600}(?:proves|establishes|provides|confers|authorizes|"
        r"enables|supports) "
        r"(?:real-world key ownership|(?:an? )?(?:external|decentralized) "
        r"(?:membership )?authority|Sybil resistance|L1 attestation)",
        re.I,
    ),
    re.compile(
        r"GH-253[^\n]{0,600}(?:is|makes Prometheus|provides) "
        r"(?:production[- ]ready|production authority|production support)",
        re.I,
    ),
    re.compile(
        r"GH-253[^\n]{0,600}(?:enables|supports) "
        r"(?:production authority|production support)",
        re.I,
    ),
)

GH258_PUBLIC_FILES = (
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
    Path("modules/client/README.md"),
)

GH258_REQUIRED_FRAGMENTS = (
    "GH-258",
    "GH-261",
    "unauthorized compute conscription",
    "reliab",
    "no real-time endpoint sensor",
    "operator-confirmed",
    "reversible",
    "limited automation",
)

GH258_ACTION_PATTERNS = (
    ("process termination", r"process termination"),
    ("quarantine", r"quarantine"),
    ("firewall mutation", r"firewall (?:changes?|mutation)"),
    ("credential rotation", r"credential rotation"),
    ("remote commands", r"remote commands?(?: execution)?"),
    ("deletion", r"deletion"),
    ("host isolation", r"host isolation"),
)

GH258_ACTION_PATTERN = (
    "(?:" + "|".join(pattern for _, pattern in GH258_ACTION_PATTERNS) + ")"
)

GH258_NEGATIVE_ACTION_PATTERNS = tuple(
    (
        label,
        re.compile(
            rf"(?:{pattern}[^.\n]{{0,240}}(?:disabled and unauthorized|not authorized)|"
            rf"(?:disabled and unauthorized|not authorized)[^.\n]{{0,240}}{pattern})",
            re.I,
        ),
    )
    for label, pattern in GH258_ACTION_PATTERNS
)

GH258_AUTOMATIC_ACTION_FIELDS = (
    "automatic_process_termination_authorized",
    "automatic_quarantine_authorized",
    "automatic_firewall_mutation_authorized",
    "automatic_credential_rotation_authorized",
    "automatic_remote_commands_authorized",
    "automatic_deletion_authorized",
    "automatic_host_isolation_authorized",
)

GH258_PROHIBITED_CLAIMS = (
    re.compile(
        r"GH-(?:258|261)[^.\n]{0,600}(?:detects|prevents|blocks|stops) "
        r"[^.\n]{0,160}(?:unauthorized )?(?:distributed )?"
        r"(?:compute|resource) conscription",
        re.I,
    ),
    re.compile(
        r"GH-(?:258|261)[^.\n]{0,600}(?:unauthorized )?(?:distributed )?"
        r"(?:compute|resource) conscription (?:detection )?(?:is|are) "
        r"(?:now )?(?:active|enabled|implemented|operational|production[- ]ready)",
        re.I,
    ),
    re.compile(
        r"GH-(?:258|261)[^\n]{0,600}(?:authorizes|allows|enables|provides|supports|"
        r"implements|performs) (?:an? )?(?:automatic(?:ally)? )?"
        + GH258_ACTION_PATTERN,
        re.I,
    ),
    re.compile(
        r"GH-(?:258|261)[^\n]{0,600}"
        + GH258_ACTION_PATTERN
        + r" (?:is|are) (?:now )?(?:active|authorized|enabled|implemented)",
        re.I,
    ),
    re.compile(
        r"GH-(?:258|261)[^\n]{0,600}(?:is|provides|implements|delivers|includes) "
        r"(?:now )?(?:production[- ]ready|production authority|"
        r"an? real-time endpoint sensor|an? response engine)",
        re.I,
    ),
    re.compile(
        r"GH-(?:258|261)[^\n]{0,600}(?:reliably )?(?:attributes|identifies|proves) "
        r"(?:an? )?(?:AI|AGI|actor|intent)",
        re.I,
    ),
    re.compile(
        r"GH-(?:258|261)[^\n]{0,600}(?:(?:AI|AGI|actor|intent) attribution|"
        r"attribution (?:to )?(?:AI|AGI|an? actor|intent)) "
        r"(?:is|are) (?:now )?reliable",
        re.I,
    ),
)

GH264_PUBLIC_FILES = GH258_PUBLIC_FILES + (
    Path("docs/endpoint-observation-v1.md"),
    Path("modules/threat-hint/README.md"),
    Path("modules/guardian-node/README.md"),
)

GH264_REQUIRED_FRAGMENTS = (
    "GH-264",
    "observe-only",
    "response",
    "production",
)

GH264_CAPABILITY_PATTERN = (
    r"(?:endpoint (?:data |telemetry )?collection|host telemetry collection|"
    r"(?:endpoint |OS )?sensor|detection|correlation|warning|transport|"
    r"response(?: authority| engine)?|containment|automation)\b"
)

GH264_PROHIBITED_CLAIMS = (
    re.compile(
        r"GH-264[^.\n]{0,700}(?:(?:"
        + GH264_CAPABILITY_PATTERN
        + r") (?:is|are|was|were|has been|have been) (?:now )?"
        r"(?:provided|implemented|enabled|authorized|supported|delivered|"
        r"activated|active|operational)|"
        r"(?<!not )(?<!never )(?<!cannot )(?<!can't )(?<!doesn't )"
        r"(?<!not currently )"
        r"(?:provides?|provided|enables?|enabled|authorizes?|authorized|"
        r"supports?|supported|implements?|implemented|delivers?|delivered|"
        r"activates?|activated) (?:now )?(?:an? |the )?"
        + GH264_CAPABILITY_PATTERN
        + r")",
        re.I,
    ),
    re.compile(
        r"(?:an? |the )?"
        + GH264_CAPABILITY_PATTERN
        + r" (?:is|are|was|were|has been|have been) (?:now )?"
        r"(?:provided|enabled|authorized|supported|implemented|delivered|"
        r"activated|active|operational) (?:by|through|via) GH-264",
        re.I,
    ),
    re.compile(
        r"GH-264[^.\n]{0,700}(?:is|makes Prometheus) "
        r"(?:production[- ]ready|a production endpoint detector)",
        re.I,
    ),
    re.compile(
        r"GH-264[^.\n]{0,700}(?:proves|detects|attributes) "
        r"[^.\n]{0,160}(?:maliciousness|AI|AGI|actor|intent)",
        re.I,
    ),
)


def has_gh264_boundary(text: str) -> bool:
    """Require the safety terms in one bounded GH-264 status section."""
    normalized = " ".join(text.split()).casefold()
    marker = "gh-264"
    offset = 0
    while (position := normalized.find(marker, offset)) >= 0:
        section = normalized[position : position + 1_800]
        if all(fragment.casefold() in section for fragment in GH264_REQUIRED_FRAGMENTS):
            return True
        offset = position + len(marker)
    return False


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
    latest_update_value = data.get("latest_project_update", {})
    if not isinstance(latest_update_value, dict):
        errors.append("latest project update must be an object")
        latest_update: dict[str, Any] = {}
    else:
        latest_update = latest_update_value
    if data.get("as_of") != AUDIT_BASELINE_DATE:
        errors.append("claim-audit baseline date must remain immutable")
    if latest_update != {
        "as_of": LATEST_PROJECT_UPDATE,
        "audit_baseline_as_of": AUDIT_BASELINE_DATE,
        "classification": "post_audit_updates_recorded_below",
        "production_ready": False,
    }:
        errors.append("latest project update metadata is invalid")
    gh_234 = data.get("post_audit_updates", {}).get("gh_234", {})
    gh_238 = data.get("post_audit_updates", {}).get("gh_238", {})
    gh_242 = data.get("post_audit_updates", {}).get("gh_242", {})
    gh_246_value = data.get("post_audit_updates", {}).get("gh_246", {})
    if not isinstance(gh_246_value, dict):
        errors.append("GH-246 machine status record must be an object")
        gh_246: dict[str, Any] = {}
    else:
        gh_246 = gh_246_value
    gh_253_value = data.get("post_audit_updates", {}).get("gh_253", {})
    if not isinstance(gh_253_value, dict):
        errors.append("GH-253 machine status record must be an object")
        gh_253: dict[str, Any] = {}
    else:
        gh_253 = gh_253_value
    gh_258_value = data.get("post_audit_updates", {}).get("gh_258", {})
    if not isinstance(gh_258_value, dict):
        errors.append("GH-258 machine status record must be an object")
        gh_258: dict[str, Any] = {}
    else:
        gh_258 = gh_258_value
    gh_264_value = data.get("post_audit_updates", {}).get("gh_264", {})
    if not isinstance(gh_264_value, dict):
        errors.append("GH-264 machine status must be an object")
        gh_264: dict[str, Any] = {}
    else:
        gh_264 = gh_264_value
    endpoint_value = classes.get("endpoint_detection_and_response", {})
    if not isinstance(endpoint_value, dict):
        errors.append("endpoint detection status must be an object")
        endpoint: dict[str, Any] = {}
    else:
        endpoint = endpoint_value

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
    if gh_242.get("issue") != 242 or gh_242.get("pull_request") != 243:
        errors.append("GH-242 machine status identity is invalid")
    if (
        gh_242.get("status") != "merged_and_exact_main_verified_repository_boundary"
        or gh_242.get("classification") != "owner_local_membership_bound_ballot_session"
        or gh_242.get("canonical_source_loaded_once") is not True
    ):
        errors.append("GH-242 repository boundary classification is invalid")
    gh_242_merge_commit = gh_242.get("merge_commit")
    if (
        not isinstance(gh_242_merge_commit, str)
        or re.fullmatch(r"[0-9a-f]{40}", gh_242_merge_commit) is None
    ):
        errors.append("GH-242 merge commit must be one full lowercase SHA-1")
    gh_242_exact_main_runs = gh_242.get("exact_main_runs", {})
    if set(gh_242_exact_main_runs) != {"prometheus_ci", "security_audit", "pages"}:
        errors.append("GH-242 exact-main run evidence is incomplete")
    elif not all(
        type(run_id) is int and run_id > 0 for run_id in gh_242_exact_main_runs.values()
    ):
        errors.append("GH-242 exact-main run IDs must be positive integers")
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
    if gh_246.get("issue") != 246 or gh_246.get("pull_request") != 247:
        errors.append("GH-246 machine status identity is invalid")
    if (
        gh_246.get("status") != "merged_and_exact_main_verified_owner_local_continuity"
        or gh_246.get("classification") != "owner_local_signed_membership_continuity"
        or gh_246.get("public_bip340_verification") is not True
        or gh_246.get("durable_current_source") is not True
        or gh_246.get("ballot_current_source_lock") is not True
    ):
        errors.append("GH-246 local repository boundary is invalid")
    gh_246_merge_commit = gh_246.get("merge_commit")
    if (
        not isinstance(gh_246_merge_commit, str)
        or re.fullmatch(r"[0-9a-f]{40}", gh_246_merge_commit) is None
    ):
        errors.append("GH-246 merge commit must be one full lowercase SHA-1")
    gh_246_exact_main_runs = gh_246.get("exact_main_runs", {})
    if not isinstance(gh_246_exact_main_runs, dict) or set(gh_246_exact_main_runs) != {
        "prometheus_ci",
        "security_audit",
        "pages",
    }:
        errors.append("GH-246 exact-main run evidence is incomplete")
    elif not all(
        type(run_id) is int and run_id > 0 for run_id in gh_246_exact_main_runs.values()
    ):
        errors.append("GH-246 exact-main run IDs must be positive integers")
    for field in (
        "signing_or_private_key_api",
        "external_membership_authority",
        "key_ownership_or_rotation_proven",
        "sybil_resistance_proven",
        "on_chain_attestation",
        "public_multihost_operation",
        "production_authority",
    ):
        if gh_246.get(field) is not False:
            errors.append(f"GH-246 {field} must remain false")
    if (
        gh_253.get("as_of") != GH253_AS_OF
        or gh_253.get("issue") != 253
        or gh_253.get("pull_request") != 254
        or gh_253.get("status")
        != "merged_and_exact_main_verified_owner_local_authority_succession"
        or gh_253.get("classification")
        != "owner_local_dual_signed_authority_succession"
    ):
        errors.append("GH-253 exact-main identity or status is invalid")
    gh_253_merge_commit = gh_253.get("merge_commit")
    if (
        not isinstance(gh_253_merge_commit, str)
        or re.fullmatch(r"[0-9a-f]{40}", gh_253_merge_commit) is None
        or gh_253_merge_commit != GH253_MERGE_COMMIT
    ):
        errors.append("GH-253 merge commit evidence is invalid")
    gh_253_exact_main_runs = gh_253.get("exact_main_runs", {})
    if not isinstance(gh_253_exact_main_runs, dict) or set(gh_253_exact_main_runs) != {
        "prometheus_ci",
        "security_audit",
        "pages",
    }:
        errors.append("GH-253 exact-main run evidence is incomplete")
    elif not all(
        type(run_id) is int and run_id > 0 for run_id in gh_253_exact_main_runs.values()
    ):
        errors.append("GH-253 exact-main run IDs must be positive integers")
    elif gh_253_exact_main_runs != GH253_EXACT_MAIN_RUNS:
        errors.append("GH-253 exact-main run evidence is invalid")
    for field in (
        "dual_bip340_authorization_and_possession",
        "durable_current_authority",
        "schema_v1_to_v2_migration",
    ):
        if gh_253.get(field) is not True:
            errors.append(f"GH-253 {field} must be true")
    for field in (
        "membership_transition_formula_changed",
        "signing_or_private_key_api",
        "real_world_key_ownership_proven",
        "external_or_decentralized_authority",
        "sybil_resistance_proven",
        "on_chain_attestation",
        "public_multihost_operation",
        "deployment_or_production_authority",
    ):
        if gh_253.get(field) is not False:
            errors.append(f"GH-253 {field} must remain false")
    if (
        gh_258.get("as_of") != LATEST_PROJECT_UPDATE
        or gh_258.get("issue") != 258
        or gh_258.get("follow_up_issue") != 261
        or gh_258.get("status") != "planned_documentation_only"
        or gh_258.get("classification")
        != "behavior_based_endpoint_detection_and_safe_response_target"
        or gh_258.get("resource_conscription_scope")
        != ["endpoints", "accelerators", "servers", "data_center_capacity"]
        or gh_258.get("stages")
        != [
            "observe_only",
            "warn_only",
            "operator_confirmed_reversible_containment",
            "separately_approved_limited_automation",
        ]
    ):
        errors.append("GH-258 planned status or capability ladder is invalid")
    for field in (
        "real_time_endpoint_sensor",
        "response_engine",
        "resource_conscription_detection_implemented",
        "ai_or_actor_attribution_proven",
        "automatic_endpoint_actions_authorized",
        *GH258_AUTOMATIC_ACTION_FIELDS,
        "production_authority",
    ):
        if gh_258.get(field) is not False:
            errors.append(f"GH-258 {field} must remain false")
    if (
        gh_264.get("as_of") != LATEST_PROJECT_UPDATE
        or gh_264.get("issue") != 264
        or gh_264.get("status") != "repository_candidate_implemented_and_locally_tested"
        or gh_264.get("classification") != "canonical_observe_only_endpoint_statement"
        or gh_264.get("schema_version") != 1
        or gh_264.get("rust_python_shared_vectors") is not True
        or gh_264.get("closed_domains") != 7
        or gh_264.get("closed_signals") != 15
        or gh_264.get("max_canonical_bytes") != 512
    ):
        errors.append("GH-264 observe-only schema status is invalid")
    for field in (
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
    ):
        if gh_264.get(field) is not False:
            errors.append(f"GH-264 {field} must remain false")
    if (
        endpoint.get("status") != "observe_only_schema_candidate_no_sensor"
        or endpoint.get("detection_basis")
        != "observable_behavior_not_ai_actor_or_intent_attribution"
        or endpoint.get("resource_conscription_detection") != "planned_only"
        or endpoint.get("canonical_observation_statement")
        != "implemented_and_locally_tested"
        or endpoint.get("endpoint_collection") != "not_implemented"
    ):
        errors.append(
            "endpoint detection must preserve observe-only schema and planned detection boundaries"
        )
    for field in (
        "real_time_sensor_implemented",
        "response_engine_implemented",
        "resource_conscription_detection_implemented",
        "automatic_endpoint_actions_authorized",
        *GH258_AUTOMATIC_ACTION_FIELDS,
    ):
        if endpoint.get(field) is not False:
            errors.append(f"endpoint detection {field} must remain false")
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


def validate_json_ld_update_date(text: str) -> list[str]:
    """Require one valid top-level JSON-LD object with the current update date."""
    bodies = re.findall(
        r'<script[^>]+type=["\']application/ld\+json["\'][^>]*>(.*?)</script>',
        text,
        flags=re.I | re.S,
    )
    parsed: list[Any] = []
    for body in bodies:
        try:
            parsed.append(json.loads(body))
        except json.JSONDecodeError:
            continue
    dated_objects = [
        item for item in parsed if isinstance(item, dict) and "dateModified" in item
    ]
    if not any(
        isinstance(item, dict) and item.get("dateModified") == LATEST_PROJECT_UPDATE
        for item in dated_objects
    ):
        return ["current JSON-LD dateModified missing"]
    if any(item.get("dateModified") != LATEST_PROJECT_UPDATE for item in dated_objects):
        return ["stale JSON-LD dateModified present"]
    return []


def validate_sitemap(path: Path) -> list[str]:
    """Validate current public-page lastmod values with an XML parser."""
    try:
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError):
        return ["missing or invalid sitemap"]
    namespace = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}
    entries: dict[str, str] = {}
    for url in root.findall("sm:url", namespace):
        location = url.findtext("sm:loc", default="", namespaces=namespace)
        last_modified = url.findtext("sm:lastmod", default="", namespaces=namespace)
        entries[location] = last_modified
    return [
        f"current public URL has stale or missing lastmod: {url}"
        for url in sorted(CURRENT_PUBLIC_URLS)
        if entries.get(url) != LATEST_PROJECT_UPDATE
    ]


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
    gh_242 = status.get("post_audit_updates", {}).get("gh_242", {})
    gh_246_value = status.get("post_audit_updates", {}).get("gh_246", {})
    gh_246 = gh_246_value if isinstance(gh_246_value, dict) else {}
    gh_246_merge_commit = gh_246.get("merge_commit", "")
    gh_246_run_ids_value = gh_246.get("exact_main_runs", {})
    gh_246_run_ids = (
        gh_246_run_ids_value if isinstance(gh_246_run_ids_value, dict) else {}
    )
    gh_246_evidence = (
        "GH-246",
        f"PR #{gh_246.get('pull_request', '')}",
        gh_246_merge_commit if isinstance(gh_246_merge_commit, str) else "",
        *(
            str(gh_246_run_ids.get(name, ""))
            for name in ("prometheus_ci", "security_audit", "pages")
        ),
    )
    gh_246_claims = (
        GH246_REQUIRED_FRAGMENTS
        if gh_246.get("status")
        == "merged_and_exact_main_verified_owner_local_continuity"
        and gh_246.get("classification") == "owner_local_signed_membership_continuity"
        else {}
    )
    gh_253_value = status.get("post_audit_updates", {}).get("gh_253", {})
    gh_253 = gh_253_value if isinstance(gh_253_value, dict) else {}
    gh_253_exact_main = (
        gh_253.get("status")
        == "merged_and_exact_main_verified_owner_local_authority_succession"
        and gh_253.get("classification")
        == "owner_local_dual_signed_authority_succession"
    )
    gh_253_merge_commit = gh_253.get("merge_commit", "")
    gh_253_run_ids_value = gh_253.get("exact_main_runs", {})
    gh_253_run_ids = (
        gh_253_run_ids_value if isinstance(gh_253_run_ids_value, dict) else {}
    )
    gh_253_evidence = (
        "GH-253",
        f"PR #{gh_253.get('pull_request', '')}",
        gh_253_merge_commit if isinstance(gh_253_merge_commit, str) else "",
        *(
            str(gh_253_run_ids.get(name, ""))
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
        latest_metadata = LATEST_METADATA_FRAGMENTS.get(relative)
        normalized_metadata = " ".join(text.split()).casefold()
        if (
            latest_metadata
            and " ".join(latest_metadata.split()).casefold() not in normalized_metadata
        ):
            errors.append(f"{relative}: latest project/audit metadata missing")
        if latest_metadata and any(
            pattern.search(text) for pattern in STALE_METADATA_PATTERNS
        ):
            errors.append(f"{relative}: stale project metadata present")
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
        if relative in GH242_PUBLIC_FILES:
            normalized_text = " ".join(text.split())
            gh_242_evidence = (
                "GH-242",
                f"PR #{gh_242.get('pull_request', '')}",
                str(gh_242.get("merge_commit", "")),
                *(str(run_id) for run_id in gh_242.get("exact_main_runs", {}).values()),
            )
            if not all(
                fragment and fragment in normalized_text for fragment in gh_242_evidence
            ):
                errors.append(f"{relative}: GH-242 exact-main evidence missing")
        if relative in GH246_PUBLIC_FILES:
            normalized_text = " ".join(text.split()).casefold()
            for fragment in gh_246_claims.get(relative, ()):
                if fragment.casefold() not in normalized_text:
                    errors.append(
                        f"{relative}: GH-246 canonical local boundary missing"
                    )
                    break
            if not all(
                fragment and fragment.casefold() in normalized_text
                for fragment in gh_246_evidence
            ):
                errors.append(f"{relative}: GH-246 exact-main evidence missing")
            if any(pattern.search(text) for pattern in GH246_PROHIBITED_CLAIMS):
                errors.append(f"{relative}: GH-246 authority or production claim drift")
        if relative in GH253_PUBLIC_FILES:
            normalized_text = " ".join(text.split()).casefold()
            if gh_253_exact_main:
                for fragment in GH253_REQUIRED_FRAGMENTS.get(relative, ()):
                    if fragment.casefold() not in normalized_text:
                        errors.append(
                            f"{relative}: GH-253 owner-local boundary missing"
                        )
                        break
                if not all(
                    fragment and fragment.casefold() in normalized_text
                    for fragment in gh_253_evidence
                ):
                    errors.append(f"{relative}: GH-253 exact-main evidence missing")
            if any(
                pattern.search(normalized_text) for pattern in GH253_PROHIBITED_CLAIMS
            ):
                errors.append(f"{relative}: GH-253 authority or production claim drift")
        if relative in GH258_PUBLIC_FILES:
            normalized_text = " ".join(text.split()).casefold()
            if not all(
                fragment.casefold() in normalized_text
                for fragment in GH258_REQUIRED_FRAGMENTS
            ):
                errors.append(f"{relative}: GH-258 planned safety boundary missing")
            for action, pattern in GH258_NEGATIVE_ACTION_PATTERNS:
                if not pattern.search(normalized_text):
                    errors.append(
                        f"{relative}: GH-258 {action} negative-state boundary missing"
                    )
            if any(
                pattern.search(normalized_text) for pattern in GH258_PROHIBITED_CLAIMS
            ):
                errors.append(
                    f"{relative}: GH-258 authority or attribution claim drift"
                )
        if relative in GH264_PUBLIC_FILES:
            normalized_text = " ".join(text.split()).casefold()
            if not has_gh264_boundary(text):
                errors.append(f"{relative}: GH-264 observe-only boundary missing")
            if any(
                pattern.search(normalized_text) for pattern in GH264_PROHIBITED_CLAIMS
            ):
                errors.append(f"{relative}: GH-264 capability claim drift")
        if relative.suffix == ".html" and "5cd13bf" not in text:
            errors.append(f"{relative}: exact reconciliation baseline missing")
        for category in find_banned_claims(text):
            errors.append(f"{relative}: prohibited claim category {category}")
        if relative.suffix == ".html":
            errors.extend(f"{relative}: {item}" for item in validate_json_ld(text))
            errors.extend(
                f"{relative}: {item}" for item in validate_json_ld_update_date(text)
            )
    errors.extend(
        f"{SITEMAP_PATH}: {item}" for item in validate_sitemap(root / SITEMAP_PATH)
    )
    for relative in set(GH264_PUBLIC_FILES) - set(PUBLIC_FILES):
        path = root / relative
        if not path.exists():
            errors.append(f"{relative}: GH-264 public surface missing")
            continue
        text = path.read_text(encoding="utf-8")
        normalized_text = " ".join(text.split()).casefold()
        if not has_gh264_boundary(text):
            errors.append(f"{relative}: GH-264 observe-only boundary missing")
        if any(pattern.search(normalized_text) for pattern in GH264_PROHIBITED_CLAIMS):
            errors.append(f"{relative}: GH-264 capability claim drift")
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

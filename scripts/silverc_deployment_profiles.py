#!/usr/bin/env python3
"""Closed deployment profiles for full releases and the testnet-10 H-001 canary."""

from __future__ import annotations

import json
from hashlib import sha256
from typing import Any

FULL_PROFILE = "full"
H001_CANARY_PROFILE = "testnet-10-validator-staking-h001"
DEPLOYMENT_PROFILES = (FULL_PROFILE, H001_CANARY_PROFILE)
PUBLIC_RESOLVER_URL = "kaspa-resolver://public"
H001_CONTRACT = "ValidatorStakingH001"
CANARY_SCOPE_NOTICE = (
    "the H-001 canary proves one testnet-10 genesis path only and cannot authorize "
    "full release, production status, or metrics-oracle readiness"
)


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def manifest_sha256(manifest: dict[str, Any]) -> str:
    return sha256(canonical_json_bytes(manifest)).hexdigest()


def expected_profile(name: str, manifest: dict[str, Any]) -> dict[str, Any]:
    manifest_names = [entry["contract_name"] for entry in manifest["fixtures"]]
    common = {
        "name": name,
        "full_bundle_fixture_count": manifest["fixture_count"],
        "full_bundle_manifest_sha256": manifest_sha256(manifest),
    }
    if name == FULL_PROFILE:
        return {
            **common,
            "kind": "full",
            "network_id": "operator-selected",
            "selected_contracts": manifest_names,
        }
    if name == H001_CANARY_PROFILE:
        if H001_CONTRACT not in manifest_names:
            raise ValueError(f"deployment profile requires {H001_CONTRACT} in release manifest")
        return {
            **common,
            "kind": "canary",
            "network_id": "testnet-10",
            "selected_contracts": [H001_CONTRACT],
        }
    raise ValueError(f"unsupported deployment profile: {name!r}")


def validate_profile_document(
    profile: Any,
    manifest: dict[str, Any],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    if not isinstance(profile, dict):
        raise ValueError("deployment_profile: expected object")
    name = profile.get("name")
    if name not in DEPLOYMENT_PROFILES:
        raise ValueError("deployment_profile.name: unsupported profile")
    expected = expected_profile(name, manifest)
    if profile != expected:
        raise ValueError("deployment_profile: profile or release-manifest binding mismatch")
    selected = set(expected["selected_contracts"])
    entries = [entry for entry in manifest["fixtures"] if entry["contract_name"] in selected]
    if [entry["contract_name"] for entry in entries] != expected["selected_contracts"]:
        raise ValueError("deployment_profile.selected_contracts: manifest order mismatch")
    return expected, entries


def validate_profile_inputs(
    *,
    profile_name: str,
    network: str,
    rpc_url: str,
    metrics_oracle_pubkey: str | None,
) -> None:
    if profile_name == FULL_PROFILE:
        if not metrics_oracle_pubkey:
            raise ValueError("--metrics-oracle-pubkey is required for --deployment-profile full")
        return
    if profile_name != H001_CANARY_PROFILE:
        raise ValueError(f"unsupported deployment profile: {profile_name!r}")
    if network != "testnet":
        raise ValueError("the H-001 canary deployment profile is restricted to --network testnet")
    if rpc_url != PUBLIC_RESOLVER_URL:
        raise ValueError(
            "the H-001 canary deployment profile requires --rpc-url kaspa-resolver://public"
        )
    if metrics_oracle_pubkey is not None:
        raise ValueError("--metrics-oracle-pubkey is forbidden for the H-001 canary deployment profile")


def is_canary(profile: dict[str, Any]) -> bool:
    return profile.get("name") == H001_CANARY_PROFILE and profile.get("kind") == "canary"


def request_status(profile: dict[str, Any]) -> str:
    return (
        "CANARY_READY_FOR_KEYLESS_GENESIS_OPERATOR"
        if is_canary(profile)
        else "READY_FOR_KEYLESS_GENESIS_OPERATOR"
    )


def request_set_status(profile: dict[str, Any]) -> str:
    return (
        "CANARY_REQUEST_READY_FOR_KEYLESS_GENESIS_OPERATOR"
        if is_canary(profile)
        else "REQUESTS_READY_FOR_KEYLESS_GENESIS_OPERATOR"
    )


def request_verification_status(profile: dict[str, Any]) -> str:
    return "CANARY_DEPLOY_REQUEST_VERIFIED" if is_canary(profile) else "DEPLOY_REQUEST_SET_VERIFIED"


def procedure_status(profile: dict[str, Any]) -> str:
    return (
        "CANARY_READY_FOR_KEYLESS_GENESIS_OPERATION"
        if is_canary(profile)
        else "READY_FOR_KEYLESS_GENESIS_OPERATION"
    )


def receipt_verification_status(profile: dict[str, Any], provenance_type: str) -> str:
    if is_canary(profile):
        return "CANARY_RECEIPTS_VERIFIED" if provenance_type == "operator_record" else "CANARY_CI_FIXTURE_VALID"
    return "READY_FOR_STATUS_RECORDING" if provenance_type == "operator_record" else "CI_FIXTURE_VALID"


def receipt_import_status(profile: dict[str, Any]) -> str:
    return "CANARY_OPERATOR_RECEIPTS_VERIFIED" if is_canary(profile) else "OPERATOR_RECEIPTS_READY_FOR_STATUS_STAGING"


def evidence_status(profile: dict[str, Any]) -> str:
    return (
        "PUBLIC_CANARY_DEPLOY_EVIDENCE_VERIFIED"
        if is_canary(profile)
        else "PUBLIC_DEPLOY_RECEIPT_EVIDENCE_VERIFIED"
    )


def status_draft_status(profile: dict[str, Any]) -> str:
    return (
        "READY_FOR_MANUAL_CANARY_STATUS_UPDATE"
        if is_canary(profile)
        else "READY_FOR_MANUAL_STATUS_UPDATE"
    )

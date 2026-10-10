#!/usr/bin/env python3
"""Closed registry of silverc release bundles (bundle-v2 profile separation).

Every release tool selects its bundle explicitly with the required ``--bundle``
argument; there is no default, fallback or auto-detection. A bundle fixes the
contract sources, constructor fixtures, ABI expectations and the exact release
manifest (pinned SHA-256 of its canonical JSON).

- ``h001-v1``: the immutable historical bundle of the confirmed, non-promotable
  H-001 Testnet-10 canary. Its sources and fixtures are frozen reproduction
  material under ``modules/contracts/silverc/bundles/h001-v1/`` (not a second
  maintained contract line); every file is pinned in ``provenance.json``.
- ``v2-draft``: the proposed bundle v2 from the current fixture tree. It is not
  promotable: receipts, status, evidence, operator procedures and handoffs are
  refused, and the Rust deployer pins only the v1 manifest, so v2 requests fail
  before any signing request is exported.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
CONTRACT_DIR = ROOT / "modules" / "contracts" / "silverc"
RECORDED_SOURCE_DIR = "modules/contracts/silverc"
H001_V1_DIR = CONTRACT_DIR / "bundles" / "h001-v1"

H001_V1 = "h001-v1"
V2_DRAFT = "v2-draft"
BUNDLE_IDS = (H001_V1, V2_DRAFT)

FULL_PROFILE = "full"
H001_CANARY_PROFILE = "testnet-10-validator-staking-h001"

# Pinned manifests (SHA-256 of the canonical manifest JSON). Never derived from
# the bundle being validated.
H001_V1_MANIFEST_SHA256 = (
    "e6cec2aa5d740c47c972fe92d4607ffd8a7a3c3f26b353475451d50b2670aefd"
)
H001_V1_ARCHIVE_SHA256 = (
    "4989f0768f2d2fc749fdd3aea227c1be6e55f5cbf35ac9c83e891b6abdf3977d"
)
V2_DRAFT_MANIFEST_SHA256 = (
    "b4e48882f40e90ea3c7991454211b66572b999dd7cc02c805c642d73289e4150"
)
H001_V1_PROVENANCE_SHA256 = (
    "8247a02a5756dc0944f66bc16abf29821e29dd5c15b1b94543cd03b7a8eba5d8"
)

# Status vocabulary for the non-promotable draft bundle.
DRAFT_REQUEST_SET_STATUS = "V2_DRAFT_REQUEST_SET_NOT_EXECUTABLE"
DRAFT_VERIFICATION_STATUS = "V2_DRAFT_REQUEST_SET_VERIFIED_NOT_EXECUTABLE"
DRAFT_BLOCKER = (
    "non-promotable draft bundle: the repository deployer pins only the h001-v1 manifest "
    "and rejects these requests before any signing request is exported"
)


@dataclass(frozen=True)
class BundleFixture:
    filename: str
    contract_name: str
    args: list[dict[str, Any]]
    abi: tuple[str, ...]


@dataclass(frozen=True)
class Bundle:
    bundle_id: str
    source_dir: Path
    fixtures: tuple[BundleFixture, ...]
    manifest_sha256: str
    archive_sha256: str | None
    promotable: bool
    profiles: frozenset[str]

    def source_path(self, recorded_source_file: str) -> Path:
        """Resolve a manifest ``source_file`` (recorded path) to this bundle's copy."""
        recorded = Path(recorded_source_file)
        if (
            recorded.parent.as_posix() != RECORDED_SOURCE_DIR
            or recorded.suffix != ".sil"
        ):
            raise ValueError(
                f"{self.bundle_id}: unexpected recorded source path {recorded_source_file!r}"
            )
        expected = {fixture.filename for fixture in self.fixtures}
        if recorded.name not in expected:
            raise ValueError(
                f"{self.bundle_id}: source {recorded.name!r} is not part of this bundle"
            )
        return self.source_dir / recorded.name


def _sha256_file(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def canonical_manifest_sha256(manifest: dict[str, Any]) -> str:
    return sha256(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _load_h001_v1() -> Bundle:
    provenance_path = H001_V1_DIR / "provenance.json"
    if _sha256_file(provenance_path) != H001_V1_PROVENANCE_SHA256:
        raise ValueError("h001-v1: provenance.json does not match its pinned SHA-256")
    provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
    if (
        provenance.get("bundle_id") != H001_V1
        or provenance.get("manifest_sha256") != H001_V1_MANIFEST_SHA256
        or provenance.get("archive_sha256") != H001_V1_ARCHIVE_SHA256
    ):
        raise ValueError("h001-v1: provenance identity mismatch")
    files = provenance.get("files")
    if not isinstance(files, dict) or not files:
        raise ValueError("h001-v1: provenance file pins missing")
    actual = sorted(
        path.relative_to(H001_V1_DIR).as_posix()
        for path in H001_V1_DIR.rglob("*")
        if path.is_file() and path.name not in {"provenance.json", "README.md"}
    )
    if actual != sorted(files):
        raise ValueError("h001-v1: frozen file set differs from provenance pins")
    for relative, digest in files.items():
        if _sha256_file(H001_V1_DIR / relative) != digest:
            raise ValueError(f"h001-v1: frozen file {relative} was modified")
    manifest = json.loads((H001_V1_DIR / "manifest.json").read_text(encoding="utf-8"))
    if canonical_manifest_sha256(manifest) != H001_V1_MANIFEST_SHA256:
        raise ValueError(
            "h001-v1: frozen manifest does not match the pinned manifest SHA-256"
        )
    data = json.loads((H001_V1_DIR / "fixtures.json").read_text(encoding="utf-8"))
    fixtures = tuple(
        BundleFixture(
            filename=entry["filename"],
            contract_name=entry["contract_name"],
            args=entry["args"],
            abi=tuple(entry["abi"]),
        )
        for entry in data["fixtures"]
    )
    return Bundle(
        bundle_id=H001_V1,
        source_dir=H001_V1_DIR / "sources",
        fixtures=fixtures,
        manifest_sha256=H001_V1_MANIFEST_SHA256,
        archive_sha256=H001_V1_ARCHIVE_SHA256,
        promotable=True,
        profiles=frozenset({FULL_PROFILE, H001_CANARY_PROFILE}),
    )


def _load_v2_draft() -> Bundle:
    from smoke_silverc_artifacts import FIXTURES  # current fixture tree

    fixtures = tuple(
        BundleFixture(
            filename=fixture.filename,
            contract_name=fixture.contract_name,
            args=fixture.args,
            abi=tuple(fixture.abi),
        )
        for fixture in FIXTURES
    )
    return Bundle(
        bundle_id=V2_DRAFT,
        source_dir=CONTRACT_DIR,
        fixtures=fixtures,
        manifest_sha256=V2_DRAFT_MANIFEST_SHA256,
        archive_sha256=None,
        promotable=False,
        profiles=frozenset({FULL_PROFILE}),
    )


def get_bundle(bundle_id: str) -> Bundle:
    if bundle_id == H001_V1:
        return _load_h001_v1()
    if bundle_id == V2_DRAFT:
        return _load_v2_draft()
    raise ValueError(f"unknown silverc bundle id: {bundle_id!r}")


def add_bundle_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--bundle",
        required=True,
        choices=BUNDLE_IDS,
        help="Release bundle identity (required; no default)",
    )


def bundle_from_args(args: argparse.Namespace) -> Bundle:
    return get_bundle(args.bundle)


def require_manifest_pin(bundle: Bundle, manifest: dict[str, Any]) -> None:
    if canonical_manifest_sha256(manifest) != bundle.manifest_sha256:
        raise ValueError(
            f"{bundle.bundle_id}: release manifest does not match the pinned bundle manifest"
        )


def require_profile(bundle: Bundle, profile_name: str) -> None:
    if profile_name not in bundle.profiles:
        raise ValueError(
            f"deployment profile {profile_name!r} is not allowed for bundle {bundle.bundle_id}"
        )


def require_promotable(bundle: Bundle, purpose: str) -> None:
    if not bundle.promotable:
        raise ValueError(
            f"bundle {bundle.bundle_id} is a non-promotable draft; {purpose} is refused"
        )

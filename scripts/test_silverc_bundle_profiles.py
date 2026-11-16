#!/usr/bin/env python3
"""End-to-end separation checks for the h001-v1 and v2-draft silverc bundles.

Requires both built archives and the repository deployer binary. Proves that
the historical v1 bundle validates against its pinned manifest, that v2 is only
statically checkable, that the Rust deployer rejects v2 requests before any
signing request is exported, and that receipts/status/evidence/procedures are
refused for the draft. Offline: no network, signing, wallet or broadcast.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tarfile
import tempfile
from hashlib import sha256
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import silverc_bundles as bundles  # noqa: E402

ROOT = bundles.ROOT
DEPLOYER_ADDRESS = "kaspatest:qptestpreflight000000000000000000000000000000000"
ORACLE_KEY = "11" * 32
RESOLVER = "kaspa-resolver://public"
COMMON = [
    "--network",
    "testnet",
    "--rpc-url",
    RESOLVER,
    "--deployer-address",
    DEPLOYER_ADDRESS,
]


def run(*args: str, expect_success: bool = True) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(
        [sys.executable, *args], cwd=ROOT, text=True, capture_output=True
    )
    if expect_success and proc.returncode != 0:
        raise AssertionError(f"{args[0]} failed: {proc.stderr[-800:]}")
    if not expect_success and proc.returncode == 0:
        raise AssertionError(f"{args[0]} unexpectedly succeeded")
    return proc


def archive_manifest(archive: Path) -> dict[str, object]:
    with tarfile.open(archive, "r:gz") as tar:
        member = tar.extractfile("prometheus-silverc-artifacts/manifest.json")
        assert member is not None
        return json.loads(member.read().decode("utf-8"))


def extract(archive: Path, target: Path) -> Path:
    with tarfile.open(archive, "r:gz") as tar:
        tar.extractall(target, filter="data")
    return target / "prometheus-silverc-artifacts"


def build_requests(bundle: str, archive: Path, out: Path, profile: str) -> Path:
    extra = (
        ["--metrics-oracle-pubkey", ORACLE_KEY]
        if profile == bundles.FULL_PROFILE
        else []
    )
    request_set = out.with_suffix(".json")
    run(
        "scripts/build_silverc_deploy_requests.py",
        "--bundle",
        bundle,
        "--archive",
        str(archive),
        "--deployment-profile",
        profile,
        *COMMON,
        *extra,
        "--out-dir",
        str(out),
        "--request-set-out",
        str(request_set),
    )
    return request_set


def deployer_prepare(
    deployer: Path, request: Path, artifact: Path, root: Path
) -> subprocess.CompletedProcess[str]:
    funding = root / "funding.json"
    funding.write_text("{}\n", encoding="utf-8")
    out = root / f"signing-request-{request.stem}.json"
    proc = subprocess.run(
        [
            str(deployer),
            "prepare",
            "--request",
            str(request),
            "--artifact",
            str(artifact),
            "--funding",
            str(funding),
            "--signing-request-out",
            str(out),
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
    )
    if out.exists():
        raise AssertionError(
            "deployer exported a signing request during a negative check"
        )
    return proc


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--v1-archive", type=Path, required=True)
    parser.add_argument("--v2-archive", type=Path, required=True)
    parser.add_argument("--deployer", type=Path, required=True)
    args = parser.parse_args()
    v1_archive = args.v1_archive.resolve()
    v2_archive = args.v2_archive.resolve()

    # 1. Pinned identities, never derived from the archive under test.
    assert sha256(v1_archive.read_bytes()).hexdigest() == bundles.H001_V1_ARCHIVE_SHA256
    assert (
        bundles.canonical_manifest_sha256(archive_manifest(v1_archive))
        == bundles.H001_V1_MANIFEST_SHA256
    )
    assert (
        bundles.canonical_manifest_sha256(archive_manifest(v2_archive))
        == bundles.V2_DRAFT_MANIFEST_SHA256
    )

    with tempfile.TemporaryDirectory(prefix="prometheus-bundle-profiles.") as tmp:
        root = Path(tmp)

        # 2. Static request checks per bundle.
        v1_set = build_requests(
            bundles.H001_V1, v1_archive, root / "v1-full", bundles.FULL_PROFILE
        )
        v2_set = build_requests(
            bundles.V2_DRAFT, v2_archive, root / "v2-full", bundles.FULL_PROFILE
        )
        canary_set = build_requests(
            bundles.H001_V1, v1_archive, root / "v1-canary", bundles.H001_CANARY_PROFILE
        )
        for bundle, archive, request_set, directory, status in (
            (
                bundles.H001_V1,
                v1_archive,
                v1_set,
                root / "v1-full",
                "DEPLOY_REQUEST_SET_VERIFIED",
            ),
            (
                bundles.V2_DRAFT,
                v2_archive,
                v2_set,
                root / "v2-full",
                bundles.DRAFT_VERIFICATION_STATUS,
            ),
            (
                bundles.H001_V1,
                v1_archive,
                canary_set,
                root / "v1-canary",
                "CANARY_DEPLOY_REQUEST_VERIFIED",
            ),
        ):
            summary_path = root / f"verify-{directory.name}.json"
            run(
                "scripts/verify_silverc_deploy_requests.py",
                "--bundle",
                bundle,
                "--archive",
                str(archive),
                "--request-set",
                str(request_set),
                "--requests-dir",
                str(directory),
                "--summary-out",
                str(summary_path),
            )
            assert (
                json.loads(summary_path.read_text(encoding="utf-8"))["status"] == status
            )
        v2_summary = json.loads(v2_set.read_text(encoding="utf-8"))
        assert v2_summary["status"] == bundles.DRAFT_REQUEST_SET_STATUS
        assert bundles.DRAFT_BLOCKER in v2_summary["blockers"]

        # 3. Cross-profile / cross-bundle rejections.
        rejected = run(
            "scripts/build_silverc_deploy_requests.py",
            "--bundle",
            bundles.V2_DRAFT,
            "--archive",
            str(v2_archive),
            "--deployment-profile",
            bundles.H001_CANARY_PROFILE,
            *COMMON,
            "--out-dir",
            str(root / "x"),
            "--request-set-out",
            str(root / "x.json"),
            expect_success=False,
        )
        assert "not allowed for bundle v2-draft" in rejected.stderr
        for bundle, archive, request_set, directory in (
            (bundles.H001_V1, v2_archive, v2_set, root / "v2-full"),
            (bundles.V2_DRAFT, v2_archive, v1_set, root / "v1-full"),
            (bundles.V2_DRAFT, v1_archive, v2_set, root / "v2-full"),
        ):
            run(
                "scripts/verify_silverc_deploy_requests.py",
                "--bundle",
                bundle,
                "--archive",
                str(archive),
                "--request-set",
                str(request_set),
                "--requests-dir",
                str(directory),
                "--summary-out",
                str(root / "x-summary.json"),
                expect_success=False,
            )

        # 4. Mixed bundle: v1 archive with one v2 artifact and manifest entry.
        v1_dir = extract(v1_archive, root / "v1-extract")
        v2_dir = extract(v2_archive, root / "v2-extract")
        mixed = json.loads((v1_dir / "manifest.json").read_text(encoding="utf-8"))
        v2_manifest = json.loads((v2_dir / "manifest.json").read_text(encoding="utf-8"))
        mixed["fixtures"][1] = v2_manifest["fixtures"][1]
        (v1_dir / "manifest.json").write_text(
            json.dumps(mixed, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        name = mixed["fixtures"][1]["artifact_file"]
        (v1_dir / name).write_bytes((v2_dir / name).read_bytes())
        for bundle in bundles.BUNDLE_IDS:
            run(
                "scripts/preflight_silverc_deploy.py",
                "--bundle",
                bundle,
                "--bundle-dir",
                str(v1_dir),
                "--deployment-profile",
                bundles.FULL_PROFILE,
                *COMMON,
                "--metrics-oracle-pubkey",
                ORACLE_KEY,
                expect_success=False,
            )

        # 5. Rust deployer: v2 rejected before export; v1 passes the profile gate.
        v2_request = sorted((root / "v2-full").glob("*.deploy-request.json"))[0]
        v2_artifact = (
            v2_dir
            / json.loads(v2_request.read_text(encoding="utf-8"))["contract"][
                "artifact_file"
            ]
        )
        proc = deployer_prepare(args.deployer, v2_request, v2_artifact, root)
        assert proc.returncode != 0, "deployer accepted a v2-draft request"
        assert "release-manifest binding mismatch" in proc.stderr, proc.stderr[-500:]
        v1_clean = extract(v1_archive, root / "v1-clean")
        for request_dir in (root / "v1-full", root / "v1-canary"):
            v1_request = sorted(request_dir.glob("*.deploy-request.json"))[0]
            contract = json.loads(v1_request.read_text(encoding="utf-8"))["contract"]
            proc = deployer_prepare(
                args.deployer, v1_request, v1_clean / contract["artifact_file"], root
            )
            assert "release-manifest binding mismatch" not in proc.stderr, proc.stderr[
                -500:
            ]

        # 6. Receipts, status, evidence and operator packages refused for the draft.
        dummy = root / "dummy.json"
        dummy.write_text("{}\n", encoding="utf-8")
        draft = ["--bundle", bundles.V2_DRAFT, "--archive", str(v2_archive)]
        for tool, extra in (
            ("verify_silverc_deploy_receipts.py", ["--receipts", str(dummy)]),
            ("stage_silverc_deployment_status.py", ["--operator-receipts", str(dummy)]),
            (
                "verify_silverc_deploy_receipt_evidence.py",
                ["--receipts", str(dummy), "--evidence", str(dummy)],
            ),
            (
                "build_silverc_deploy_operator_procedure.py",
                ["--request-set", str(v2_set), "--requests-dir", str(root / "v2-full")],
            ),
            (
                "build_silverc_operator_receipts.py",
                [
                    "--request-set",
                    str(v2_set),
                    "--requests-dir",
                    str(root / "v2-full"),
                    "--orchestrator-results",
                    str(dummy),
                ],
            ),
            ("build_metrics_oracle_tx_request.py", ["--report", str(dummy)]),
        ):
            proc = run(f"scripts/{tool}", *draft, *extra, expect_success=False)
            assert "non-promotable draft" in proc.stderr, (
                f"{tool}: {proc.stderr[-400:]}"
            )

        # 7. No default bundle.
        proc = run(
            "scripts/preflight_silverc_deploy.py",
            "--archive",
            str(v1_archive),
            expect_success=False,
        )
        assert "--bundle" in proc.stderr

    print("silverc bundle profile separation: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())

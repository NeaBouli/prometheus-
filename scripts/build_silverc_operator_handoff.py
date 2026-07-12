#!/usr/bin/env python3
"""Build a CI-safe Silverc operator handoff package for Prometheus."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from hashlib import sha256
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REPORT = ROOT / "modules" / "contracts" / "silverc" / "metrics-oracle-report.sample.json"
DEFAULT_CI_RECEIPTS = ROOT / "modules" / "contracts" / "silverc" / "deploy-receipts.sample.json"
DEFAULT_OUT_DIR = Path("/tmp/prometheus-silverc-operator-handoff")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Build a public operator handoff package from an existing Prometheus "
            "current-Silverc release archive. This validates and bundles public "
            "artifacts only; it does not deploy, sign, broadcast, or update status files."
        )
    )
    parser.add_argument("--archive", type=Path, required=True, help="Validated release .tar.gz archive")
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR, help="Output handoff directory")
    parser.add_argument("--network", choices=("sandbox", "testnet", "mainnet"), default="sandbox")
    parser.add_argument("--rpc-url", required=True, help="Public Kaspa RPC/wRPC endpoint")
    parser.add_argument("--deployer-address", required=True, help="Public deployer address")
    parser.add_argument(
        "--metrics-oracle-pubkey",
        required=True,
        help="32-byte x-only metrics-oracle public key hex; never pass private keys",
    )
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT, help="Public metrics-oracle report JSON")
    parser.add_argument(
        "--ci-receipts",
        type=Path,
        default=DEFAULT_CI_RECEIPTS,
        help="Synthetic ci_fixture deployment receipt JSON for schema/hash checks",
    )
    parser.add_argument(
        "--operator-receipts",
        type=Path,
        help="Optional real operator_record receipts JSON; verified with --require-operator-record",
    )
    parser.add_argument(
        "--orchestrator-results",
        type=Path,
        help="Optional public external deploy-orchestrator results JSON to convert into operator_record receipts",
    )
    parser.add_argument(
        "--contract-instance-id",
        help="Optional public GovernanceAutoTuningState deployed instance/outpoint for signer-ready tx requests",
    )
    parser.add_argument(
        "--metrics-tx-result",
        type=Path,
        help="Optional public metrics-oracle transaction result JSON to verify against the generated tx request",
    )
    return parser.parse_args()


def run(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(cmd, cwd=ROOT, text=True, capture_output=True)
    if proc.returncode != 0:
        if proc.stdout:
            print(proc.stdout, file=sys.stdout)
        if proc.stderr:
            print(proc.stderr, file=sys.stderr)
        proc.check_returncode()
    return proc


def load_json(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path}: expected JSON object")
    return data


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def sha256_file(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def ensure_public_file(path: Path, label: str) -> Path:
    resolved = path.expanduser().resolve()
    if not resolved.is_file():
        raise FileNotFoundError(f"{label} not found: {resolved}")
    return resolved


def run_deploy_preflight(args: argparse.Namespace, archive: Path, out_dir: Path) -> dict[str, Any]:
    plan_path = out_dir / "deploy-preflight.json"
    runbook_path = out_dir / "deploy-preflight.md"
    run(
        [
            sys.executable,
            "scripts/preflight_silverc_deploy.py",
            "--archive",
            str(archive),
            "--network",
            args.network,
            "--rpc-url",
            args.rpc_url,
            "--deployer-address",
            args.deployer_address,
            "--metrics-oracle-pubkey",
            args.metrics_oracle_pubkey,
            "--plan-out",
            str(plan_path),
            "--runbook-out",
            str(runbook_path),
        ]
    )
    return load_json(plan_path)


def run_deploy_requests(args: argparse.Namespace, archive: Path, out_dir: Path) -> dict[str, Any]:
    requests_dir = out_dir / "deploy-requests"
    summary_path = out_dir / "deploy-request-set.json"
    runbook_path = out_dir / "deploy-requests.md"
    run(
        [
            sys.executable,
            "scripts/build_silverc_deploy_requests.py",
            "--archive",
            str(archive),
            "--out-dir",
            str(requests_dir),
            "--network",
            args.network,
            "--rpc-url",
            args.rpc_url,
            "--deployer-address",
            args.deployer_address,
            "--metrics-oracle-pubkey",
            args.metrics_oracle_pubkey,
            "--request-set-out",
            str(summary_path),
            "--runbook-out",
            str(runbook_path),
        ]
    )
    return load_json(summary_path)


def run_deploy_request_verification(archive: Path, out_dir: Path) -> dict[str, Any]:
    summary_path = out_dir / "deploy-request-verification.json"
    runbook_path = out_dir / "deploy-request-verification.md"
    run(
        [
            sys.executable,
            "scripts/verify_silverc_deploy_requests.py",
            "--archive",
            str(archive),
            "--request-set",
            str(out_dir / "deploy-request-set.json"),
            "--requests-dir",
            str(out_dir / "deploy-requests"),
            "--summary-out",
            str(summary_path),
            "--runbook-out",
            str(runbook_path),
        ]
    )
    return load_json(summary_path)


def run_deploy_operator_procedure(archive: Path, out_dir: Path) -> dict[str, Any]:
    summary_path = out_dir / "deploy-operator-procedure.json"
    runbook_path = out_dir / "deploy-operator-procedure.md"
    run(
        [
            sys.executable,
            "scripts/build_silverc_deploy_operator_procedure.py",
            "--archive",
            str(archive),
            "--request-set",
            str(out_dir / "deploy-request-set.json"),
            "--requests-dir",
            str(out_dir / "deploy-requests"),
            "--summary-out",
            str(summary_path),
            "--runbook-out",
            str(runbook_path),
        ]
    )
    return load_json(summary_path)


def run_operator_receipt_import(archive: Path, out_dir: Path, orchestrator_results: Path) -> dict[str, Any]:
    receipts_path = out_dir / "operator-receipts.from-results.json"
    summary_path = out_dir / "operator-receipts-import-summary.json"
    runbook_path = out_dir / "operator-receipts-import.md"
    run(
        [
            sys.executable,
            "scripts/build_silverc_operator_receipts.py",
            "--archive",
            str(archive),
            "--request-set",
            str(out_dir / "deploy-request-set.json"),
            "--requests-dir",
            str(out_dir / "deploy-requests"),
            "--orchestrator-results",
            str(orchestrator_results),
            "--operator-receipts-out",
            str(receipts_path),
            "--summary-out",
            str(summary_path),
            "--runbook-out",
            str(runbook_path),
        ]
    )
    return load_json(summary_path)


def run_receipt_verification(
    archive: Path,
    receipts: Path,
    out_dir: Path,
    name: str,
    require_operator_record: bool,
) -> dict[str, Any]:
    summary_path = out_dir / f"{name}-receipt-summary.json"
    runbook_path = out_dir / f"{name}-receipt-runbook.md"
    cmd = [
        sys.executable,
        "scripts/verify_silverc_deploy_receipts.py",
        "--archive",
        str(archive),
        "--receipts",
        str(receipts),
        "--summary-out",
        str(summary_path),
        "--runbook-out",
        str(runbook_path),
    ]
    if require_operator_record:
        cmd.append("--require-operator-record")
    run(cmd)
    return load_json(summary_path)


def run_metrics_report_preflight(report: Path, out_dir: Path) -> dict[str, Any]:
    plan_path = out_dir / "metrics-oracle-report-preflight.json"
    runbook_path = out_dir / "metrics-oracle-report-preflight.md"
    run(
        [
            sys.executable,
            "scripts/preflight_metrics_oracle_report.py",
            "--report",
            str(report),
            "--plan-out",
            str(plan_path),
            "--runbook-out",
            str(runbook_path),
        ]
    )
    return load_json(plan_path)


def run_tx_request(
    archive: Path,
    report: Path,
    out_dir: Path,
    contract_instance_id: str | None,
) -> dict[str, Any]:
    request_path = out_dir / "metrics-oracle-tx-request.json"
    runbook_path = out_dir / "metrics-oracle-tx-request.md"
    cmd = [
        sys.executable,
        "scripts/build_metrics_oracle_tx_request.py",
        "--archive",
        str(archive),
        "--report",
        str(report),
        "--tx-request-out",
        str(request_path),
        "--runbook-out",
        str(runbook_path),
    ]
    if contract_instance_id:
        cmd.extend(["--contract-instance-id", contract_instance_id])
    run(cmd)
    return load_json(request_path)


def run_metrics_operator_procedure(archive: Path, out_dir: Path) -> dict[str, Any]:
    summary_path = out_dir / "metrics-oracle-operator-procedure.json"
    runbook_path = out_dir / "metrics-oracle-operator-procedure.md"
    run(
        [
            sys.executable,
            "scripts/build_metrics_oracle_operator_procedure.py",
            "--archive",
            str(archive),
            "--tx-request",
            str(out_dir / "metrics-oracle-tx-request.json"),
            "--summary-out",
            str(summary_path),
            "--runbook-out",
            str(runbook_path),
        ]
    )
    return load_json(summary_path)


def run_metrics_tx_result_verification(archive: Path, out_dir: Path, metrics_tx_result: Path) -> dict[str, Any]:
    summary_path = out_dir / "metrics-oracle-tx-result-summary.json"
    runbook_path = out_dir / "metrics-oracle-tx-result.md"
    run(
        [
            sys.executable,
            "scripts/verify_metrics_oracle_tx_result.py",
            "--archive",
            str(archive),
            "--tx-request",
            str(out_dir / "metrics-oracle-tx-request.json"),
            "--tx-result",
            str(metrics_tx_result),
            "--summary-out",
            str(summary_path),
            "--runbook-out",
            str(runbook_path),
        ]
    )
    return load_json(summary_path)


def run_metrics_oracle_status_staging(archive: Path, out_dir: Path, metrics_tx_result: Path) -> dict[str, Any]:
    status_path = out_dir / "metrics-oracle-status-draft.json"
    snippet_path = out_dir / "metrics-oracle-status-draft.md"
    run(
        [
            sys.executable,
            "scripts/stage_metrics_oracle_status.py",
            "--archive",
            str(archive),
            "--tx-request",
            str(out_dir / "metrics-oracle-tx-request.json"),
            "--tx-result",
            str(metrics_tx_result),
            "--status-out",
            str(status_path),
            "--snippet-out",
            str(snippet_path),
        ]
    )
    return load_json(status_path)


def status_from_components(
    deploy_plan: dict[str, Any],
    operator_receipts: dict[str, Any] | None,
    tx_request: dict[str, Any],
    tx_result: dict[str, Any] | None,
) -> tuple[str, list[str]]:
    blockers = []
    if not deploy_plan["deploy_supported"]:
        blockers.extend(deploy_plan["deploy_blockers"])
    if operator_receipts is None:
        blockers.append("missing verified operator_record deployment receipts")
    if tx_request["status"] != "READY_FOR_EXTERNAL_TX_ASSEMBLER":
        blockers.extend(tx_request["blockers"])
    elif tx_result is None:
        blockers.append("missing verified metrics-oracle transaction result")

    status = "READY_FOR_OPERATOR_DEPLOY" if not blockers else "HANDOFF_BLOCKED"
    return status, blockers


def included_files(out_dir: Path) -> list[str]:
    return sorted(str(path.relative_to(out_dir)) for path in out_dir.rglob("*") if path.is_file())


def write_handoff_markdown(out_dir: Path, summary: dict[str, Any]) -> None:
    lines = [
        "# Prometheus Silverc Operator Handoff",
        "",
        f"Status: {summary['status']}",
        f"Network: {summary['network']}",
        f"Release archive SHA-256: `{summary['release_archive_sha256']}`",
        f"Silverscript commit: `{summary['silverscript_commit']}`",
        "",
        "## Safety Rules",
        "",
        "- This handoff package contains public deployment artifacts only.",
        "- It does not accept private keys, sign transactions, broadcast transactions, deploy contracts, or update status files.",
        "- Synthetic ci_fixture receipts are included only for schema/hash verification.",
        "- Real status updates require verified operator_record receipts from an actual network deploy.",
        "- Validators stake KAS only; PROM remains earned-only and is not a staking asset.",
        "",
        "## Included Files",
        "",
    ]
    lines.extend(f"- `{name}`" for name in summary["included_files"])
    lines.extend(["", "## Gate Summary", ""])
    lines.extend(
        [
            f"- Deploy preflight: {'supported' if summary['deploy_supported'] else 'blocked'}",
            f"- Deploy request set: {summary['deploy_requests_status']}",
            f"- Deploy request verification: {summary['deploy_request_verification_status']}",
            f"- Deploy operator procedure: {summary['deploy_operator_procedure_status']}",
            f"- Operator receipt import: {summary['operator_receipt_import_status']}",
            f"- CI receipt verification: {summary['ci_receipts_status']}",
            f"- Operator receipt verification: {summary['operator_receipts_status']}",
            f"- Metrics report preflight: {summary['metrics_report_status']}",
            f"- Metrics tx request: {summary['metrics_tx_request_status']}",
            f"- Metrics operator procedure: {summary['metrics_operator_procedure_status']}",
            f"- Metrics tx result: {summary['metrics_tx_result_status']}",
            f"- Metrics oracle status draft: {summary['metrics_oracle_status_draft_status']}",
            "",
            "## Blockers",
            "",
        ]
    )
    blockers = summary["blockers"]
    lines.extend(f"- {blocker}" for blocker in blockers) if blockers else lines.append("- none")
    lines.extend(
        [
            "",
            "## Operator Sequence",
            "",
            "1. Review `deploy-preflight.md` and confirm the deploy-tool capability status.",
            "2. Review `deploy-operator-procedure.md` before any external deploy orchestration.",
            "3. Deploy only through an approved external network deploy/orchestration tool.",
            "4. Import public external deploy results with `--orchestrator-results`, or provide verified `operator_record` receipts with `--operator-receipts`.",
            "5. Use only verified operator_record contract IDs for signer-ready oracle transaction requests.",
            "6. Review `metrics-oracle-operator-procedure.md` before any external signing or broadcast.",
            "7. Sign and broadcast outside this repository through the approved wallet/vault process, then verify the public result with `--metrics-tx-result`.",
            "8. Update `memory/STATUS.md` only after all real receipts and transaction receipts verify.",
        ]
    )
    (out_dir / "HANDOFF.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    args = parse_args()
    archive = ensure_public_file(args.archive, "release archive")
    report = ensure_public_file(args.report, "metrics-oracle report")
    ci_receipts = ensure_public_file(args.ci_receipts, "ci receipt fixture")
    operator_receipts_path = (
        ensure_public_file(args.operator_receipts, "operator receipts") if args.operator_receipts else None
    )
    orchestrator_results_path = (
        ensure_public_file(args.orchestrator_results, "orchestrator results") if args.orchestrator_results else None
    )
    metrics_tx_result_path = (
        ensure_public_file(args.metrics_tx_result, "metrics tx result") if args.metrics_tx_result else None
    )
    out_dir = args.out_dir.expanduser().resolve()
    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True)

    packaged_archive = out_dir / "prometheus-silverc-artifacts.tar.gz"
    shutil.copyfile(archive, packaged_archive)

    deploy_plan = run_deploy_preflight(args, packaged_archive, out_dir)
    deploy_requests = run_deploy_requests(args, packaged_archive, out_dir)
    deploy_request_verification = run_deploy_request_verification(packaged_archive, out_dir)
    deploy_operator_procedure = run_deploy_operator_procedure(packaged_archive, out_dir)
    operator_receipt_import = None
    if orchestrator_results_path:
        operator_receipt_import = run_operator_receipt_import(packaged_archive, out_dir, orchestrator_results_path)
        if operator_receipts_path is None:
            operator_receipts_path = out_dir / "operator-receipts.from-results.json"
    ci_receipts_summary = run_receipt_verification(
        packaged_archive,
        ci_receipts,
        out_dir,
        "ci-fixture",
        require_operator_record=False,
    )
    operator_receipts_summary = None
    if operator_receipts_path:
        operator_receipts_summary = run_receipt_verification(
            packaged_archive,
            operator_receipts_path,
            out_dir,
            "operator",
            require_operator_record=True,
        )
    metrics_report_plan = run_metrics_report_preflight(report, out_dir)
    tx_request = run_tx_request(packaged_archive, report, out_dir, args.contract_instance_id)
    metrics_operator_procedure = None
    if tx_request["status"] == "READY_FOR_EXTERNAL_TX_ASSEMBLER":
        metrics_operator_procedure = run_metrics_operator_procedure(packaged_archive, out_dir)
    tx_result_summary = None
    metrics_oracle_status_draft = None
    if metrics_tx_result_path:
        tx_result_summary = run_metrics_tx_result_verification(packaged_archive, out_dir, metrics_tx_result_path)
        metrics_oracle_status_draft = run_metrics_oracle_status_staging(
            packaged_archive,
            out_dir,
            metrics_tx_result_path,
        )

    status, blockers = status_from_components(deploy_plan, operator_receipts_summary, tx_request, tx_result_summary)
    summary = {
        "schema_version": 1,
        "status": status,
        "network": args.network,
        "release_archive_sha256": sha256_file(packaged_archive),
        "silverscript_commit": deploy_plan["bundle"]["silverscript_commit"],
        "deploy_supported": deploy_plan["deploy_supported"],
        "deploy_requests_status": deploy_requests["status"],
        "deploy_request_count": deploy_requests["request_count"],
        "deploy_request_verification_status": deploy_request_verification["status"],
        "deploy_operator_procedure_status": deploy_operator_procedure["status"],
        "operator_receipt_import_status": (
            operator_receipt_import["status"] if operator_receipt_import else "NOT_PROVIDED"
        ),
        "ci_receipts_status": ci_receipts_summary["status"],
        "operator_receipts_status": (
            operator_receipts_summary["status"] if operator_receipts_summary else "MISSING_OPERATOR_RECORD"
        ),
        "metrics_report_status": metrics_report_plan["status"],
        "metrics_tx_request_status": tx_request["status"],
        "metrics_operator_procedure_status": (
            metrics_operator_procedure["status"] if metrics_operator_procedure else "NOT_READY_TX_REQUEST_BLOCKED"
        ),
        "metrics_tx_result_status": tx_result_summary["status"] if tx_result_summary else "NOT_PROVIDED",
        "metrics_oracle_status_draft_status": (
            metrics_oracle_status_draft["status"] if metrics_oracle_status_draft else "NOT_PROVIDED"
        ),
        "safety": {
            "accepts_private_keys": False,
            "signs_transactions": False,
            "assembles_chain_transaction": False,
            "broadcasts_transactions": False,
            "deploys_contracts": False,
            "updates_status_files": False,
        },
        "blockers": blockers,
        "included_files": included_files(out_dir),
    }
    write_json(out_dir / "operator-handoff-summary.json", summary)
    summary["included_files"] = included_files(out_dir)
    write_json(out_dir / "operator-handoff-summary.json", summary)
    write_handoff_markdown(out_dir, summary)
    summary["included_files"] = included_files(out_dir)
    write_json(out_dir / "operator-handoff-summary.json", summary)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)

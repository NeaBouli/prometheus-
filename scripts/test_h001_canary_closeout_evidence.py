#!/usr/bin/env python3
"""Regression tests for repository-public H-001 closeout evidence."""

from __future__ import annotations

import copy
import unittest

from scripts.verify_h001_canary_closeout_evidence import (
    DEFAULT_EVIDENCE,
    DEFAULT_RECEIPTS,
    DEFAULT_SUMMARY,
    EvidenceValidationError,
    load_document,
    verify_documents,
    verify_paths,
)


class H001CanaryCloseoutEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.summary = load_document(DEFAULT_SUMMARY)
        self.receipts = load_document(DEFAULT_RECEIPTS)
        self.evidence = load_document(DEFAULT_EVIDENCE)

    def test_committed_evidence_verifies(self) -> None:
        verify_paths(DEFAULT_SUMMARY, DEFAULT_RECEIPTS, DEFAULT_EVIDENCE)

    def test_receipt_tamper_is_rejected(self) -> None:
        receipts = copy.deepcopy(self.receipts)
        receipts["receipts"][0]["deploy_tx_id"] = "00" * 32
        with self.assertRaisesRegex(EvidenceValidationError, "operator_receipts_sha256"):
            verify_documents(self.summary, receipts, self.evidence)

    def test_unverified_summary_status_is_rejected(self) -> None:
        summary = copy.deepcopy(self.summary)
        summary["status"] = "UNVERIFIED"
        with self.assertRaisesRegex(EvidenceValidationError, "summary.status"):
            verify_documents(summary, self.receipts, self.evidence)

    def test_nonpublic_payload_is_rejected(self) -> None:
        evidence = copy.deepcopy(self.evidence)
        evidence["signature_hex"] = "00"
        with self.assertRaisesRegex(EvidenceValidationError, "forbidden public evidence field"):
            verify_documents(self.summary, self.receipts, evidence)


if __name__ == "__main__":
    unittest.main()

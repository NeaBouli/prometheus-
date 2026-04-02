//! End-to-End Threat Lifecycle Test
//!
//! Simulates the complete Prometheus threat detection pipeline
//! from Whitepaper section 2.3:
//!   1. Light Client detects anomaly (EICAR)
//!   2. ThreatHint created with ZK proof
//!   3. Validator creates vote commitment + reveal
//!   4. Rule stored and loaded by scanner
//!
//! Timing: total elapsed < 60 seconds (Whitepaper requirement).
//! No live Kaspa node required — uses mocks/stubs.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use prometheus_client::ai::detection::{AnomalyDetector, Verdict};
use prometheus_client::ai::phi3::Phi3Model;
use prometheus_client::network::zk_proof::ZkProofGenerator;
use prometheus_client::security::scanner::{compute_sha256, CompiledRule, YaraScanner};
use prometheus_validator::slashing::SlashingEngine;
use prometheus_validator::voting::commit::CommitmentBuilder;
use prometheus_validator::voting::reveal::{RevealResult, RevealValidator};
use prometheus_validator::{BOND_PERCENT, MIN_STAKE_KAS, SLASH_SIMPLE_PCT};
use tokio::sync::Mutex;

/// EICAR test string — standard antivirus test file content
const EICAR: &[u8] = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

#[tokio::test]
async fn test_full_threat_lifecycle_under_60s() {
    let start = Instant::now();

    // ============================================================
    // PHASE 1: Light Client detects anomaly (t=0s)
    // ============================================================

    // Set up YARA scanner with EICAR detection rule
    let mut scanner = YaraScanner::new().unwrap();
    scanner.add_rule(CompiledRule {
        name: "EICAR_Test".to_string(),
        patterns: vec![b"EICAR".to_vec(), b"$H+H*".to_vec()],
        required_matches: 1,
    });

    // Scan the EICAR test content
    let scan_result = scanner.scan_bytes(EICAR).unwrap();
    assert!(scan_result.is_threat, "EICAR must be detected as threat");
    assert!(
        scan_result
            .matched_rules
            .contains(&"EICAR_Test".to_string()),
        "EICAR_Test rule must match"
    );

    // Run anomaly detector (AI model not loaded → stub mode)
    let model = Phi3Model::new(&PathBuf::from("/nonexistent/phi3.onnx")).unwrap();
    let detector = AnomalyDetector::new(Arc::new(model), Arc::new(Mutex::new(scanner)));
    let detection = detector.analyze_bytes(EICAR).await.unwrap();
    assert_eq!(
        detection.final_verdict,
        Verdict::Suspicious,
        "YARA match without AI = Suspicious"
    );

    let phase1_elapsed = start.elapsed();
    eprintln!("Phase 1 (detection): {:?}", phase1_elapsed);

    // ============================================================
    // PHASE 2: Create ThreatHint with ZK proof (t≈2s)
    // ============================================================

    let file_hash = compute_sha256(EICAR);

    // Generate ZK proof for anonymous reporting
    let zk_gen = ZkProofGenerator::new().unwrap();
    let zk_proof = zk_gen.generate_threat_proof(&file_hash).unwrap();
    assert!(zk_gen.verify_proof(&zk_proof), "ZK proof must verify");
    assert_eq!(zk_proof.public_input, file_hash);

    let phase2_elapsed = start.elapsed();
    eprintln!("Phase 2 (ZK proof): {:?}", phase2_elapsed);

    // ============================================================
    // PHASE 3: Validator voting — Commit-Reveal (t≈15s)
    // ============================================================

    let validator_addr = [0xAA; 32];
    let validator_stake: u64 = 50_000;
    let proposal_id: u64 = 1;
    let vote = true;
    let salt: u64 = 0xDEAD_BEEF_CAFE;
    let block_height: u64 = 100_000;

    // Create commitment
    let builder = CommitmentBuilder::new(validator_addr);
    let commitment = builder.build(proposal_id, vote, salt, block_height, validator_stake);
    assert_eq!(
        commitment.bond_kas,
        validator_stake * BOND_PERCENT / 100,
        "Bond must be 10% of stake"
    );

    // Validate reveal (correct vote + salt)
    let reveal_validator = RevealValidator;
    let reveal_result = reveal_validator.validate_reveal(&commitment, vote, salt);
    assert_eq!(reveal_result, RevealResult::Valid, "Valid reveal must pass");

    // Verify wrong salt is caught
    let bad_reveal = reveal_validator.validate_reveal(&commitment, vote, 999);
    assert!(
        matches!(bad_reveal, RevealResult::InvalidHash { .. }),
        "Wrong salt must be detected"
    );

    // Verify slashing calculation
    let slashing = SlashingEngine;
    let (penalty, remaining, deactivate) = slashing.execute(validator_stake, SLASH_SIMPLE_PCT, 0);
    assert_eq!(penalty, 2_500); // 50000 * 5 * 1 / 100
    assert_eq!(remaining, 47_500);
    assert!(!deactivate); // 47500 > MIN_STAKE_KAS

    let phase3_elapsed = start.elapsed();
    eprintln!("Phase 3 (voting): {:?}", phase3_elapsed);

    // ============================================================
    // PHASE 4: Rule stored and reloaded (t≈35s)
    // ============================================================

    // Simulate: rule accepted by consensus, stored as KRC20
    let new_rule_content = b"EICAR";

    // Reload scanner with the new rule
    let mut reloaded_scanner = YaraScanner::new().unwrap();
    reloaded_scanner.add_rule(CompiledRule {
        name: "PROM-RULE-2026-0001".to_string(),
        patterns: vec![new_rule_content.to_vec()],
        required_matches: 1,
    });

    // Verify: EICAR detected by new rule
    let rescan = reloaded_scanner.scan_bytes(EICAR).unwrap();
    assert!(rescan.is_threat);
    assert!(rescan
        .matched_rules
        .contains(&"PROM-RULE-2026-0001".to_string()));

    // Verify: clean file is clean
    let clean_scan = reloaded_scanner
        .scan_bytes(b"This is a safe document")
        .unwrap();
    assert!(!clean_scan.is_threat);
    assert!(clean_scan.matched_rules.is_empty());

    let phase4_elapsed = start.elapsed();
    eprintln!("Phase 4 (rule reload): {:?}", phase4_elapsed);

    // ============================================================
    // TIMING ASSERTION: total < 60 seconds
    // ============================================================

    let total = start.elapsed();
    eprintln!("Total E2E time: {:?}", total);
    assert!(
        total < Duration::from_secs(60),
        "E2E lifecycle must complete in under 60 seconds, took {:?}",
        total
    );
}

#[tokio::test]
async fn test_lifecycle_data_integrity() {
    // Verify that the file hash is consistent through the entire pipeline
    let file_hash = compute_sha256(EICAR);

    // Hash at detection
    let scanner = YaraScanner::new().unwrap();
    let scan_result = scanner.scan_bytes(EICAR).unwrap();
    assert_eq!(scan_result.file_hash, file_hash);

    // Hash in ZK proof
    let zk_gen = ZkProofGenerator::new().unwrap();
    let proof = zk_gen.generate_threat_proof(&file_hash).unwrap();
    assert_eq!(proof.public_input, file_hash);

    // Hash persists through commitment
    let builder = CommitmentBuilder::new([0xBB; 32]);
    let _commitment = builder.build(1, true, 42, 1000, MIN_STAKE_KAS);
    // commitment is proposal-level, not file-hash-level — but the threat_hash
    // is what links detection to the proposal in the full system
}

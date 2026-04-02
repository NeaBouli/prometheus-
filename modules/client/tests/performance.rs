//! Performance tests for individual operations.
//!
//! Verifies that key operations meet timing requirements:
//! - Scanner scan: < 500ms for 10MB
//! - Detector analyze: < 100ms without model
//! - ZK proof generation: < 500ms
//! - Commitment build: < 1ms
//! - Slashing calculation: < 1ms

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use prometheus_client::ai::detection::AnomalyDetector;
use prometheus_client::ai::phi3::Phi3Model;
use prometheus_client::network::zk_proof::ZkProofGenerator;
use prometheus_client::security::scanner::{CompiledRule, YaraScanner};
use prometheus_validator::slashing::SlashingEngine;
use prometheus_validator::voting::commit::CommitmentBuilder;
use tokio::sync::Mutex;

#[test]
fn test_scanner_10mb_under_500ms() {
    let mut scanner = YaraScanner::new().unwrap();
    scanner.add_rule(CompiledRule {
        name: "PerfTest".to_string(),
        patterns: vec![b"MALWARE_SIG_PERF".to_vec()],
        required_matches: 1,
    });

    // Create 10MB of data
    let data = vec![0x41u8; 10 * 1024 * 1024];

    let start = Instant::now();
    let _result = scanner.scan_bytes(&data).unwrap();
    let elapsed = start.elapsed();

    eprintln!("Scanner 10MB: {:?}", elapsed);
    // 500ms in release mode; up to 5s in debug mode due to no optimizations
    let threshold = if cfg!(debug_assertions) {
        Duration::from_secs(5)
    } else {
        Duration::from_millis(500)
    };
    assert!(
        elapsed < threshold,
        "Scanner must handle 10MB in < {:?}, took {:?}",
        threshold,
        elapsed
    );
}

#[tokio::test]
async fn test_detector_without_model_under_100ms() {
    let model = Phi3Model::new(&PathBuf::from("/nonexistent/model.onnx")).unwrap();
    let scanner = YaraScanner::new().unwrap();
    let detector = AnomalyDetector::new(Arc::new(model), Arc::new(Mutex::new(scanner)));

    let data = vec![0x42u8; 1024];

    let start = Instant::now();
    let _result = detector.analyze_bytes(&data).await.unwrap();
    let elapsed = start.elapsed();

    eprintln!("Detector (no model): {:?}", elapsed);
    assert!(
        elapsed < Duration::from_millis(100),
        "Detector without model must finish in < 100ms, took {:?}",
        elapsed
    );
}

#[test]
fn test_zk_proof_under_500ms() {
    let gen = ZkProofGenerator::new().unwrap();
    let threat_hash = [0xAB; 32];

    let start = Instant::now();
    let _proof = gen.generate_threat_proof(&threat_hash).unwrap();
    let elapsed = start.elapsed();

    eprintln!("ZK proof gen: {:?}", elapsed);
    assert!(
        elapsed < Duration::from_millis(500),
        "ZK proof generation must complete in < 500ms, took {:?}",
        elapsed
    );
}

#[test]
fn test_commitment_build_under_1ms() {
    let builder = CommitmentBuilder::new([0xCC; 32]);

    let start = Instant::now();
    let _commitment = builder.build(1, true, 42, 100_000, 50_000);
    let elapsed = start.elapsed();

    eprintln!("Commitment build: {:?}", elapsed);
    assert!(
        elapsed < Duration::from_millis(1),
        "Commitment build must complete in < 1ms, took {:?}",
        elapsed
    );
}

#[test]
fn test_slashing_calculation_under_1ms() {
    let engine = SlashingEngine;

    let start = Instant::now();
    let _result = engine.calculate_penalty(100_000, 20, 6);
    let elapsed = start.elapsed();

    eprintln!("Slashing calc: {:?}", elapsed);
    assert!(
        elapsed < Duration::from_millis(1),
        "Slashing calculation must complete in < 1ms, took {:?}",
        elapsed
    );
}

#[test]
fn test_100_sequential_scans_performance() {
    let mut scanner = YaraScanner::new().unwrap();
    scanner.add_rule(CompiledRule {
        name: "BulkTest".to_string(),
        patterns: vec![b"BULK_TEST_PATTERN".to_vec()],
        required_matches: 1,
    });

    let data = vec![0x55u8; 100_000]; // 100KB per scan

    let start = Instant::now();
    for _ in 0..100 {
        let _ = scanner.scan_bytes(&data).unwrap();
    }
    let elapsed = start.elapsed();

    eprintln!("100 scans (100KB each): {:?}", elapsed);
    let threshold = if cfg!(debug_assertions) {
        Duration::from_secs(30)
    } else {
        Duration::from_secs(5)
    };
    assert!(
        elapsed < threshold,
        "100 sequential scans must complete in < {:?}, took {:?}",
        threshold,
        elapsed
    );
}

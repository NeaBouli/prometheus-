//! Integration tests for CID-bound development rule ingestion (GH-190).
//!
//! Covers valid load/scan, empty-snapshot clear, CID version/codec/hash/
//! canonical-case/length failures, strict grammar failures, every bound at its
//! boundary and boundary+1, unsupported rule types, inactive rules, duplicate
//! IDs/patterns, atomic rollback for mixed batches and the scanner's direct
//! API, and the beta/mainnet gate. No test prints rule IDs, CIDs, digests,
//! content, or patterns.

use prometheus_client::blockchain::krc20::{RuleType, ThreatRule};
use prometheus_client::blockchain::rule_ingest::{
    ingest_rule_snapshot, ingest_rule_snapshot_for_mode, RuleSnapshotEntry, MAX_CONTENT_BYTES,
    MAX_PATTERNS_PER_RULE, MAX_PATTERN_BYTES, MAX_RULES_PER_SNAPSHOT, MAX_RULE_ID_BYTES,
};
use prometheus_client::runtime::RuntimeMode;
use prometheus_client::security::scanner::{compute_sha256, CompiledRule, YaraScanner};
use std::process::Command;

const VECTORS: &str = include_str!("vectors/rule-ingest-v1.json");

/// Canonical raw CIDv1 sha2-256 CID for exact content bytes.
fn cid_for(content: &[u8]) -> String {
    cid_with_header([0x01, 0x55, 0x12, 0x20], content)
}

/// CID for content with a caller-chosen 4-byte header (for negative cases).
fn cid_with_header(header: [u8; 4], content: &[u8]) -> String {
    let digest = compute_sha256(content);
    let mut bytes = Vec::with_capacity(36);
    bytes.extend_from_slice(&header);
    bytes.extend_from_slice(&digest);
    multibase::encode(multibase::Base::Base32Lower, &bytes)
}

fn make_entry(
    rule_id: &str,
    rule_type: RuleType,
    active: bool,
    content: &[u8],
) -> RuleSnapshotEntry {
    RuleSnapshotEntry {
        rule: ThreatRule {
            rule_id: rule_id.to_string(),
            rule_type,
            ipfs_cid: cid_for(content),
            guardian_id: [0u8; 32],
            validator_consensus: 0.9,
            timestamp: 1_762_531_235,
            active,
        },
        content: content.to_vec(),
    }
}

fn yara_entry(rule_id: &str, content: &[u8]) -> RuleSnapshotEntry {
    make_entry(rule_id, RuleType::Yara, true, content)
}

/// Build valid rule content for `rule_id` from pattern literals.
fn rule_text(rule_id: &str, literals: &[&str]) -> String {
    let mut text = format!("rule {rule_id} {{\nstrings:\n");
    for (i, literal) in literals.iter().enumerate() {
        text.push_str(&format!("$p{i} = \"{literal}\"\n"));
    }
    text.push_str("condition:\nany of them\n}\n");
    text
}

/// Build valid rule content of exactly `target` bytes (uses up to 64
/// patterns; only called with sizes that fit the pattern bounds).
fn sized_rule_text(rule_id: &str, target: usize) -> String {
    let header = format!("rule {rule_id} {{\nstrings:\n");
    let footer = "condition:\nany of them\n}\n".to_string();
    let mut body = String::new();
    let mut i = 0usize;
    loop {
        let prefix = format!("$p{i} = \"");
        let fixed = header.len() + body.len() + prefix.len() + 2 + footer.len();
        assert!(fixed < target, "target too small for grammar overhead");
        let remaining = target - fixed;
        let lit_len = remaining.min(MAX_PATTERN_BYTES);
        // Unique prefix per literal: duplicate patterns are rejected.
        let tag = format!("{i:04}");
        assert!(lit_len >= tag.len(), "literal too small for uniqueness tag");
        body.push_str(&prefix);
        body.push_str(&tag);
        body.push_str(&"X".repeat(lit_len - tag.len()));
        body.push_str("\"\n");
        i += 1;
        if lit_len == remaining {
            break;
        }
    }
    let text = format!("{header}{body}{footer}");
    assert_eq!(text.len(), target);
    text
}

fn development() -> RuntimeMode {
    RuntimeMode::Development
}

#[test]
fn test_valid_snapshot_loads_and_scans() {
    let vectors: serde_json::Value = serde_json::from_str(VECTORS).unwrap();
    let vector = &vectors["valid"][0];
    let rule_id = vector["rule_id"].as_str().unwrap();
    let content = vector["content"].as_str().unwrap();
    let cid = vector["cid"].as_str().unwrap();
    let sha256 = vector["sha256"].as_str().unwrap();

    // The anchored vector must agree with the client's own primitives.
    assert_eq!(cid, cid_for(content.as_bytes()));
    assert_eq!(hex::encode(compute_sha256(content.as_bytes())), sha256);

    let entry = yara_entry(rule_id, content.as_bytes());
    assert_eq!(entry.rule.ipfs_cid, cid);

    let mut scanner = YaraScanner::new().unwrap();
    ingest_rule_snapshot_for_mode(development(), &mut scanner, &[entry]).unwrap();
    assert_eq!(scanner.rule_count(), 1);

    let hit = scanner
        .scan_bytes(vector["must_match"].as_str().unwrap().as_bytes())
        .unwrap();
    assert!(hit.is_threat);
    assert_eq!(hit.matched_rules.len(), 1);

    let miss = scanner
        .scan_bytes(vector["must_not_match"].as_str().unwrap().as_bytes())
        .unwrap();
    assert!(!miss.is_threat);
    assert!(miss.matched_rules.is_empty());
}

#[test]
fn test_public_entry_ingests_in_default_development_mode() {
    // PROMETHEUS_RUNTIME is unset/development in this test process.
    let content = rule_text("R1", &["ABC"]);
    let entry = yara_entry("R1", content.as_bytes());
    let mut scanner = YaraScanner::new().unwrap();
    ingest_rule_snapshot(&mut scanner, &[entry]).unwrap();
    assert_eq!(scanner.rule_count(), 1);
}

#[test]
fn test_process_beta_gate_cannot_be_weakened_by_explicit_development_mode() {
    const CHILD_ENV: &str = "PROMETHEUS_RULE_INGEST_GATE_CHILD";
    if std::env::var_os(CHILD_ENV).is_some() {
        let content = rule_text("R1", &["ABC"]);
        let entry = yara_entry("R1", content.as_bytes());
        let mut scanner = YaraScanner::new().unwrap();
        assert!(
            ingest_rule_snapshot_for_mode(RuntimeMode::Development, &mut scanner, &[entry])
                .is_err()
        );
        assert_eq!(scanner.rule_count(), 0);
        return;
    }

    let status = Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("test_process_beta_gate_cannot_be_weakened_by_explicit_development_mode")
        .env(CHILD_ENV, "1")
        .env("PROMETHEUS_RUNTIME", "beta")
        .status()
        .unwrap();
    assert!(status.success());
}

#[test]
fn test_empty_snapshot_clears_rules() {
    let content = rule_text("R1", &["ABC"]);
    let entry = yara_entry("R1", content.as_bytes());
    let mut scanner = YaraScanner::new().unwrap();
    ingest_rule_snapshot_for_mode(development(), &mut scanner, &[entry]).unwrap();
    assert_eq!(scanner.rule_count(), 1);

    // A complete empty snapshot is valid and clears all rules.
    ingest_rule_snapshot_for_mode(development(), &mut scanner, &[]).unwrap();
    assert_eq!(scanner.rule_count(), 0);
    let result = scanner.scan_bytes(b"ABC").unwrap();
    assert!(!result.is_threat);
}

#[test]
fn test_rejects_wrong_cid_version() {
    let content = rule_text("R1", &["ABC"]);
    let mut entry = yara_entry("R1", content.as_bytes());
    entry.rule.ipfs_cid = cid_with_header([0x02, 0x55, 0x12, 0x20], content.as_bytes());
    let mut scanner = YaraScanner::new().unwrap();
    assert!(ingest_rule_snapshot_for_mode(development(), &mut scanner, &[entry]).is_err());
}

#[test]
fn test_rejects_wrong_codec_dag_pb() {
    let vectors: serde_json::Value = serde_json::from_str(VECTORS).unwrap();
    let dag_pb_cid = vectors["invalid"][0]["cid"].as_str().unwrap();
    let vector = &vectors["valid"][0];
    let content = vector["content"].as_str().unwrap();
    // Same digest, dag-pb codec: must fail closed.
    assert_eq!(
        dag_pb_cid,
        cid_with_header([0x01, 0x70, 0x12, 0x20], content.as_bytes())
    );

    let mut entry = yara_entry(vector["rule_id"].as_str().unwrap(), content.as_bytes());
    entry.rule.ipfs_cid = dag_pb_cid.to_string();
    let mut scanner = YaraScanner::new().unwrap();
    assert!(ingest_rule_snapshot_for_mode(development(), &mut scanner, &[entry]).is_err());
}

#[test]
fn test_rejects_other_codecs() {
    let content = rule_text("R1", &["ABC"]);
    for codec in [0x70u8, 0x51, 0x00, 0x71] {
        let mut entry = yara_entry("R1", content.as_bytes());
        entry.rule.ipfs_cid = cid_with_header([0x01, codec, 0x12, 0x20], content.as_bytes());
        let mut scanner = YaraScanner::new().unwrap();
        assert!(ingest_rule_snapshot_for_mode(development(), &mut scanner, &[entry]).is_err());
    }
}

#[test]
fn test_rejects_wrong_hash() {
    let content = rule_text("R1", &["ABC"]);
    let mut entry = yara_entry("R1", content.as_bytes());
    entry.rule.ipfs_cid = cid_for(b"different content");
    let mut scanner = YaraScanner::new().unwrap();
    assert!(ingest_rule_snapshot_for_mode(development(), &mut scanner, &[entry]).is_err());
}

#[test]
fn test_rejects_non_canonical_case() {
    let content = rule_text("R1", &["ABC"]);
    let mut entry = yara_entry("R1", content.as_bytes());
    entry.rule.ipfs_cid = entry.rule.ipfs_cid.to_uppercase();
    let mut scanner = YaraScanner::new().unwrap();
    assert!(ingest_rule_snapshot_for_mode(development(), &mut scanner, &[entry]).is_err());
}

#[test]
fn test_rejects_wrong_cid_length() {
    let content = rule_text("R1", &["ABC"]);
    let digest = compute_sha256(content.as_bytes());
    let mut bytes = vec![0x01, 0x55, 0x12, 0x20];
    bytes.extend_from_slice(&digest[..31]); // 35 bytes total, not 36
    let mut entry = yara_entry("R1", content.as_bytes());
    entry.rule.ipfs_cid = multibase::encode(multibase::Base::Base32Lower, &bytes);
    let mut scanner = YaraScanner::new().unwrap();
    assert!(ingest_rule_snapshot_for_mode(development(), &mut scanner, &[entry]).is_err());
}

#[test]
fn test_rejects_oversized_cid_before_decode() {
    let content = rule_text("R1", &["ABC"]);
    let mut entry = yara_entry("R1", content.as_bytes());
    entry.rule.ipfs_cid = format!("b{}", "a".repeat(1_000_000));
    let mut scanner = YaraScanner::new().unwrap();
    assert!(ingest_rule_snapshot_for_mode(development(), &mut scanner, &[entry]).is_err());
    assert_eq!(scanner.rule_count(), 0);
}

#[test]
fn test_rejects_malformed_grammar() {
    let cases: Vec<String> = vec![
        // Missing closing brace
        "rule R1 {\nstrings:\n$a = \"ABC\"\ncondition:\nany of them\n".to_string(),
        // Wrong condition
        rule_text("R1", &["ABC"]).replace("any of them", "all of them"),
        // Comment line
        rule_text("R1", &["ABC"]).replace("strings:", "strings:\n// comment"),
        // Import directive
        rule_text("R1", &["ABC"]).replace("rule R1", "import \"pe\"\nrule R1"),
        // Escape sequence in literal
        "rule R1 {\nstrings:\n$a = \"A\\nB\"\ncondition:\nany of them\n}\n".to_string(),
        // Empty literal
        "rule R1 {\nstrings:\n$a = \"\"\ncondition:\nany of them\n}\n".to_string(),
        // Trailing content after closing brace
        format!("{}extra\n", rule_text("R1", &["ABC"])),
        // Missing strings section
        "rule R1 {\ncondition:\nany of them\n}\n".to_string(),
        // Header rule name mismatch
        rule_text("OTHER", &["ABC"]),
        // Missing condition section
        "rule R1 {\nstrings:\n$a = \"ABC\"\n}\n".to_string(),
        // Empty strings section
        "rule R1 {\nstrings:\ncondition:\nany of them\n}\n".to_string(),
        // Duplicate string identifier
        "rule R1 {\nstrings:\n$a = \"ABC\"\n$a = \"DEF\"\ncondition:\nany of them\n}\n".to_string(),
    ];
    for content in cases {
        let entry = yara_entry("R1", content.as_bytes());
        let mut scanner = YaraScanner::new().unwrap();
        assert!(ingest_rule_snapshot_for_mode(development(), &mut scanner, &[entry]).is_err());
        assert_eq!(scanner.rule_count(), 0);
    }
}

#[test]
fn test_bound_rule_count() {
    let build = |n: usize| -> Vec<RuleSnapshotEntry> {
        (0..n)
            .map(|i| {
                let id = format!("R{i}");
                let content = rule_text(&id, &["ABC"]);
                yara_entry(&id, content.as_bytes())
            })
            .collect()
    };

    let mut scanner = YaraScanner::new().unwrap();
    let snapshot = build(MAX_RULES_PER_SNAPSHOT);
    ingest_rule_snapshot_for_mode(development(), &mut scanner, &snapshot).unwrap();
    assert_eq!(scanner.rule_count(), MAX_RULES_PER_SNAPSHOT);

    let mut scanner = YaraScanner::new().unwrap();
    let snapshot = build(MAX_RULES_PER_SNAPSHOT + 1);
    assert!(ingest_rule_snapshot_for_mode(development(), &mut scanner, &snapshot).is_err());
    assert_eq!(scanner.rule_count(), 0);
}

#[test]
fn test_bound_content_bytes() {
    let content = sized_rule_text("R1", MAX_CONTENT_BYTES);
    let entry = yara_entry("R1", content.as_bytes());
    let mut scanner = YaraScanner::new().unwrap();
    ingest_rule_snapshot_for_mode(development(), &mut scanner, &[entry]).unwrap();
    assert_eq!(scanner.rule_count(), 1);

    // Boundary + 1: length check fires before grammar, so filler bytes work.
    let oversized = vec![b'x'; MAX_CONTENT_BYTES + 1];
    let entry = yara_entry("R1", &oversized);
    let mut scanner = YaraScanner::new().unwrap();
    assert!(ingest_rule_snapshot_for_mode(development(), &mut scanner, &[entry]).is_err());
}

#[test]
fn test_bound_patterns_per_rule() {
    let at_limit: Vec<String> = (0..MAX_PATTERNS_PER_RULE)
        .map(|i| format!("PAT{i}"))
        .collect();
    let refs: Vec<&str> = at_limit.iter().map(String::as_str).collect();
    let content = rule_text("R1", &refs);
    let entry = yara_entry("R1", content.as_bytes());
    let mut scanner = YaraScanner::new().unwrap();
    ingest_rule_snapshot_for_mode(development(), &mut scanner, &[entry]).unwrap();
    assert_eq!(scanner.rule_count(), 1);

    let over: Vec<String> = (0..MAX_PATTERNS_PER_RULE + 1)
        .map(|i| format!("PAT{i}"))
        .collect();
    let refs: Vec<&str> = over.iter().map(String::as_str).collect();
    let content = rule_text("R1", &refs);
    let entry = yara_entry("R1", content.as_bytes());
    let mut scanner = YaraScanner::new().unwrap();
    assert!(ingest_rule_snapshot_for_mode(development(), &mut scanner, &[entry]).is_err());
}

#[test]
fn test_bound_pattern_bytes() {
    let literal = "X".repeat(MAX_PATTERN_BYTES);
    let content = rule_text("R1", &[&literal]);
    let entry = yara_entry("R1", content.as_bytes());
    let mut scanner = YaraScanner::new().unwrap();
    ingest_rule_snapshot_for_mode(development(), &mut scanner, &[entry]).unwrap();
    assert_eq!(scanner.rule_count(), 1);

    let literal = "X".repeat(MAX_PATTERN_BYTES + 1);
    let content = rule_text("R1", &[&literal]);
    let entry = yara_entry("R1", content.as_bytes());
    let mut scanner = YaraScanner::new().unwrap();
    assert!(ingest_rule_snapshot_for_mode(development(), &mut scanner, &[entry]).is_err());
}

#[test]
fn test_bound_rule_id() {
    let id = "a".repeat(MAX_RULE_ID_BYTES);
    let content = rule_text(&id, &["ABC"]);
    let entry = yara_entry(&id, content.as_bytes());
    let mut scanner = YaraScanner::new().unwrap();
    ingest_rule_snapshot_for_mode(development(), &mut scanner, &[entry]).unwrap();
    assert_eq!(scanner.rule_count(), 1);

    let id = "a".repeat(MAX_RULE_ID_BYTES + 1);
    let content = rule_text(&id, &["ABC"]);
    let entry = yara_entry(&id, content.as_bytes());
    let mut scanner = YaraScanner::new().unwrap();
    assert!(ingest_rule_snapshot_for_mode(development(), &mut scanner, &[entry]).is_err());

    for bad_id in ["", "PROM.RULE", "PROM RULE", "PROM/RULE", "RULE!"] {
        let content = rule_text("R1", &["ABC"]);
        let entry = yara_entry(bad_id, content.as_bytes());
        let mut scanner = YaraScanner::new().unwrap();
        assert!(ingest_rule_snapshot_for_mode(development(), &mut scanner, &[entry]).is_err());
    }
}

#[test]
fn test_rejects_empty_content() {
    let entry = yara_entry("R1", b"");
    let mut scanner = YaraScanner::new().unwrap();
    assert!(ingest_rule_snapshot_for_mode(development(), &mut scanner, &[entry]).is_err());
}

#[test]
fn test_rejects_unsupported_rule_types() {
    let content = rule_text("R1", &["ABC"]);
    for rule_type in [RuleType::Stix, RuleType::Sigma, RuleType::Suricata] {
        let entry = make_entry("R1", rule_type, true, content.as_bytes());
        let mut scanner = YaraScanner::new().unwrap();
        assert!(ingest_rule_snapshot_for_mode(development(), &mut scanner, &[entry]).is_err());
    }
}

#[test]
fn test_rejects_inactive_rule() {
    let content = rule_text("R1", &["ABC"]);
    let entry = make_entry("R1", RuleType::Yara, false, content.as_bytes());
    let mut scanner = YaraScanner::new().unwrap();
    assert!(ingest_rule_snapshot_for_mode(development(), &mut scanner, &[entry]).is_err());
}

#[test]
fn test_rejects_duplicate_rule_ids() {
    let first = yara_entry("R1", rule_text("R1", &["ABC"]).as_bytes());
    let second = yara_entry("R1", rule_text("R1", &["DEF"]).as_bytes());
    let mut scanner = YaraScanner::new().unwrap();
    assert!(ingest_rule_snapshot_for_mode(development(), &mut scanner, &[first, second]).is_err());
}

#[test]
fn test_rejects_duplicate_patterns_in_rule() {
    let content = "rule R1 {\nstrings:\n$a = \"ABC\"\n$b = \"ABC\"\ncondition:\nany of them\n}\n";
    let entry = yara_entry("R1", content.as_bytes());
    let mut scanner = YaraScanner::new().unwrap();
    assert!(ingest_rule_snapshot_for_mode(development(), &mut scanner, &[entry]).is_err());
}

#[test]
fn test_mixed_batch_atomic_rollback() {
    let mut scanner = YaraScanner::new().unwrap();
    scanner
        .add_rule(CompiledRule {
            name: "PRIOR".to_string(),
            patterns: vec![b"PRIOR-SIG".to_vec()],
            required_matches: 1,
        })
        .unwrap();

    let good = yara_entry("R1", rule_text("R1", &["ABC"]).as_bytes());
    let bad = make_entry(
        "R2",
        RuleType::Yara,
        false,
        rule_text("R2", &["DEF"]).as_bytes(),
    );
    assert!(ingest_rule_snapshot_for_mode(development(), &mut scanner, &[good, bad]).is_err());

    // Prior scanner behavior and count are preserved.
    assert_eq!(scanner.rule_count(), 1);
    let result = scanner.scan_bytes(b"contains PRIOR-SIG here").unwrap();
    assert!(result.is_threat);
    assert_eq!(result.matched_rules, vec!["PRIOR"]);
    let result = scanner.scan_bytes(b"ABC").unwrap();
    assert!(!result.is_threat);
}

#[test]
fn test_scanner_direct_api_atomic_rollback() {
    let mut scanner = YaraScanner::new().unwrap();
    scanner
        .add_rule(CompiledRule {
            name: "PRIOR".to_string(),
            patterns: vec![b"PRIOR-SIG".to_vec()],
            required_matches: 1,
        })
        .unwrap();

    let invalid = vec![
        ("Ok".to_string(), vec![b"ABC".to_vec()]),
        ("Bad".to_string(), vec![Vec::new()]),
    ];
    assert!(scanner.load_rules_from_patterns(&invalid).is_err());
    assert_eq!(scanner.rule_count(), 1);
    let result = scanner.scan_bytes(b"PRIOR-SIG").unwrap();
    assert_eq!(result.matched_rules, vec!["PRIOR"]);
}

#[test]
fn test_beta_and_mainnet_gate_rejects_ingestion() {
    let content = rule_text("R1", &["ABC"]);
    for mode in [RuntimeMode::Beta, RuntimeMode::Mainnet] {
        let entry = yara_entry("R1", content.as_bytes());
        let mut scanner = YaraScanner::new().unwrap();
        assert!(ingest_rule_snapshot_for_mode(mode, &mut scanner, &[entry]).is_err());
        assert_eq!(scanner.rule_count(), 0);
    }
}

#[test]
fn test_error_never_exposes_sensitive_values() {
    let content = rule_text("R1", &["SECRET-PATTERN"]);
    let mut entry = yara_entry("R1", content.as_bytes());
    entry.rule.ipfs_cid = cid_for(b"tampered");
    let mut scanner = YaraScanner::new().unwrap();
    let err = ingest_rule_snapshot_for_mode(development(), &mut scanner, &[entry]).unwrap_err();

    let shown = format!("{err}");
    let debugged = format!("{err:?}");
    assert_eq!(shown, "invalid CID-bound rule snapshot");
    for text in [shown, debugged] {
        assert!(!text.contains("R1"));
        assert!(!text.contains("SECRET-PATTERN"));
        assert!(!text.contains("baf"));
    }
}

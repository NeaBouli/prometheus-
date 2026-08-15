//! YARA-based threat scanner module.
//!
//! Scans files against loaded threat detection rules.
//! Uses pattern matching for YARA-style rules.
//! ScanResult contains matched rules, threat status, and confidence.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use log::info;
use sha2::{Digest, Sha256};

/// Result of scanning a file or byte buffer.
#[derive(Debug, Clone)]
pub struct ScanResult {
    /// Names of matched rules
    pub matched_rules: Vec<String>,
    /// Whether any threat was detected
    pub is_threat: bool,
    /// Confidence score (0.0 - 1.0)
    pub confidence: f64,
    /// SHA-256 hash of scanned content
    pub file_hash: [u8; 32],
}

/// A compiled YARA-style rule for threat detection.
#[derive(Debug, Clone)]
pub struct CompiledRule {
    /// Rule name (e.g. "PROM-RULE-2026-0001")
    pub name: String,
    /// Byte patterns to match
    pub patterns: Vec<Vec<u8>>,
    /// Minimum number of patterns that must match
    pub required_matches: usize,
}

/// YARA-based scanner for threat detection.
/// Loads rules from on-chain ThreatRule definitions and scans files.
pub struct YaraScanner {
    rules: Vec<CompiledRule>,
}

impl YaraScanner {
    /// Create a new scanner with no rules loaded.
    pub fn new() -> Result<Self> {
        Ok(Self { rules: Vec::new() })
    }

    /// Load rules from ThreatRule definitions.
    /// Each rule's YARA content is parsed into byte patterns.
    /// The full set is validated before it replaces the current rules
    /// atomically; on failure the prior rules are preserved.
    pub fn load_rules_from_patterns(&mut self, rules: &[(String, Vec<Vec<u8>>)]) -> Result<()> {
        let compiled: Vec<CompiledRule> = rules
            .iter()
            .map(|(name, patterns)| CompiledRule {
                name: name.clone(),
                patterns: patterns.clone(),
                required_matches: 1,
            })
            .collect();
        self.replace_rules(compiled)
    }

    /// Add a single compiled rule.
    /// Rejects invalid rules (empty name, empty patterns, empty pattern
    /// entries, invalid required_matches) and duplicate rule names.
    pub fn add_rule(&mut self, rule: CompiledRule) -> Result<()> {
        validate_rule(&rule)?;
        if self.rules.iter().any(|r| r.name == rule.name) {
            anyhow::bail!("duplicate rule name");
        }
        self.rules.push(rule);
        Ok(())
    }

    /// Atomically replace all loaded rules with a validated set.
    /// On any validation failure the prior rules are preserved.
    pub fn replace_rules(&mut self, rules: Vec<CompiledRule>) -> Result<()> {
        validate_rule_set(&rules)?;
        self.rules = rules;
        info!("Loaded {} YARA rules", self.rules.len());
        Ok(())
    }

    /// Scan a file at the given path against all loaded rules.
    pub fn scan_file(&self, path: &Path) -> Result<ScanResult> {
        let data = fs::read(path).context("Failed to read file for scanning")?;
        self.scan_bytes(&data)
    }

    /// Scan raw bytes against all loaded rules.
    pub fn scan_bytes(&self, data: &[u8]) -> Result<ScanResult> {
        let file_hash = compute_sha256(data);
        let mut matched_rules = Vec::new();
        let mut max_confidence = 0.0_f64;

        for rule in &self.rules {
            let matches = count_pattern_matches(&rule.patterns, data);
            if matches >= rule.required_matches {
                matched_rules.push(rule.name.clone());
                // Confidence scales with match ratio
                let ratio = matches as f64 / rule.patterns.len() as f64;
                max_confidence = max_confidence.max(ratio);
            }
        }

        let is_threat = !matched_rules.is_empty();

        Ok(ScanResult {
            matched_rules,
            is_threat,
            confidence: if is_threat { max_confidence } else { 0.0 },
            file_hash,
        })
    }

    /// Get the number of loaded rules.
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }
}

/// Compute SHA-256 hash of data.
pub fn compute_sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// Validate one compiled rule. Error messages stay generic on purpose: they
/// must not carry rule names or patterns into logs.
fn validate_rule(rule: &CompiledRule) -> Result<()> {
    if rule.name.is_empty() {
        anyhow::bail!("rule name must not be empty");
    }
    if rule.patterns.is_empty() {
        anyhow::bail!("rule must contain at least one pattern");
    }
    if rule.patterns.iter().any(|p| p.is_empty()) {
        anyhow::bail!("rule patterns must not be empty");
    }
    if rule.required_matches == 0 || rule.required_matches > rule.patterns.len() {
        anyhow::bail!("invalid required_matches");
    }
    Ok(())
}

/// Validate a complete rule set: every rule valid and no duplicate names.
fn validate_rule_set(rules: &[CompiledRule]) -> Result<()> {
    let mut names = std::collections::HashSet::with_capacity(rules.len());
    for rule in rules {
        validate_rule(rule)?;
        if !names.insert(rule.name.as_str()) {
            anyhow::bail!("duplicate rule name");
        }
    }
    Ok(())
}

/// Count how many patterns match in the data.
/// Uses memchr-style first-byte lookup for fast scanning.
fn count_pattern_matches(patterns: &[Vec<u8>], data: &[u8]) -> usize {
    patterns
        .iter()
        .filter(|pattern| {
            if pattern.is_empty() {
                return false;
            }
            let plen = pattern.len();
            if plen > data.len() {
                return false;
            }
            let first = pattern[0];
            // Use memchr to find candidate positions (much faster than byte-by-byte)
            let mut start = 0;
            while let Some(offset) = memchr_single(first, &data[start..]) {
                let pos = start + offset;
                if pos + plen > data.len() {
                    break;
                }
                if data[pos..pos + plen] == **pattern {
                    return true;
                }
                start = pos + 1;
            }
            false
        })
        .count()
}

/// Fast single-byte search (equivalent to memchr).
#[inline]
fn memchr_single(needle: u8, haystack: &[u8]) -> Option<usize> {
    haystack.iter().position(|&b| b == needle)
}

/// Parse a simple YARA-like rule string into patterns.
/// Supports format: rule Name { strings: $a = "pattern" condition: $a }
pub fn parse_simple_yara_rule(name: &str, rule_text: &str) -> Result<CompiledRule> {
    let mut patterns = Vec::new();

    // Extract quoted string patterns
    let mut in_strings = false;
    for line in rule_text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("strings:") || trimmed.contains("strings:") {
            in_strings = true;
        }
        if trimmed.starts_with("condition:") {
            in_strings = false;
        }
        if in_strings {
            // Find quoted patterns like $a = "EICAR"
            if let Some(start) = trimmed.find('"') {
                if let Some(end) = trimmed[start + 1..].find('"') {
                    let pattern = &trimmed[start + 1..start + 1 + end];
                    patterns.push(pattern.as_bytes().to_vec());
                }
            }
        }
    }

    if patterns.is_empty() || patterns.iter().any(Vec::is_empty) {
        anyhow::bail!("rule must contain nonempty patterns");
    }

    Ok(CompiledRule {
        name: name.to_string(),
        patterns,
        required_matches: 1,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_new_scanner() {
        let scanner = YaraScanner::new().unwrap();
        assert_eq!(scanner.rule_count(), 0);
    }

    #[test]
    fn test_scan_bytes_no_rules() {
        let scanner = YaraScanner::new().unwrap();
        let result = scanner.scan_bytes(b"hello world").unwrap();
        assert!(!result.is_threat);
        assert!(result.matched_rules.is_empty());
        assert_eq!(result.confidence, 0.0);
    }

    #[test]
    fn test_scan_bytes_with_match() {
        let mut scanner = YaraScanner::new().unwrap();
        scanner
            .add_rule(CompiledRule {
                name: "TestRule".to_string(),
                patterns: vec![b"EICAR".to_vec()],
                required_matches: 1,
            })
            .unwrap();

        let data = b"This file contains EICAR test string";
        let result = scanner.scan_bytes(data).unwrap();
        assert!(result.is_threat);
        assert_eq!(result.matched_rules, vec!["TestRule"]);
        assert_eq!(result.confidence, 1.0);
    }

    #[test]
    fn test_scan_bytes_no_match() {
        let mut scanner = YaraScanner::new().unwrap();
        scanner
            .add_rule(CompiledRule {
                name: "TestRule".to_string(),
                patterns: vec![b"MALWARE_SIGNATURE".to_vec()],
                required_matches: 1,
            })
            .unwrap();

        let result = scanner.scan_bytes(b"clean file content").unwrap();
        assert!(!result.is_threat);
        assert!(result.matched_rules.is_empty());
    }

    #[test]
    fn test_scan_file() {
        let mut scanner = YaraScanner::new().unwrap();
        scanner
            .add_rule(CompiledRule {
                name: "EicarTest".to_string(),
                patterns: vec![b"EICAR".to_vec()],
                required_matches: 1,
            })
            .unwrap();

        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
            .unwrap();

        let result = scanner.scan_file(tmp.path()).unwrap();
        assert!(result.is_threat);
        assert_eq!(result.matched_rules, vec!["EicarTest"]);
    }

    #[test]
    fn test_multiple_rules() {
        let mut scanner = YaraScanner::new().unwrap();
        scanner
            .add_rule(CompiledRule {
                name: "Rule1".to_string(),
                patterns: vec![b"EICAR".to_vec()],
                required_matches: 1,
            })
            .unwrap();
        scanner
            .add_rule(CompiledRule {
                name: "Rule2".to_string(),
                patterns: vec![b"MALWARE".to_vec()],
                required_matches: 1,
            })
            .unwrap();

        let data = b"Contains EICAR but not the other signature";
        let result = scanner.scan_bytes(data).unwrap();
        assert!(result.is_threat);
        assert_eq!(result.matched_rules, vec!["Rule1"]);
    }

    #[test]
    fn test_sha256_hash() {
        let hash = compute_sha256(b"test");
        // Known SHA-256 of "test"
        assert_eq!(
            hex::encode(hash),
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
        );
    }

    #[test]
    fn test_parse_simple_yara_rule() {
        let rule_text = r#"
            rule TestRule {
                strings:
                    $a = "EICAR"
                    $b = "TEST"
                condition:
                    $a or $b
            }
        "#;
        let compiled = parse_simple_yara_rule("TestRule", rule_text).unwrap();
        assert_eq!(compiled.name, "TestRule");
        assert_eq!(compiled.patterns.len(), 2);
        assert_eq!(compiled.patterns[0], b"EICAR");
        assert_eq!(compiled.patterns[1], b"TEST");
    }

    #[test]
    fn test_parse_simple_yara_rule_rejects_empty_or_missing_patterns() {
        let empty = r#"
            rule Empty {
                strings:
                    $a = ""
                condition:
                    $a
            }
        "#;
        assert!(parse_simple_yara_rule("Empty", empty).is_err());
        assert!(parse_simple_yara_rule("Missing", "rule Missing { condition: true }").is_err());
        assert_eq!(count_pattern_matches(&[Vec::new()], b"anything"), 0);
    }

    #[test]
    fn test_load_rules_from_patterns() {
        let mut scanner = YaraScanner::new().unwrap();
        let rules = vec![
            ("Rule1".to_string(), vec![b"pattern1".to_vec()]),
            ("Rule2".to_string(), vec![b"pattern2".to_vec()]),
        ];
        scanner.load_rules_from_patterns(&rules).unwrap();
        assert_eq!(scanner.rule_count(), 2);
    }

    #[test]
    fn test_confidence_scales_with_matches() {
        let mut scanner = YaraScanner::new().unwrap();
        scanner
            .add_rule(CompiledRule {
                name: "MultiPattern".to_string(),
                patterns: vec![b"AAA".to_vec(), b"BBB".to_vec(), b"CCC".to_vec()],
                required_matches: 1,
            })
            .unwrap();

        // Only 1 of 3 patterns match
        let result = scanner.scan_bytes(b"data with AAA inside").unwrap();
        assert!(result.is_threat);
        assert!((result.confidence - 1.0 / 3.0).abs() < 0.01);
    }

    fn valid_rule(name: &str) -> CompiledRule {
        CompiledRule {
            name: name.to_string(),
            patterns: vec![b"EICAR".to_vec()],
            required_matches: 1,
        }
    }

    #[test]
    fn test_add_rule_rejects_empty_patterns() {
        let mut scanner = YaraScanner::new().unwrap();
        let rule = CompiledRule {
            patterns: Vec::new(),
            ..valid_rule("EmptyPatterns")
        };
        assert!(scanner.add_rule(rule).is_err());
        assert_eq!(scanner.rule_count(), 0);
    }

    #[test]
    fn test_add_rule_rejects_empty_pattern_entry() {
        let mut scanner = YaraScanner::new().unwrap();
        let rule = CompiledRule {
            patterns: vec![Vec::new()],
            ..valid_rule("EmptyEntry")
        };
        assert!(scanner.add_rule(rule).is_err());
        assert_eq!(scanner.rule_count(), 0);
    }

    #[test]
    fn test_add_rule_rejects_invalid_required_matches() {
        let mut scanner = YaraScanner::new().unwrap();
        let zero = CompiledRule {
            required_matches: 0,
            ..valid_rule("ZeroRequired")
        };
        assert!(scanner.add_rule(zero).is_err());
        let too_many = CompiledRule {
            required_matches: 2,
            ..valid_rule("TooManyRequired")
        };
        assert!(scanner.add_rule(too_many).is_err());
        assert_eq!(scanner.rule_count(), 0);
    }

    #[test]
    fn test_add_rule_rejects_duplicate_name() {
        let mut scanner = YaraScanner::new().unwrap();
        scanner.add_rule(valid_rule("Dup")).unwrap();
        assert!(scanner.add_rule(valid_rule("Dup")).is_err());
        assert_eq!(scanner.rule_count(), 1);
    }

    #[test]
    fn test_replace_rules_is_atomic_on_invalid_set() {
        let mut scanner = YaraScanner::new().unwrap();
        scanner.add_rule(valid_rule("Prior")).unwrap();

        let invalid = CompiledRule {
            patterns: Vec::new(),
            ..valid_rule("Bad")
        };
        assert!(scanner
            .replace_rules(vec![valid_rule("Good"), invalid])
            .is_err());
        assert_eq!(scanner.rule_count(), 1);

        assert!(scanner
            .replace_rules(vec![valid_rule("A"), valid_rule("B")])
            .is_ok());
        assert_eq!(scanner.rule_count(), 2);
    }

    #[test]
    fn test_replace_rules_rejects_duplicate_names() {
        let mut scanner = YaraScanner::new().unwrap();
        assert!(scanner
            .replace_rules(vec![valid_rule("Same"), valid_rule("Same")])
            .is_err());
        assert_eq!(scanner.rule_count(), 0);
    }

    #[test]
    fn test_load_rules_from_patterns_atomic_rollback() {
        let mut scanner = YaraScanner::new().unwrap();
        scanner.add_rule(valid_rule("Prior")).unwrap();

        let rules = vec![
            ("Ok".to_string(), vec![b"pattern1".to_vec()]),
            ("Bad".to_string(), vec![Vec::new()]),
        ];
        assert!(scanner.load_rules_from_patterns(&rules).is_err());
        // Prior state preserved after a failed load.
        assert_eq!(scanner.rule_count(), 1);
        let result = scanner.scan_bytes(b"EICAR").unwrap();
        assert_eq!(result.matched_rules, vec!["Prior"]);
    }
}

//! YARA-based threat scanner module.
//!
//! Scans files against loaded threat detection rules.
//! Uses pattern matching for YARA-style rules.
//! ScanResult contains matched rules, threat status, and confidence.

use std::fs::File;
use std::io::Read;
use std::path::Path;

use anyhow::{bail, Context, Result};
use log::info;
use sha2::{Digest, Sha256};

/// Maximum file size accepted by [`YaraScanner::scan_file`] (16 MiB, development client).
pub const MAX_SCAN_FILE_BYTES: u64 = 16 * 1024 * 1024;

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

    /// Install a rule set already validated by the crate's preparation path.
    pub(crate) fn install_prevalidated(&mut self, rules: Vec<CompiledRule>) {
        self.rules = rules;
        info!("Loaded {} prevalidated YARA rules", self.rules.len());
    }

    /// Scan a file at the given path against all loaded rules.
    /// Rejects empty files and files larger than [`MAX_SCAN_FILE_BYTES`]; the read
    /// itself is capped, so file growth or special files cannot bypass the limit.
    pub fn scan_file(&self, path: &Path) -> Result<ScanResult> {
        let file = File::open(path).context("Failed to read file for scanning")?;
        let mut data = Vec::new();
        file.take(MAX_SCAN_FILE_BYTES + 1)
            .read_to_end(&mut data)
            .context("Failed to read file for scanning")?;
        if data.is_empty() {
            bail!("File for scanning is empty");
        }
        if data.len() as u64 > MAX_SCAN_FILE_BYTES {
            bail!("File for scanning exceeds size limit");
        }
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
pub(crate) fn validate_rule_set(rules: &[CompiledRule]) -> Result<()> {
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

/// Parse a minimal YARA-like rule string into patterns.
///
/// This is a bounded development grammar, not a YARA engine. Anything the
/// matcher does not implement is rejected instead of being approximated:
///
/// ```text
/// rule <name> {
/// strings:
/// $id = "literal"        (1+ lines, nonempty printable ASCII, no escapes)
/// condition:
/// any of them | $id | $a or $b or ...
/// }
/// ```
///
/// A `$id` or `or`-chain condition is accepted only if it references every
/// declared string exactly once, i.e. it is exactly any-of semantics.
pub fn parse_simple_yara_rule(name: &str, rule_text: &str) -> Result<CompiledRule> {
    // 0 = header, 1 = strings marker, 2 = string lines, 3 = condition value,
    // 4 = closing brace, 5 = closed.
    let mut stage = 0u8;
    let mut ids: Vec<&str> = Vec::new();
    let mut patterns: Vec<Vec<u8>> = Vec::new();

    for raw_line in rule_text.lines() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        match stage {
            0 => {
                let tokens: Vec<&str> = line.split_whitespace().collect();
                if tokens.len() != 3 || tokens[0] != "rule" || tokens[1] != name || tokens[2] != "{"
                {
                    anyhow::bail!("unsupported rule header");
                }
                stage = 1;
            }
            1 if line == "strings:" => stage = 2,
            2 if line == "condition:" => {
                if patterns.is_empty() {
                    anyhow::bail!("rule must contain nonempty patterns");
                }
                stage = 3;
            }
            2 => {
                let (id, literal) = parse_string_line(line)?;
                if ids.contains(&id) || patterns.iter().any(|p| p == literal) {
                    anyhow::bail!("duplicate string identifier or literal");
                }
                ids.push(id);
                patterns.push(literal.to_vec());
            }
            3 => {
                if !is_any_of_condition(line, &ids) {
                    anyhow::bail!("unsupported rule condition");
                }
                stage = 4;
            }
            4 if line == "}" => stage = 5,
            _ => anyhow::bail!("malformed rule"),
        }
    }

    if stage != 5 {
        anyhow::bail!("malformed rule");
    }

    Ok(CompiledRule {
        name: name.to_string(),
        patterns,
        required_matches: 1,
    })
}

/// Parse one `$id = "literal"` line. The identifier is 1..=32 ASCII
/// alphanumerics or underscore; the literal is nonempty printable ASCII
/// without `"` or `\`. Hex strings, regexes and modifiers are rejected.
fn parse_string_line(line: &str) -> Result<(&str, &[u8])> {
    let malformed = || anyhow::anyhow!("unsupported string definition");
    let rest = line.strip_prefix('$').ok_or_else(malformed)?;
    let (id, rest) = rest.split_once('=').ok_or_else(malformed)?;
    let id = id.trim_end();
    if !is_identifier(id) {
        return Err(malformed());
    }
    let literal = rest
        .trim_start()
        .strip_prefix('"')
        .and_then(|r| r.strip_suffix('"'))
        .ok_or_else(malformed)?;
    if literal.is_empty()
        || !literal
            .bytes()
            .all(|b| (0x20..=0x7e).contains(&b) && b != b'"' && b != b'\\')
    {
        return Err(malformed());
    }
    Ok((id, literal.as_bytes()))
}

fn is_identifier(id: &str) -> bool {
    !id.is_empty() && id.len() <= 32 && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// True only for conditions whose semantics are exactly any-of over all
/// declared strings: `any of them`, or `$x` / `$x or $y ...` naming every
/// declared identifier exactly once.
fn is_any_of_condition(condition: &str, ids: &[&str]) -> bool {
    let tokens: Vec<&str> = condition.split_whitespace().collect();
    if tokens == ["any", "of", "them"] {
        return true;
    }
    if tokens.len() != ids.len() * 2 - 1 {
        return false;
    }
    let mut referenced: Vec<&str> = Vec::with_capacity(ids.len());
    for (i, token) in tokens.iter().enumerate() {
        if i % 2 == 1 {
            if *token != "or" {
                return false;
            }
            continue;
        }
        match token.strip_prefix('$') {
            Some(id) if ids.contains(&id) && !referenced.contains(&id) => referenced.push(id),
            _ => return false,
        }
    }
    referenced.len() == ids.len()
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

    fn eicar_scanner() -> YaraScanner {
        let mut scanner = YaraScanner::new().unwrap();
        scanner
            .add_rule(CompiledRule {
                name: "EicarTest".to_string(),
                patterns: vec![b"EICAR".to_vec()],
                required_matches: 1,
            })
            .unwrap();
        scanner
    }

    fn sized_file_with_tail(len: u64, tail: &[u8]) -> NamedTempFile {
        let tmp = NamedTempFile::new().unwrap();
        tmp.as_file().set_len(len - tail.len() as u64).unwrap();
        let mut f = tmp.reopen().unwrap();
        std::io::Seek::seek(&mut f, std::io::SeekFrom::End(0)).unwrap();
        f.write_all(tail).unwrap();
        tmp
    }

    #[test]
    fn test_scan_file_rejects_empty() {
        let tmp = NamedTempFile::new().unwrap();
        let err = eicar_scanner().scan_file(tmp.path()).unwrap_err();
        assert_eq!(err.to_string(), "File for scanning is empty");
    }

    #[test]
    fn test_scan_file_accepts_exact_limit() {
        let tmp = sized_file_with_tail(MAX_SCAN_FILE_BYTES, b"EICAR");
        let result = eicar_scanner().scan_file(tmp.path()).unwrap();
        assert!(result.is_threat);
        assert_eq!(result.matched_rules, vec!["EicarTest"]);
    }

    #[test]
    fn test_scan_file_rejects_over_limit() {
        let tmp = sized_file_with_tail(MAX_SCAN_FILE_BYTES + 1, b"EICAR");
        let err = eicar_scanner().scan_file(tmp.path()).unwrap_err();
        assert_eq!(err.to_string(), "File for scanning exceeds size limit");
    }

    #[cfg(unix)]
    #[test]
    fn test_scan_file_caps_unbounded_special_file() {
        let err = eicar_scanner()
            .scan_file(Path::new("/dev/zero"))
            .unwrap_err();
        assert_eq!(err.to_string(), "File for scanning exceeds size limit");
    }

    #[test]
    fn test_scan_file_missing_error_is_generic() {
        let err = eicar_scanner()
            .scan_file(Path::new("/nonexistent/prometheus-scan-target"))
            .unwrap_err();
        assert_eq!(err.to_string(), "Failed to read file for scanning");
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

    fn rule_with(strings: &str, condition: &str) -> String {
        format!("rule R {{\nstrings:\n{strings}\ncondition:\n{condition}\n}}\n")
    }

    #[test]
    fn test_parse_rejects_all_of_them_instead_of_degrading_to_any_of() {
        let text = rule_with("$a = \"AAA\"\n$b = \"BBB\"", "all of them");
        assert!(parse_simple_yara_rule("R", &text).is_err());

        // The same strings under the supported condition still load, and
        // they match on a single pattern (any-of), which is exactly why
        // `all of them` must not be accepted as the same rule.
        let any = rule_with("$a = \"AAA\"\n$b = \"BBB\"", "any of them");
        let compiled = parse_simple_yara_rule("R", &any).unwrap();
        let mut scanner = YaraScanner::new().unwrap();
        scanner.add_rule(compiled).unwrap();
        assert_eq!(
            scanner.scan_bytes(b"only AAA").unwrap().matched_rules,
            vec!["R"]
        );
        assert!(!scanner.scan_bytes(b"neither").unwrap().is_threat);
    }

    #[test]
    fn test_parse_rejects_unsupported_conditions() {
        let strings = "$a = \"AAA\"\n$b = \"BBB\"";
        for condition in [
            "all of them",
            "2 of them",
            "any of ($a*)",
            "$a and $b",
            "$a or $b and $a",
            "($a or $b)",
            "$a",
            "$a or $a",
            "$a or $c",
            "not $a or $b",
            "true",
            "any of them or $a",
            "",
        ] {
            let text = rule_with(strings, condition);
            assert!(
                parse_simple_yara_rule("R", &text).is_err(),
                "condition {condition:?} must be rejected"
            );
        }
    }

    #[test]
    fn test_parse_rejects_unsupported_string_definitions() {
        for strings in [
            "$a = { 4D 5A }",
            "$a = /evil[0-9]+/",
            "$a = \"es\\x41cape\"",
            "$a = \"quo\\\"te\"",
            "$a = \"AAA\" nocase",
            "$a = \"AAA\" wide ascii",
            "$a = \"\"",
            "$ = \"AAA\"",
            "a = \"AAA\"",
            "$a-b = \"AAA\"",
            "$a = \"AAA\"\n$a = \"BBB\"",
            "$a = \"AAA\"\n$b = \"AAA\"",
            "$a = \"tab\there\"",
            "// comment",
        ] {
            let text = rule_with(strings, "any of them");
            assert!(
                parse_simple_yara_rule("R", &text).is_err(),
                "strings {strings:?} must be rejected"
            );
        }
    }

    #[test]
    fn test_parse_rejects_malformed_sections() {
        let cases = [
            // Header mismatch / missing.
            "rule Other {\nstrings:\n$a = \"AAA\"\ncondition:\nany of them\n}",
            "rule R : tag {\nstrings:\n$a = \"AAA\"\ncondition:\nany of them\n}",
            "strings:\n$a = \"AAA\"\ncondition:\nany of them\n}",
            // Inline sections, missing sections, extra content.
            "rule R { strings: $a = \"AAA\" condition: any of them }",
            "rule R {\nstrings: $a = \"AAA\"\ncondition:\nany of them\n}",
            "rule R {\nstrings:\n$a = \"AAA\"\ncondition: any of them\n}",
            "rule R {\ncondition:\nany of them\n}",
            "rule R {\nstrings:\n$a = \"AAA\"\n}",
            "rule R {\nstrings:\n$a = \"AAA\"\ncondition:\nany of them",
            "rule R {\nstrings:\n$a = \"AAA\"\ncondition:\nany of them\n}\nextra",
            "rule R {\nstrings:\n$a = \"AAA\"\ncondition:\nany of them\n$b\n}",
            "rule R {\nmeta:\nx = \"y\"\nstrings:\n$a = \"AAA\"\ncondition:\nany of them\n}",
            "rule R {\nstrings:\nstrings:\n$a = \"AAA\"\ncondition:\nany of them\n}",
            "",
        ];
        for text in cases {
            assert!(
                parse_simple_yara_rule("R", text).is_err(),
                "rule {text:?} must be rejected"
            );
        }
    }

    #[test]
    fn test_parse_accepts_supported_minimal_rules() {
        let single = rule_with("$a = \"EICAR\"", "$a");
        let chain = rule_with("$a = \"AAA\"\n$b = \"BBB\"\n$c = \"CCC\"", "$c or $a or $b");
        let any = rule_with("$x_1 = \"X Y!\"", "any of them");
        for text in [&single, &chain, &any] {
            let compiled = parse_simple_yara_rule("R", text).unwrap();
            assert_eq!(compiled.required_matches, 1);
            let mut scanner = YaraScanner::new().unwrap();
            scanner.add_rule(compiled).unwrap();
            assert_eq!(scanner.rule_count(), 1);
        }
        let compiled = parse_simple_yara_rule("R", &chain).unwrap();
        assert_eq!(
            compiled.patterns,
            vec![b"AAA".to_vec(), b"BBB".to_vec(), b"CCC".to_vec()]
        );
        let mut scanner = YaraScanner::new().unwrap();
        scanner.add_rule(compiled).unwrap();
        assert!(scanner.scan_bytes(b"xx CCC xx").unwrap().is_threat);
        assert!(!scanner.scan_bytes(b"xx DDD xx").unwrap().is_threat);
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

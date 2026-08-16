//! CID-bound development rule ingestion.
//!
//! Ingests a complete, caller-supplied snapshot of active threat rules. Each
//! entry pairs finalized `ThreatRule` metadata with the exact content bytes the
//! caller resolved out of band. The entry's CID must be a canonical lowercase
//! base32 CIDv1 with the raw codec and a sha2-256 multihash whose digest equals
//! SHA-256 of the exact content bytes. Dag-pb and every other codec fail closed
//! because direct file-byte binding is only correct for raw.
//!
//! Only `RuleType::Yara` is supported, parsed with a strict simple matcher
//! grammar (not real YARA syntax): one `rule <rule_id> {` declaration, one
//! strings section of `$id = "literal"` lines, one condition section accepting
//! only `any of them`, and a closing brace.
//!
//! The whole snapshot is validated and compiled off to the side, then the
//! scanner's rules are replaced atomically once. Any failure preserves prior
//! scanner behavior and rule count. An empty snapshot is valid and clears all
//! rules, which is required when every canonical rule is deactivated upstream.
//!
//! This is a development-only path: the public entry point calls
//! `require_stub_allowed` and therefore rejects beta/mainnet. Real Kaspa/IPFS
//! loading, production YARA, and durable rollback protection remain open.

use std::collections::HashSet;
use std::fmt;

use log::info;

use crate::runtime::{require_stub_allowed, require_stub_allowed_for, RuntimeMode};
use crate::security::scanner::{validate_rule_set, CompiledRule, YaraScanner};

use super::krc20::{RuleType, ThreatRule};
use super::rule_fetch::verify_raw_cid_content_binding;
use super::rule_state::RuleStateMetadata;

/// Maximum number of rules accepted in one snapshot.
pub const MAX_RULES_PER_SNAPSHOT: usize = 256;
/// Maximum exact content bytes accepted per rule.
pub const MAX_CONTENT_BYTES: usize = 64 * 1024;
/// Maximum number of patterns accepted per rule.
pub const MAX_PATTERNS_PER_RULE: usize = 64;
/// Maximum bytes accepted per pattern literal.
pub const MAX_PATTERN_BYTES: usize = 1024;
/// Maximum bytes accepted for a rule identifier.
pub const MAX_RULE_ID_BYTES: usize = 128;

/// One snapshot entry: finalized rule metadata from a trusted caller plus the
/// exact content bytes the caller bound to the entry's CID.
#[derive(Clone)]
pub struct RuleSnapshotEntry {
    /// Normalized, finalized rule metadata. Must be active.
    pub rule: ThreatRule,
    /// Exact content bytes for `rule.ipfs_cid`.
    pub content: Vec<u8>,
}

impl fmt::Debug for RuleSnapshotEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RuleSnapshotEntry")
            .field("rule_type", &self.rule.rule_type)
            .field("active", &self.rule.active)
            .field("content_len", &self.content.len())
            .finish_non_exhaustive()
    }
}

/// One metadata-native snapshot entry: GH-193 [`RuleStateMetadata`] used
/// directly plus the exact content bytes bound to its CID.
///
/// Unlike [`RuleSnapshotEntry`] this path never constructs a `ThreatRule`, so
/// no wall-clock timestamp is fabricated and no confidence/consensus basis
/// points are converted into floating-point authority fields.
pub struct RuleMetadataSnapshotEntry {
    /// Validated, finalized accepted-and-active rule metadata.
    pub metadata: RuleStateMetadata,
    /// Exact content bytes for `metadata.ipfs_cid()`.
    pub content: Vec<u8>,
}

/// Fully compiled and validated rule set awaiting an infallible install.
pub(crate) struct PreparedRuleSnapshot {
    rules: Vec<CompiledRule>,
}

impl PreparedRuleSnapshot {
    pub(crate) fn prepare(snapshot: &[RuleMetadataSnapshotEntry]) -> Result<Self, RuleIngestError> {
        if snapshot.len() > MAX_RULES_PER_SNAPSHOT {
            return Err(RuleIngestError);
        }
        let mut seen_ids = HashSet::with_capacity(snapshot.len());
        let mut rules = Vec::with_capacity(snapshot.len());
        for entry in snapshot {
            rules.push(compile_metadata_entry(entry, &mut seen_ids)?);
        }
        validate_rule_set(&rules).map_err(|_| RuleIngestError)?;
        Ok(Self { rules })
    }

    pub(crate) fn into_rules(self) -> Vec<CompiledRule> {
        self.rules
    }
}

impl fmt::Debug for RuleMetadataSnapshotEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RuleMetadataSnapshotEntry")
            .field("rule_type", &self.metadata.rule_type())
            .field("active", &self.metadata.active())
            .field("content_len", &self.content.len())
            .finish_non_exhaustive()
    }
}

/// The single public ingestion error.
///
/// Deliberately generic: Display/Debug/logging never contain rule IDs, CIDs,
/// digests, content, or patterns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuleIngestError;

impl fmt::Display for RuleIngestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid CID-bound rule snapshot")
    }
}

impl std::error::Error for RuleIngestError {}

/// Ingest a complete active-rule snapshot into the scanner.
///
/// Development-only: rejects beta/mainnet via `require_stub_allowed`. The
/// snapshot replaces the scanner's rules atomically; on any failure the prior
/// scanner state is preserved.
pub fn ingest_rule_snapshot(
    scanner: &mut YaraScanner,
    snapshot: &[RuleSnapshotEntry],
) -> Result<(), RuleIngestError> {
    require_stub_allowed("CID-bound rule ingestion").map_err(|_| RuleIngestError)?;
    ingest_validated(scanner, snapshot)
}

/// Ingest a complete active-rule snapshot under an explicit runtime mode.
///
/// Deterministic helper for tests and callers that select the mode
/// themselves; identical policy to [`ingest_rule_snapshot`].
pub fn ingest_rule_snapshot_for_mode(
    mode: RuntimeMode,
    scanner: &mut YaraScanner,
    snapshot: &[RuleSnapshotEntry],
) -> Result<(), RuleIngestError> {
    // An explicit mode may make tests stricter, but it must never weaken the
    // process-wide beta/mainnet gate selected by the environment.
    require_stub_allowed("CID-bound rule ingestion").map_err(|_| RuleIngestError)?;
    require_stub_allowed_for(mode, "CID-bound rule ingestion").map_err(|_| RuleIngestError)?;
    ingest_validated(scanner, snapshot)
}

/// Ingest a complete metadata-native active-rule snapshot into the scanner.
///
/// Uses GH-193 [`RuleStateMetadata`] fields directly; identical validation and
/// atomic-replacement policy to [`ingest_rule_snapshot`]. Development-only:
/// rejects beta/mainnet via `require_stub_allowed`.
pub fn ingest_rule_state_snapshot(
    scanner: &mut YaraScanner,
    snapshot: &[RuleMetadataSnapshotEntry],
) -> Result<(), RuleIngestError> {
    require_stub_allowed("CID-bound rule ingestion").map_err(|_| RuleIngestError)?;
    ingest_state_validated(scanner, snapshot)
}

/// Ingest a metadata-native snapshot under an explicit runtime mode.
///
/// Deterministic helper for tests and callers that select the mode
/// themselves; identical policy to [`ingest_rule_state_snapshot`]. The
/// explicit mode can only be stricter; it never weakens the process-wide
/// beta/mainnet env gate.
pub fn ingest_rule_state_snapshot_for_mode(
    mode: RuntimeMode,
    scanner: &mut YaraScanner,
    snapshot: &[RuleMetadataSnapshotEntry],
) -> Result<(), RuleIngestError> {
    require_stub_allowed("CID-bound rule ingestion").map_err(|_| RuleIngestError)?;
    require_stub_allowed_for(mode, "CID-bound rule ingestion").map_err(|_| RuleIngestError)?;
    ingest_state_validated(scanner, snapshot)
}

/// Validate and compile the entire snapshot off to the side, then replace the
/// scanner's rules exactly once.
fn ingest_validated(
    scanner: &mut YaraScanner,
    snapshot: &[RuleSnapshotEntry],
) -> Result<(), RuleIngestError> {
    if snapshot.len() > MAX_RULES_PER_SNAPSHOT {
        return Err(RuleIngestError);
    }

    let mut seen_ids = HashSet::with_capacity(snapshot.len());
    let mut compiled = Vec::with_capacity(snapshot.len());
    for entry in snapshot {
        compiled.push(compile_entry(entry, &mut seen_ids)?);
    }

    scanner
        .replace_rules(compiled)
        .map_err(|_| RuleIngestError)?;
    info!("Ingested {} CID-bound rules", scanner.rule_count());
    Ok(())
}

/// Metadata-native counterpart of [`ingest_validated`]; same bounds, same
/// single atomic replacement.
fn ingest_state_validated(
    scanner: &mut YaraScanner,
    snapshot: &[RuleMetadataSnapshotEntry],
) -> Result<(), RuleIngestError> {
    if snapshot.len() > MAX_RULES_PER_SNAPSHOT {
        return Err(RuleIngestError);
    }

    let mut seen_ids = HashSet::with_capacity(snapshot.len());
    let mut compiled = Vec::with_capacity(snapshot.len());
    for entry in snapshot {
        compiled.push(compile_metadata_entry(entry, &mut seen_ids)?);
    }

    scanner
        .replace_rules(compiled)
        .map_err(|_| RuleIngestError)?;
    info!("Ingested {} CID-bound rules", scanner.rule_count());
    Ok(())
}

/// Validate one snapshot entry and compile it into a scanner rule.
fn compile_entry(
    entry: &RuleSnapshotEntry,
    seen_ids: &mut HashSet<String>,
) -> Result<CompiledRule, RuleIngestError> {
    compile_fields(
        &entry.rule.rule_id,
        &entry.rule.rule_type,
        &entry.rule.ipfs_cid,
        entry.rule.active,
        &entry.content,
        seen_ids,
    )
}

/// Validate one metadata-native snapshot entry and compile it into a scanner
/// rule, using [`RuleStateMetadata`] fields directly.
fn compile_metadata_entry(
    entry: &RuleMetadataSnapshotEntry,
    seen_ids: &mut HashSet<String>,
) -> Result<CompiledRule, RuleIngestError> {
    let rule_type = entry.metadata.rule_type();
    compile_fields(
        entry.metadata.rule_id(),
        &rule_type,
        entry.metadata.ipfs_cid(),
        entry.metadata.active(),
        &entry.content,
        seen_ids,
    )
}

/// Shared entry validation and compilation for both snapshot entry shapes.
fn compile_fields(
    rule_id: &str,
    rule_type: &RuleType,
    ipfs_cid: &str,
    active: bool,
    content: &[u8],
    seen_ids: &mut HashSet<String>,
) -> Result<CompiledRule, RuleIngestError> {
    if !active {
        return Err(RuleIngestError);
    }
    if *rule_type != RuleType::Yara {
        return Err(RuleIngestError);
    }
    validate_rule_id(rule_id)?;
    if !seen_ids.insert(rule_id.to_string()) {
        return Err(RuleIngestError);
    }

    if content.is_empty() || content.len() > MAX_CONTENT_BYTES {
        return Err(RuleIngestError);
    }
    verify_cid(ipfs_cid, content)?;

    let text = std::str::from_utf8(content).map_err(|_| RuleIngestError)?;
    let patterns = parse_rule_text(rule_id, text)?;

    Ok(CompiledRule {
        name: rule_id.to_string(),
        patterns,
        required_matches: 1,
    })
}

/// Rule IDs are 1..=128 bytes of ASCII alphanumerics, hyphen, or underscore.
fn validate_rule_id(rule_id: &str) -> Result<(), RuleIngestError> {
    let ok = !rule_id.is_empty()
        && rule_id.len() <= MAX_RULE_ID_BYTES
        && rule_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    if ok {
        Ok(())
    } else {
        Err(RuleIngestError)
    }
}

/// Verify that `cid` is the canonical lowercase base32 CIDv1 raw sha2-256
/// binding of the exact content bytes.
///
/// Delegates to the single shared binding implementation in `rule_fetch` so
/// GH-190 ingestion and GH-205 content sync can never drift apart.
fn verify_cid(cid: &str, content: &[u8]) -> Result<(), RuleIngestError> {
    verify_raw_cid_content_binding(cid, content).map_err(|_| RuleIngestError)
}

/// Parse rule content under the strict simple matcher grammar and return the
/// pattern literals in declaration order.
///
/// Grammar (whitespace and blank lines allowed between constructs; anything
/// else, including imports, includes, and comments, is rejected):
///
/// ```text
/// rule <rule_id> {
/// strings:
/// $id = "literal"        (1..=64 lines, nonempty ASCII literal, no escapes)
/// condition:
/// any of them
/// }
/// ```
fn parse_rule_text(expected_id: &str, text: &str) -> Result<Vec<Vec<u8>>, RuleIngestError> {
    // 0 = header, 1 = strings marker, 2 = string lines, 3 = condition marker
    // consumed, 4 = condition value consumed, 5 = closed.
    let mut stage = 0u8;
    let mut patterns: Vec<Vec<u8>> = Vec::new();
    let mut string_ids: HashSet<&str> = HashSet::new();
    let mut literals: HashSet<&[u8]> = HashSet::new();

    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        match stage {
            0 => {
                let tokens: Vec<&str> = line.split_whitespace().collect();
                if tokens.len() == 3
                    && tokens[0] == "rule"
                    && tokens[1] == expected_id
                    && tokens[2] == "{"
                {
                    stage = 1;
                } else {
                    return Err(RuleIngestError);
                }
            }
            1 if line == "strings:" => stage = 2,
            2 => {
                if line == "condition:" {
                    if patterns.is_empty() {
                        return Err(RuleIngestError);
                    }
                    stage = 3;
                } else {
                    let (id, literal) = parse_string_line(line)?;
                    if !string_ids.insert(id) || !literals.insert(literal) {
                        return Err(RuleIngestError);
                    }
                    patterns.push(literal.to_vec());
                    if patterns.len() > MAX_PATTERNS_PER_RULE {
                        return Err(RuleIngestError);
                    }
                }
            }
            3 if line == "any of them" => stage = 4,
            4 if line == "}" => stage = 5,
            _ => return Err(RuleIngestError),
        }
    }

    if stage != 5 {
        return Err(RuleIngestError);
    }
    Ok(patterns)
}

/// Parse one `$id = "literal"` strings line.
///
/// The identifier is 1..=32 ASCII alphanumerics or underscore. The literal is
/// nonempty printable ASCII (space through `~`) of at most
/// [`MAX_PATTERN_BYTES`] bytes, with no escapes and no embedded quotes.
fn parse_string_line(line: &str) -> Result<(&str, &[u8]), RuleIngestError> {
    let rest = line.strip_prefix('$').ok_or(RuleIngestError)?;
    let eq = rest.find('=').ok_or(RuleIngestError)?;

    let id = rest[..eq].trim();
    let id_ok = !id.is_empty()
        && id.len() <= 32
        && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_');
    if !id_ok {
        return Err(RuleIngestError);
    }

    let value = rest[eq + 1..].trim();
    if value.len() < 2 || !value.starts_with('"') || !value.ends_with('"') {
        return Err(RuleIngestError);
    }
    let literal = &value.as_bytes()[1..value.len() - 1];
    let literal_ok = !literal.is_empty()
        && literal.len() <= MAX_PATTERN_BYTES
        && literal
            .iter()
            .all(|&b| (0x20..=0x7e).contains(&b) && b != b'"' && b != b'\\');
    if !literal_ok {
        return Err(RuleIngestError);
    }

    Ok((id, literal))
}

#[cfg(test)]
mod tests {
    use super::super::rule_fetch::{CID_RAW_SHA256_HEADER, CID_RAW_SHA256_LEN};
    use super::*;
    use crate::security::scanner::compute_sha256;

    fn cid_for(content: &[u8]) -> String {
        let digest = compute_sha256(content);
        let mut bytes = Vec::with_capacity(CID_RAW_SHA256_LEN);
        bytes.extend_from_slice(&CID_RAW_SHA256_HEADER);
        bytes.extend_from_slice(&digest);
        multibase::encode(multibase::Base::Base32Lower, &bytes)
    }

    #[test]
    fn test_verify_cid_accepts_canonical_raw_sha256() {
        let content = b"rule R {\nstrings:\n$a = \"X\"\ncondition:\nany of them\n}\n";
        assert!(verify_cid(&cid_for(content), content).is_ok());
    }

    #[test]
    fn test_verify_cid_rejects_dag_pb_codec() {
        let content = b"payload";
        let digest = compute_sha256(content);
        let mut bytes = vec![0x01, 0x70, 0x12, 0x20];
        bytes.extend_from_slice(&digest);
        let cid = multibase::encode(multibase::Base::Base32Lower, &bytes);
        assert_eq!(verify_cid(&cid, content), Err(RuleIngestError));
    }

    #[test]
    fn test_verify_cid_rejects_uppercase() {
        let content = b"payload";
        let cid = cid_for(content).to_uppercase();
        assert_eq!(verify_cid(&cid, content), Err(RuleIngestError));
    }

    #[test]
    fn test_parse_rule_text_minimal() {
        let text = "rule R {\nstrings:\n$a = \"ABC\"\ncondition:\nany of them\n}\n";
        let patterns = parse_rule_text("R", text).unwrap();
        assert_eq!(patterns, vec![b"ABC".to_vec()]);
    }

    #[test]
    fn test_parse_rule_text_rejects_comments_and_trailing() {
        let with_comment = "rule R {\n// c\nstrings:\n$a = \"ABC\"\ncondition:\nany of them\n}\n";
        assert!(parse_rule_text("R", with_comment).is_err());
        let trailing = "rule R {\nstrings:\n$a = \"ABC\"\ncondition:\nany of them\n}\nextra\n";
        assert!(parse_rule_text("R", trailing).is_err());
    }

    #[test]
    fn test_parse_rule_text_rejects_id_mismatch_and_escape() {
        let wrong_id = "rule Q {\nstrings:\n$a = \"ABC\"\ncondition:\nany of them\n}\n";
        assert!(parse_rule_text("R", wrong_id).is_err());
        let escaped = "rule R {\nstrings:\n$a = \"A\\nB\"\ncondition:\nany of them\n}\n";
        assert!(parse_rule_text("R", escaped).is_err());
    }

    #[test]
    fn test_parse_rule_text_rejects_duplicate_patterns() {
        let text = "rule R {\nstrings:\n$a = \"ABC\"\n$b = \"ABC\"\ncondition:\nany of them\n}\n";
        assert!(parse_rule_text("R", text).is_err());
    }

    #[test]
    fn test_error_is_generic() {
        let err = RuleIngestError;
        assert_eq!(err.to_string(), "invalid CID-bound rule snapshot");
        assert_eq!(format!("{err:?}"), "RuleIngestError");
    }

    #[test]
    fn test_snapshot_debug_is_redacted() {
        let entry = RuleSnapshotEntry {
            rule: ThreatRule {
                rule_id: "SENSITIVE-RULE".to_string(),
                rule_type: RuleType::Yara,
                ipfs_cid: "sensitive-cid".to_string(),
                guardian_id: [7u8; 32],
                validator_consensus: 0.9,
                timestamp: 1,
                active: true,
            },
            content: b"SENSITIVE-PATTERN".to_vec(),
        };
        let debugged = format!("{entry:?}");
        assert!(!debugged.contains("SENSITIVE"));
        assert!(!debugged.contains("sensitive-cid"));
        assert!(!debugged.contains("guardian_id"));
        assert!(debugged.contains("content_len: 17"));
    }
}

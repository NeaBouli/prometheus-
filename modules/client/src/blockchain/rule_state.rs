//! Development-only `RuleStorageState` constructor-args decoding.
//!
//! Decodes one exact, caller-supplied upstream Silverc `--constructor-args`
//! JSON document (or a batch of documents) for the current
//! `RuleStorageState.sil` fixture into structurally validated, normalized
//! rule metadata. The input is the exact 20-entry `Vec<Expr>`-shape JSON the
//! pinned `silverc` accepts: strict tagged `{"kind","data"}` objects in the
//! exact constructor order (32-byte governance key, signed `next_proposal_id`
//! and `proposal_id`, 32-byte guardian key, 32-byte threat hash, signed rule
//! type, 36-byte rule content CID, signed ints through `stored_at_block`,
//! bool `active`, signed guardian reputation event). Unknown fields, wrong
//! kinds, wrong order, wrong byte lengths, and trailing data are rejected.
//!
//! The decoder proves structure only. It does **not** prove RPC origin,
//! covenant-instance identity, script-template equality, finality, content
//! availability, CID content binding, or any production authority. The CID
//! digest is not bound to any content here; content binding is a separate
//! boundary (see `rule_ingest`).
//!
//! Only finalized accepted-and-active states decode successfully: the exact
//! current `RuleStorageState.sil` invariants are revalidated locally
//! (status, confidence/quorum bounds, voting window arithmetic, exact
//! consensus recomputation, nonzero threat hash, counting window bounds, and
//! the accepted guardian reputation event).
//!
//! This is a development-only path: every public entry point calls
//! `require_stub_allowed` and therefore rejects beta/mainnet. The `_for_mode`
//! helpers can only make tests stricter; they can never weaken the
//! process-wide beta/mainnet env gate.

use std::collections::HashSet;
use std::fmt;

use serde_json::Value;

use crate::runtime::{require_stub_allowed, require_stub_allowed_for, RuntimeMode};

use super::krc20::RuleType;

/// Maximum bytes accepted for a single constructor-args JSON document.
pub const MAX_STATE_JSON_BYTES: usize = 16 * 1024;
/// Maximum number of state documents accepted in one batch.
pub const MAX_STATES_PER_BATCH: usize = 256;
/// Maximum total bytes accepted across one batch, checked before parsing.
pub const MAX_BATCH_JSON_BYTES: usize = 1024 * 1024;

/// Exact number of constructor entries in the current `RuleStorageState.sil`.
const STATE_ENTRY_COUNT: usize = 20;
/// Voting window from `RuleStorageState.sil` (`VOTING_BLOCKS`).
const VOTING_BLOCKS: u64 = 864_000;
/// Minimum AI confidence from `RuleStorageState.sil` (`MIN_CONFIDENCE`).
const MIN_CONFIDENCE_BPS: u64 = 8_500;
/// Maximum expressible confidence/consensus basis points.
const MAX_BPS: u64 = 10_000;
/// Validator quorum from `RuleStorageState.sil` (`VALIDATOR_QUORUM`).
const VALIDATOR_QUORUM_BPS: u64 = 6_700;
/// Finalized accepted status from `RuleStorageState.sil` (`STATUS_ACCEPTED`).
const STATUS_ACCEPTED: i64 = 2;
/// Accepted guardian reputation event (`GUARDIAN_EVENT_ACCEPTED`).
const GUARDIAN_EVENT_ACCEPTED: i64 = 1;

/// Header of a CIDv1 raw sha2-256/32 binary CID: version 0x01, codec raw
/// (0x55), multihash sha2-256 (0x12), digest length 32 (0x20).
const CID_RAW_SHA256_HEADER: [u8; 4] = [0x01, 0x55, 0x12, 0x20];
/// Exact byte length of a CIDv1 raw sha2-256/32 binary CID.
const CID_RAW_SHA256_LEN: usize = 36;

/// The single public decoding error.
///
/// Deliberately generic: Display/Debug/logging never contain proposal or
/// rule IDs, CIDs, hashes, keys, votes, heights, or any decoded value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuleStateError;

impl fmt::Display for RuleStateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid RuleStorage state")
    }
}

impl std::error::Error for RuleStateError {}

/// Structurally validated, provenance-unverified `RuleStorageState` metadata
/// for one finalized accepted-and-active rule.
///
/// Fields are private and there is no public constructor: instances can only
/// come from the validating decoders in this module.
pub struct RuleStateMetadata {
    proposal_id: u64,
    rule_id: String,
    rule_type: RuleType,
    ipfs_cid: String,
    guardian_id: [u8; 32],
    threat_hash: [u8; 32],
    confidence_bps: u16,
    consensus_bps: u16,
    stored_at_block: u64,
    active: bool,
}

impl RuleStateMetadata {
    /// Proposal identifier carried by the decoded state.
    pub fn proposal_id(&self) -> u64 {
        self.proposal_id
    }

    /// Deterministic rule identifier `PROM-RULE-{proposal_id:04}` (minimum
    /// width 4; no year, because no year exists in the state).
    pub fn rule_id(&self) -> &str {
        &self.rule_id
    }

    /// Rule type; only Yara, Stix, and Sigma are decodable.
    pub fn rule_type(&self) -> RuleType {
        self.rule_type.clone()
    }

    /// Canonical 59-character lowercase base32 Raw-CIDv1/sha2-256 CID string
    /// re-encoded from the exact 36 CID bytes in the state.
    pub fn ipfs_cid(&self) -> &str {
        &self.ipfs_cid
    }

    /// Guardian key bytes carried by the decoded state.
    pub fn guardian_id(&self) -> &[u8; 32] {
        &self.guardian_id
    }

    /// Nonzero threat hash carried by the decoded state.
    pub fn threat_hash(&self) -> &[u8; 32] {
        &self.threat_hash
    }

    /// AI confidence in basis points (8500..=10000).
    pub fn confidence_bps(&self) -> u16 {
        self.confidence_bps
    }

    /// Recomputed validator consensus in basis points (6700..=10000).
    pub fn consensus_bps(&self) -> u16 {
        self.consensus_bps
    }

    /// Block height at which the accepted rule was stored.
    pub fn stored_at_block(&self) -> u64 {
        self.stored_at_block
    }

    /// Whether the decoded state marks the rule active (always true for a
    /// successfully decoded accepted state).
    pub fn active(&self) -> bool {
        self.active
    }
}

impl fmt::Debug for RuleStateMetadata {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Redacted: proposal/rule IDs, CID, hashes, and keys never appear.
        // Only the non-sensitive class and coarse ranges are shown.
        f.debug_struct("RuleStateMetadata")
            .field("rule_type", &self.rule_type)
            .field("active", &self.active)
            .field("confidence_bucket", &(self.confidence_bps / 1_000))
            .field("consensus_bucket", &(self.consensus_bps / 1_000))
            .field(
                "stored_at_block_bucket",
                &(self.stored_at_block / VOTING_BLOCKS),
            )
            .finish_non_exhaustive()
    }
}

/// Decode one exact upstream Silverc constructor-args JSON document into
/// validated rule metadata.
///
/// Development-only: rejects beta/mainnet via `require_stub_allowed`.
pub fn decode_rule_state(json: &str) -> Result<RuleStateMetadata, RuleStateError> {
    require_stub_allowed("RuleStorage state decoding").map_err(|_| RuleStateError)?;
    decode_state(json)
}

/// Decode one document under an explicit runtime mode.
///
/// Deterministic helper for tests and callers that select the mode
/// themselves; identical policy to [`decode_rule_state`]. The explicit mode
/// can only be stricter; it never weakens the process-wide env gate.
pub fn decode_rule_state_for_mode(
    mode: RuntimeMode,
    json: &str,
) -> Result<RuleStateMetadata, RuleStateError> {
    require_stub_allowed("RuleStorage state decoding").map_err(|_| RuleStateError)?;
    require_stub_allowed_for(mode, "RuleStorage state decoding").map_err(|_| RuleStateError)?;
    decode_state(json)
}

/// Decode a batch of constructor-args JSON documents.
///
/// Every document is validated before any output is returned: on the first
/// failure the whole batch is rejected. Duplicate proposal-derived rule IDs
/// across the batch are rejected. Batch limits (state count and total bytes)
/// are enforced before parsing any document.
///
/// Development-only: rejects beta/mainnet via `require_stub_allowed`.
pub fn decode_rule_state_batch(
    documents: &[&str],
) -> Result<Vec<RuleStateMetadata>, RuleStateError> {
    require_stub_allowed("RuleStorage state decoding").map_err(|_| RuleStateError)?;
    decode_batch_validated(documents)
}

/// Decode a batch under an explicit runtime mode; identical policy to
/// [`decode_rule_state_batch`]. The explicit mode can only be stricter; it
/// never weakens the process-wide env gate.
pub fn decode_rule_state_batch_for_mode(
    mode: RuntimeMode,
    documents: &[&str],
) -> Result<Vec<RuleStateMetadata>, RuleStateError> {
    require_stub_allowed("RuleStorage state decoding").map_err(|_| RuleStateError)?;
    require_stub_allowed_for(mode, "RuleStorage state decoding").map_err(|_| RuleStateError)?;
    decode_batch_validated(documents)
}

/// Validate the batch limits, decode every document, and reject duplicate
/// proposal-derived rule IDs before returning any output.
fn decode_batch_validated(documents: &[&str]) -> Result<Vec<RuleStateMetadata>, RuleStateError> {
    if documents.len() > MAX_STATES_PER_BATCH {
        return Err(RuleStateError);
    }
    let mut total_bytes = 0usize;
    for document in documents {
        total_bytes = total_bytes
            .checked_add(document.len())
            .ok_or(RuleStateError)?;
    }
    if total_bytes > MAX_BATCH_JSON_BYTES {
        return Err(RuleStateError);
    }

    let mut seen_ids = HashSet::with_capacity(documents.len());
    let mut decoded = Vec::with_capacity(documents.len());
    for document in documents {
        let metadata = decode_state(document)?;
        if !seen_ids.insert(metadata.rule_id.clone()) {
            return Err(RuleStateError);
        }
        decoded.push(metadata);
    }
    Ok(decoded)
}

/// Decode and fully validate one constructor-args JSON document.
fn decode_state(json: &str) -> Result<RuleStateMetadata, RuleStateError> {
    if json.len() > MAX_STATE_JSON_BYTES {
        return Err(RuleStateError);
    }
    // serde_json rejects trailing data after the top-level value.
    let value: Value = serde_json::from_str(json).map_err(|_| RuleStateError)?;
    let entries = value.as_array().ok_or(RuleStateError)?;
    if entries.len() != STATE_ENTRY_COUNT {
        return Err(RuleStateError);
    }

    // Exact constructor order from the current RuleStorageState.sil. The
    // governance key is structurally validated but not retained in the
    // normalized metadata.
    let _governance_pk = parse_fixed_bytes::<32>(&entries[0])?;
    let next_proposal_id = parse_int(&entries[1])?;
    let proposal_id = parse_int(&entries[2])?;
    let guardian_id = parse_fixed_bytes::<32>(&entries[3])?;
    let threat_hash = parse_fixed_bytes::<32>(&entries[4])?;
    let rule_type_raw = parse_int(&entries[5])?;
    let cid_bytes = parse_fixed_bytes::<CID_RAW_SHA256_LEN>(&entries[6])?;
    let confidence = parse_int(&entries[7])?;
    let submitted_at_block = parse_int(&entries[8])?;
    let votes_for = parse_int(&entries[9])?;
    let votes_against = parse_int(&entries[10])?;
    let voting_end_block = parse_int(&entries[11])?;
    let status = parse_int(&entries[12])?;
    let rule_count = parse_int(&entries[13])?;
    let count_in_window = parse_int(&entries[14])?;
    let last_count_reset_block = parse_int(&entries[15])?;
    let consensus_score = parse_int(&entries[16])?;
    let stored_at_block = parse_int(&entries[17])?;
    let active = parse_bool(&entries[18])?;
    let guardian_reputation_event = parse_int(&entries[19])?;

    validate_semantics(
        next_proposal_id,
        proposal_id,
        rule_type_raw,
        confidence,
        submitted_at_block,
        votes_for,
        votes_against,
        voting_end_block,
        status,
        rule_count,
        count_in_window,
        last_count_reset_block,
        consensus_score,
        stored_at_block,
        active,
        guardian_reputation_event,
    )?;

    let proposal_id = u64::try_from(proposal_id).map_err(|_| RuleStateError)?;
    let confidence = u64::try_from(confidence).map_err(|_| RuleStateError)?;
    let consensus_score = u64::try_from(consensus_score).map_err(|_| RuleStateError)?;
    let stored_at_block = u64::try_from(stored_at_block).map_err(|_| RuleStateError)?;

    if threat_hash.iter().all(|&byte| byte == 0) {
        return Err(RuleStateError);
    }
    if cid_bytes[..4] != CID_RAW_SHA256_HEADER {
        return Err(RuleStateError);
    }

    let rule_type = match rule_type_raw {
        0 => RuleType::Yara,
        1 => RuleType::Stix,
        2 => RuleType::Sigma,
        _ => return Err(RuleStateError),
    };

    // Re-encoding a fixed 36-byte raw/sha2-256 CID body always yields the
    // canonical 59-character lowercase base32 form.
    let ipfs_cid = multibase::encode(multibase::Base::Base32Lower, cid_bytes);

    Ok(RuleStateMetadata {
        proposal_id,
        rule_id: format!("PROM-RULE-{proposal_id:04}"),
        rule_type,
        ipfs_cid,
        guardian_id,
        threat_hash,
        confidence_bps: u16::try_from(confidence).map_err(|_| RuleStateError)?,
        consensus_bps: u16::try_from(consensus_score).map_err(|_| RuleStateError)?,
        stored_at_block,
        active,
    })
}

/// Revalidate the exact current `RuleStorageState.sil` invariants for a
/// finalized accepted-and-active state. All inputs are still signed `i64`
/// exactly as parsed; every conversion and arithmetic step is checked.
#[allow(clippy::too_many_arguments)]
fn validate_semantics(
    next_proposal_id: i64,
    proposal_id: i64,
    rule_type: i64,
    confidence: i64,
    submitted_at_block: i64,
    votes_for: i64,
    votes_against: i64,
    voting_end_block: i64,
    status: i64,
    rule_count: i64,
    count_in_window: i64,
    last_count_reset_block: i64,
    consensus_score: i64,
    stored_at_block: i64,
    active: bool,
    guardian_reputation_event: i64,
) -> Result<(), RuleStateError> {
    if status != STATUS_ACCEPTED || !active {
        return Err(RuleStateError);
    }
    if !(0..=2).contains(&rule_type) {
        return Err(RuleStateError);
    }
    if confidence < MIN_CONFIDENCE_BPS as i64 || confidence > MAX_BPS as i64 {
        return Err(RuleStateError);
    }

    // All count/height/vote fields must be nonnegative.
    let next_proposal_id = u64::try_from(next_proposal_id).map_err(|_| RuleStateError)?;
    let proposal_id = u64::try_from(proposal_id).map_err(|_| RuleStateError)?;
    let submitted_at_block = u64::try_from(submitted_at_block).map_err(|_| RuleStateError)?;
    let votes_for = u64::try_from(votes_for).map_err(|_| RuleStateError)?;
    let votes_against = u64::try_from(votes_against).map_err(|_| RuleStateError)?;
    let voting_end_block = u64::try_from(voting_end_block).map_err(|_| RuleStateError)?;
    let rule_count = u64::try_from(rule_count).map_err(|_| RuleStateError)?;
    let count_in_window = u64::try_from(count_in_window).map_err(|_| RuleStateError)?;
    let last_count_reset_block =
        u64::try_from(last_count_reset_block).map_err(|_| RuleStateError)?;
    let consensus_score = u64::try_from(consensus_score).map_err(|_| RuleStateError)?;
    let stored_at_block = u64::try_from(stored_at_block).map_err(|_| RuleStateError)?;

    if next_proposal_id != proposal_id.checked_add(1).ok_or(RuleStateError)? {
        return Err(RuleStateError);
    }
    if voting_end_block
        != submitted_at_block
            .checked_add(VOTING_BLOCKS)
            .ok_or(RuleStateError)?
    {
        return Err(RuleStateError);
    }

    let total_votes = votes_for.checked_add(votes_against).ok_or(RuleStateError)?;
    if total_votes == 0 {
        return Err(RuleStateError);
    }
    // Recompute consensus exactly as finalizeProposal does:
    // votes_for * 10000 / total_votes with checked integer arithmetic.
    let recomputed = votes_for
        .checked_mul(MAX_BPS)
        .ok_or(RuleStateError)?
        .checked_div(total_votes)
        .ok_or(RuleStateError)?;
    if recomputed != consensus_score {
        return Err(RuleStateError);
    }
    if !(VALIDATOR_QUORUM_BPS..=MAX_BPS).contains(&consensus_score) {
        return Err(RuleStateError);
    }

    if stored_at_block < voting_end_block {
        return Err(RuleStateError);
    }
    if rule_count < 1 || count_in_window < 1 {
        return Err(RuleStateError);
    }
    if last_count_reset_block > submitted_at_block {
        return Err(RuleStateError);
    }
    if guardian_reputation_event != GUARDIAN_EVENT_ACCEPTED {
        return Err(RuleStateError);
    }
    Ok(())
}

/// Extract the `data` payload of a strict tagged `{"kind","data"}` object of
/// exactly the expected kind. Unknown or missing fields are rejected.
fn tagged_data<'a>(value: &'a Value, expected_kind: &str) -> Result<&'a Value, RuleStateError> {
    let object = value.as_object().ok_or(RuleStateError)?;
    if object.len() != 2 {
        return Err(RuleStateError);
    }
    let kind = object
        .get("kind")
        .and_then(Value::as_str)
        .ok_or(RuleStateError)?;
    if kind != expected_kind {
        return Err(RuleStateError);
    }
    object.get("data").ok_or(RuleStateError)
}

/// Parse a strict `{"kind":"int","data":<signed integer>}` entry. JSON
/// floats, strings, booleans, and out-of-`i64`-range numbers are rejected.
fn parse_int(value: &Value) -> Result<i64, RuleStateError> {
    tagged_data(value, "int")?.as_i64().ok_or(RuleStateError)
}

/// Parse a strict `{"kind":"bool","data":<boolean>}` entry.
fn parse_bool(value: &Value) -> Result<bool, RuleStateError> {
    tagged_data(value, "bool")?.as_bool().ok_or(RuleStateError)
}

/// Parse a strict `{"kind":"array","data":[<byte exprs>]}` entry of exactly
/// `N` strict `{"kind":"byte","data":0..=255}` objects.
fn parse_fixed_bytes<const N: usize>(value: &Value) -> Result<[u8; N], RuleStateError> {
    let items = tagged_data(value, "array")?
        .as_array()
        .ok_or(RuleStateError)?;
    if items.len() != N {
        return Err(RuleStateError);
    }
    let mut bytes = [0u8; N];
    for (slot, item) in bytes.iter_mut().zip(items.iter()) {
        let byte = tagged_data(item, "byte")?.as_u64().ok_or(RuleStateError)?;
        *slot = u8::try_from(byte).map_err(|_| RuleStateError)?;
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build one valid accepted-state document with overridable scalar fields.
    fn valid_doc_with(
        proposal_id: i64,
        votes_for: i64,
        votes_against: i64,
        rule_type: i64,
    ) -> String {
        let bytes = |seed: u8, len: usize| {
            let data: Vec<Value> = (0..len)
                .map(|_| serde_json::json!({"kind": "byte", "data": seed}))
                .collect();
            serde_json::json!({"kind": "array", "data": data})
        };
        let int = |v: i64| serde_json::json!({"kind": "int", "data": v});
        let mut cid = vec![0x01u8, 0x55, 0x12, 0x20];
        cid.extend(0u8..32);
        let cid_data: Vec<Value> = cid
            .iter()
            .map(|b| serde_json::json!({"kind": "byte", "data": b}))
            .collect();
        let total = votes_for + votes_against;
        let consensus = if total > 0 {
            votes_for * 10_000 / total
        } else {
            0
        };
        let doc = serde_json::json!([
            bytes(4, 32),
            int(proposal_id + 1),
            int(proposal_id),
            bytes(5, 32),
            bytes(6, 32),
            int(rule_type),
            {"kind": "array", "data": cid_data},
            int(9_000),
            int(100_000),
            int(votes_for),
            int(votes_against),
            int(964_000),
            int(2),
            int(3),
            int(2),
            int(50_000),
            int(consensus),
            int(965_000),
            {"kind": "bool", "data": true},
            int(1),
        ]);
        serde_json::to_string(&doc).unwrap()
    }

    #[test]
    fn test_decodes_valid_state() {
        let metadata = decode_state(&valid_doc_with(7, 3, 1, 0)).unwrap();
        assert_eq!(metadata.proposal_id(), 7);
        assert_eq!(metadata.rule_id(), "PROM-RULE-0007");
        assert_eq!(metadata.rule_type(), RuleType::Yara);
        assert_eq!(metadata.confidence_bps(), 9_000);
        assert_eq!(metadata.consensus_bps(), 7_500);
        assert_eq!(metadata.stored_at_block(), 965_000);
        assert!(metadata.active());
        assert_eq!(metadata.ipfs_cid().len(), 59);
        assert!(metadata.ipfs_cid().starts_with("bafkrei"));
    }

    #[test]
    fn test_rule_id_minimum_width_four() {
        let wide = decode_state(&valid_doc_with(12_345, 1, 0, 1)).unwrap();
        assert_eq!(wide.rule_id(), "PROM-RULE-12345");
        assert_eq!(wide.rule_type(), RuleType::Stix);
        let sigma = decode_state(&valid_doc_with(42, 1, 0, 2)).unwrap();
        assert_eq!(sigma.rule_id(), "PROM-RULE-0042");
        assert_eq!(sigma.rule_type(), RuleType::Sigma);
    }

    #[test]
    fn test_rejects_oversize_before_parse() {
        let doc = format!("{} ", valid_doc_with(7, 3, 1, 0));
        let padded = format!("{:>width$}", doc, width = MAX_STATE_JSON_BYTES + 1);
        assert!(decode_state(&padded).is_err());
    }

    #[test]
    fn test_rejects_trailing_data_and_malformed() {
        let doc = valid_doc_with(7, 3, 1, 0);
        assert!(decode_state(&format!("{doc} {{}}")).is_err());
        assert!(decode_state(&doc[..doc.len() - 1]).is_err());
        assert!(decode_state("not json").is_err());
    }

    #[test]
    fn test_error_is_generic() {
        let err = RuleStateError;
        assert_eq!(err.to_string(), "invalid RuleStorage state");
        assert_eq!(format!("{err:?}"), "RuleStateError");
    }

    #[test]
    fn test_metadata_debug_is_redacted() {
        let metadata = decode_state(&valid_doc_with(7, 3, 1, 0)).unwrap();
        let debugged = format!("{metadata:?}");
        assert!(!debugged.contains("PROM-RULE"));
        assert!(!debugged.contains("bafkrei"));
        assert!(!debugged.contains("guardian_id"));
        assert!(!debugged.contains("threat_hash"));
        assert!(!debugged.contains("9000"));
        assert!(debugged.contains("Yara"));
        assert!(debugged.contains("active: true"));
    }
}

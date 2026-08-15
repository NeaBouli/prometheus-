//! Development-only complete-snapshot RuleStorage content sync (GH-205).
//!
//! Composes the existing boundaries without duplicating their validation:
//!
//! 1. Every owner-pinned manifest entry is verified through one shared
//!    GH-203/GH-197 live observation path (`rule_observation`): the entry's
//!    explicit Testnet-10 `kaspatest` address is parsed and checked, the
//!    injected [`RuleObservationSource`] supplies exactly one node snapshot
//!    for that address, and the unchanged GH-197 verifier decodes GH-193
//!    [`RuleStateMetadata`] only after all manifest, observation, maturity,
//!    and constructor-hash checks pass. No caller-supplied observation JSON
//!    is accepted anywhere on this path.
//! 2. Duplicate rule IDs, canonical CIDs, and verified manifest outpoints are
//!    rejected across the whole request.
//! 3. Each entry's canonical Raw-CIDv1 is revalidated immediately before the
//!    injected [`RuleContentSource`] is asked for the exact content bytes.
//! 4. Only after every entry verifies and fetches does the GH-190
//!    metadata-native ingest (`rule_ingest::ingest_rule_state_snapshot`)
//!    re-check every CID/content binding and swap the scanner's rules
//!    atomically exactly once.
//!
//! Any failure at any stage preserves the prior scanner state. An empty
//! request is valid and clears all rules, consistent with GH-190 empty
//! snapshot semantics (required when every canonical rule is deactivated
//! upstream). No wall-clock timestamps are fabricated and no
//! confidence/consensus basis points are converted to floating-point
//! authority fields anywhere on this path.
//!
//! This boundary proves **only** local complete-snapshot consistency under an
//! owner-pinned trust root. It does **not** prove manifest authority, RPC
//! truth, transaction history, finality, IPFS/content availability, durable
//! anti-downgrade protection, or production readiness.
//!
//! This is a development-only path: every public entry point calls
//! `require_stub_allowed` and therefore rejects beta/mainnet. The `_for_mode`
//! helper can only make tests stricter; it can never weaken the process-wide
//! beta/mainnet env gate.

use std::collections::HashSet;
use std::fmt;

use log::info;

use crate::runtime::{require_stub_allowed, require_stub_allowed_for, RuntimeMode};
use crate::security::scanner::YaraScanner;

use super::rule_fetch::{validate_canonical_raw_cid, RuleContentSource};
use super::rule_ingest::{
    ingest_rule_state_snapshot, RuleMetadataSnapshotEntry, MAX_RULES_PER_SNAPSHOT,
};
use super::rule_observation::{verify_observation_live_shared, RuleObservationSource};

/// The single public content-sync error.
///
/// Deliberately generic: Display/Debug/logging never contain manifest or
/// observation hashes, outpoints, CIDs, rule IDs, URLs, or content bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuleSyncError;

impl fmt::Display for RuleSyncError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RuleStorage content sync failed")
    }
}

impl std::error::Error for RuleSyncError {}

/// One owner-pinned manifest verification request.
///
/// The documents are exactly the inputs of the GH-203/GH-197 live observation
/// path: `expected_manifest_sha256` is the owner trust root (64 lowercase hex
/// of SHA-256 over the canonical manifest bytes), `manifest_json` is strict
/// canonical compact JSON, `constructor_json` is the exact Silverc
/// `--constructor-args` document the manifest binds, and `address` is the
/// explicit Testnet-10 `kaspatest` address whose UTXOs the injected
/// [`RuleObservationSource`] is asked to observe. Callers never supply
/// observation JSON; the observation is acquired live/injected through the
/// GH-203 boundary.
pub struct RuleSyncEntry {
    /// Owner-pinned expected SHA-256 of the canonical manifest bytes.
    pub expected_manifest_sha256: String,
    /// Canonical manifest JSON document.
    pub manifest_json: String,
    /// Exact constructor-args JSON document bound by the manifest.
    pub constructor_json: String,
    /// Explicit Testnet-10 `kaspatest` address to observe for this manifest.
    pub address: String,
}

impl fmt::Debug for RuleSyncEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RuleSyncEntry").finish_non_exhaustive()
    }
}

/// Sync one complete owner-pinned manifest snapshot into the scanner.
///
/// Every entry is verified against one injected node observation and every
/// content fetch succeeds before the scanner's rules are replaced atomically
/// exactly once; any failure preserves the prior scanner state. An empty
/// `entries` slice clears all rules (GH-190 clear semantics).
///
/// Development-only: rejects beta/mainnet via `require_stub_allowed`.
pub async fn sync_rule_snapshot(
    scanner: &mut YaraScanner,
    content_source: &dyn RuleContentSource,
    observation_source: &dyn RuleObservationSource,
    entries: &[RuleSyncEntry],
) -> Result<(), RuleSyncError> {
    require_stub_allowed("RuleStorage content sync").map_err(|_| RuleSyncError)?;
    sync_validated(scanner, content_source, observation_source, entries).await
}

/// Sync under an explicit runtime mode; identical policy to
/// [`sync_rule_snapshot`]. The explicit mode can only be stricter; it never
/// weakens the process-wide env gate.
pub async fn sync_rule_snapshot_for_mode(
    mode: RuntimeMode,
    scanner: &mut YaraScanner,
    content_source: &dyn RuleContentSource,
    observation_source: &dyn RuleObservationSource,
    entries: &[RuleSyncEntry],
) -> Result<(), RuleSyncError> {
    require_stub_allowed("RuleStorage content sync").map_err(|_| RuleSyncError)?;
    require_stub_allowed_for(mode, "RuleStorage content sync").map_err(|_| RuleSyncError)?;
    sync_validated(scanner, content_source, observation_source, entries).await
}

/// Verify every entry against its injected node observation, fetch every
/// content, then swap the scanner exactly once through the GH-190
/// metadata-native ingest path.
async fn sync_validated(
    scanner: &mut YaraScanner,
    content_source: &dyn RuleContentSource,
    observation_source: &dyn RuleObservationSource,
    entries: &[RuleSyncEntry],
) -> Result<(), RuleSyncError> {
    if entries.len() > MAX_RULES_PER_SNAPSHOT {
        return Err(RuleSyncError);
    }

    // Phase 1: verify every owner-pinned manifest through the shared
    // GH-203/GH-197 live observation path and reject duplicate identities
    // across the whole request before any fetch runs.
    let mut seen_outpoints = HashSet::with_capacity(entries.len());
    let mut seen_rule_ids = HashSet::with_capacity(entries.len());
    let mut seen_cids = HashSet::with_capacity(entries.len());
    let mut verified = Vec::with_capacity(entries.len());
    for entry in entries {
        let (metadata, outpoint) = verify_observation_live_shared(
            observation_source,
            &entry.address,
            &entry.expected_manifest_sha256,
            &entry.manifest_json,
            &entry.constructor_json,
        )
        .await
        .map_err(|_| RuleSyncError)?;
        if !seen_outpoints.insert(outpoint) {
            return Err(RuleSyncError);
        }
        if !seen_rule_ids.insert(metadata.rule_id().to_string()) {
            return Err(RuleSyncError);
        }
        if !seen_cids.insert(metadata.ipfs_cid().to_string()) {
            return Err(RuleSyncError);
        }
        verified.push(metadata);
    }

    // Phase 2: fetch the exact content bytes for every entry. The canonical
    // Raw-CIDv1 is revalidated immediately before each source call; no
    // scanner mutation happens here.
    let mut snapshot = Vec::with_capacity(verified.len());
    for metadata in verified {
        validate_canonical_raw_cid(metadata.ipfs_cid()).map_err(|_| RuleSyncError)?;
        let content = content_source
            .fetch_rule_content(metadata.ipfs_cid())
            .await
            .map_err(|_| RuleSyncError)?;
        snapshot.push(RuleMetadataSnapshotEntry { metadata, content });
    }

    // Phase 3: the GH-190 metadata-native ingest re-checks every CID/content
    // binding and replaces the scanner's rules atomically exactly once. Any
    // failure preserves the prior scanner state.
    ingest_rule_state_snapshot(scanner, &snapshot).map_err(|_| RuleSyncError)?;
    info!("Synced {} CID-bound rules", scanner.rule_count());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_is_generic() {
        let err = RuleSyncError;
        assert_eq!(err.to_string(), "RuleStorage content sync failed");
        assert_eq!(format!("{err:?}"), "RuleSyncError");
    }

    #[test]
    fn test_entry_debug_is_redacted() {
        let entry = RuleSyncEntry {
            expected_manifest_sha256: "SENSITIVE-HASH".to_string(),
            manifest_json: "SENSITIVE-MANIFEST".to_string(),
            constructor_json: "SENSITIVE-CONSTRUCTOR".to_string(),
            address: "SENSITIVE-ADDRESS".to_string(),
        };
        let debugged = format!("{entry:?}");
        assert!(!debugged.contains("SENSITIVE"));
    }
}

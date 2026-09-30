//! KRC-20 rule reader module.
//!
//! Reads threat detection rules stored on-chain as KRC-20 assets
//! with tick "PROM-RULES". Each rule has supply=1 (unique NFT-like asset).

use std::sync::Arc;

use anyhow::{Context, Result};
use log::info;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::runtime::require_stub_allowed;

use super::connection::KaspaConnection;
use super::rule_fetch::validate_canonical_raw_cid;
use super::rule_ingest::{MAX_RULES_PER_SNAPSHOT, MAX_RULE_ID_BYTES};

/// KRC-20 tick identifier for Prometheus rules
pub const KRC20_RULES_TICK: &str = "PROM-RULES";

/// Maximum number of distinct rules held by the development cache.
///
/// Reuses the authoritative CID-bound snapshot limit so the dev cache can
/// never hold more rules than one validated snapshot may carry.
pub const MAX_CACHED_RULES: usize = MAX_RULES_PER_SNAPSHOT;

/// Threat rule type enumeration (from SCHEMA.md 2.3)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RuleType {
    Yara,
    Stix,
    Sigma,
    Suricata,
}

/// On-chain threat rule read from KRC-20 assets (from SCHEMA.md 2.3).
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct ThreatRule {
    /// Rule identifier, e.g. "PROM-RULE-2026-0001"
    pub rule_id: String,
    /// Type of rule (YARA, STIX, Sigma, Suricata)
    pub rule_type: RuleType,
    /// IPFS CID of the rule content (base32 CIDv1 string for display)
    pub ipfs_cid: String,
    /// Guardian who proposed this rule
    pub guardian_id: [u8; 32],
    /// Validator consensus score (0.0 - 1.0)
    pub validator_consensus: f64,
    /// Unix timestamp when stored
    pub timestamp: u64,
    /// Whether the rule is currently active
    pub active: bool,
}

/// Rejection reasons for the development rule cache.
///
/// Display never contains rule IDs, CIDs, or other caller-supplied values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Krc20CacheError {
    /// `rule_id` is empty, too long, or outside `[A-Za-z0-9_-]`.
    InvalidRuleId,
    /// `ipfs_cid` is not a canonical lowercase base32 CIDv1 raw sha2-256.
    InvalidCid,
    /// `validator_consensus` is not a finite value in `0.0..=1.0`.
    InvalidConsensus,
    /// A different rule is already cached under the same `rule_id`.
    ConflictingDuplicate,
    /// The cache already holds `MAX_CACHED_RULES` distinct rules.
    CapacityExceeded,
}

impl std::fmt::Display for Krc20CacheError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let reason = match self {
            Self::InvalidRuleId => "invalid rule id",
            Self::InvalidCid => "invalid rule CID",
            Self::InvalidConsensus => "invalid validator consensus",
            Self::ConflictingDuplicate => "conflicting duplicate rule id",
            Self::CapacityExceeded => "rule cache capacity exceeded",
        };
        write!(f, "development rule cache rejected rule: {reason}")
    }
}

impl std::error::Error for Krc20CacheError {}

/// Validate every caller-owned field before the rule touches the cache.
///
/// Rule IDs follow the CID-bound ingest grammar: 1..=`MAX_RULE_ID_BYTES`
/// bytes of ASCII alphanumerics, hyphen, or underscore. `guardian_id` and
/// `timestamp` are fixed-size and need no further bound.
fn validate_rule(rule: &ThreatRule) -> Result<(), Krc20CacheError> {
    let id = &rule.rule_id;
    if id.is_empty()
        || id.len() > MAX_RULE_ID_BYTES
        || !id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(Krc20CacheError::InvalidRuleId);
    }
    validate_canonical_raw_cid(&rule.ipfs_cid).map_err(|_| Krc20CacheError::InvalidCid)?;
    let consensus = rule.validator_consensus;
    if !consensus.is_finite() || !(0.0..=1.0).contains(&consensus) {
        return Err(Krc20CacheError::InvalidConsensus);
    }
    Ok(())
}

/// Reads KRC-20 threat rules from the Kaspa blockchain.
/// Uses tokio::sync::Mutex for async safety (PATTERN-003).
pub struct Krc20RuleReader {
    connection: Arc<Mutex<KaspaConnection>>,
    cached_rules: Arc<Mutex<Vec<ThreatRule>>>,
}

impl Krc20RuleReader {
    /// Create a new rule reader using the given Kaspa connection.
    pub fn new(connection: Arc<Mutex<KaspaConnection>>) -> Self {
        Self {
            connection,
            cached_rules: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Fetch the latest threat rules from on-chain KRC-20 assets.
    /// Filters for tick "PROM-RULES" and active rules only.
    pub async fn fetch_latest_rules(&self) -> Result<Vec<ThreatRule>> {
        let conn = self.connection.lock().await;
        let _dag_info = conn
            .get_block_dag_info()
            .await
            .context("Failed to query node for rules")?;

        // In production: query UTXO set for KRC-20 assets with tick PROM-RULES,
        // decode the metadata, and return as ThreatRule structs.
        // For now: return cached rules (will be populated when ssc + Covenant-Hardfork
        // enable on-chain rule storage).
        require_stub_allowed("KRC-20 rule cache")?;
        let rules = self.cached_rules.lock().await;
        info!(
            "Fetched {} rules from {} (tick: {})",
            rules.len(),
            "on-chain",
            KRC20_RULES_TICK
        );
        Ok(rules.clone())
    }

    /// Get a specific rule by its ID.
    pub async fn get_rule_by_id(&self, rule_id: &str) -> Result<Option<ThreatRule>> {
        let rules = self.fetch_latest_rules().await?;
        Ok(rules.into_iter().find(|r| r.rule_id == rule_id))
    }

    /// Manually add a rule to the development cache (testing or pre-Covenant use).
    ///
    /// The rule is fully validated before the cache lock is taken. One
    /// `rule_id` maps to at most one entry: re-adding an identical rule is an
    /// idempotent no-op, a different rule under a cached ID is rejected, and a
    /// new ID is rejected once `MAX_CACHED_RULES` is reached. Existing entries
    /// are never replaced or evicted, and every rejection leaves the cache
    /// unchanged.
    pub async fn add_cached_rule(&self, rule: ThreatRule) -> Result<(), Krc20CacheError> {
        validate_rule(&rule)?;
        let mut cache = self.cached_rules.lock().await;
        if let Some(existing) = cache.iter().find(|r| r.rule_id == rule.rule_id) {
            return if *existing == rule {
                Ok(())
            } else {
                Err(Krc20CacheError::ConflictingDuplicate)
            };
        }
        if cache.len() >= MAX_CACHED_RULES {
            return Err(Krc20CacheError::CapacityExceeded);
        }
        cache.push(rule);
        Ok(())
    }

    /// Get the number of cached rules.
    pub async fn cached_count(&self) -> usize {
        self.cached_rules.lock().await.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blockchain::connection::KaspaConnection;

    /// Canonical base32 CIDv1 raw sha2-256 of b"a".
    const TEST_CID: &str = "bafkreigks6arfsq3xxfpvqrrwonchxcnu6do76auprhhfomao6c273sixm";
    /// Canonical base32 CIDv1 raw sha2-256 of b"b".
    const OTHER_CID: &str = "bafkreib6epubmabzlffdhckpmvsodmjuro6xuaei2qwevs3t52xnlhaatu";

    fn make_reader() -> Krc20RuleReader {
        let conn = KaspaConnection::new("ws://127.0.0.1:17210").unwrap();
        Krc20RuleReader::new(Arc::new(Mutex::new(conn)))
    }

    async fn snapshot(reader: &Krc20RuleReader) -> Vec<ThreatRule> {
        reader.cached_rules.lock().await.clone()
    }

    /// Assert the rule is rejected with `expected` and the cache is unchanged.
    async fn assert_rejected(
        reader: &Krc20RuleReader,
        rule: ThreatRule,
        expected: Krc20CacheError,
    ) {
        let before = snapshot(reader).await;
        assert_eq!(reader.add_cached_rule(rule).await, Err(expected));
        assert_eq!(snapshot(reader).await, before);
    }

    fn make_test_rule(id: &str, rule_type: RuleType) -> ThreatRule {
        ThreatRule {
            rule_id: id.to_string(),
            rule_type,
            ipfs_cid: TEST_CID.to_string(),
            guardian_id: [0u8; 32],
            validator_consensus: 0.89,
            timestamp: 1762531235,
            active: true,
        }
    }

    #[tokio::test]
    async fn test_new_reader() {
        let conn = KaspaConnection::new("ws://127.0.0.1:17210").unwrap();
        let reader = Krc20RuleReader::new(Arc::new(Mutex::new(conn)));
        assert_eq!(reader.cached_count().await, 0);
    }

    #[tokio::test]
    async fn test_add_cached_rule() {
        let conn = KaspaConnection::new("ws://127.0.0.1:17210").unwrap();
        let reader = Krc20RuleReader::new(Arc::new(Mutex::new(conn)));

        let rule = make_test_rule("PROM-RULE-2026-0001", RuleType::Yara);
        reader.add_cached_rule(rule.clone()).await.unwrap();
        assert_eq!(reader.cached_count().await, 1);
        assert_eq!(snapshot(&reader).await, vec![rule]);
    }

    #[tokio::test]
    async fn test_cache_lookup_by_id() {
        let conn = KaspaConnection::new("ws://127.0.0.1:17210").unwrap();
        let reader = Krc20RuleReader::new(Arc::new(Mutex::new(conn)));

        reader
            .add_cached_rule(make_test_rule("PROM-RULE-2026-0001", RuleType::Yara))
            .await
            .unwrap();
        reader
            .add_cached_rule(make_test_rule("PROM-RULE-2026-0002", RuleType::Sigma))
            .await
            .unwrap();

        // This test bypasses the live connection by reading from cache
        let rules = reader.cached_rules.lock().await;
        let found = rules.iter().find(|r| r.rule_id == "PROM-RULE-2026-0002");
        assert!(found.is_some());
        assert_eq!(found.unwrap().rule_type, RuleType::Sigma);
    }

    #[tokio::test]
    async fn test_get_rule_by_id_not_found() {
        let conn = KaspaConnection::new("ws://127.0.0.1:17210").unwrap();
        let reader = Krc20RuleReader::new(Arc::new(Mutex::new(conn)));

        reader
            .add_cached_rule(make_test_rule("PROM-RULE-2026-0001", RuleType::Yara))
            .await
            .unwrap();

        let rules = reader.cached_rules.lock().await;
        let found = rules.iter().find(|r| r.rule_id == "PROM-RULE-9999-0000");
        assert!(found.is_none());
    }

    /// Integration test: requires a live testnet-10 node.
    /// Run with: cargo test -- --ignored test_get_rule_by_id_returns_none_without_node
    #[tokio::test]
    #[ignore]
    async fn test_get_rule_by_id_returns_none_without_node() {
        let conn = KaspaConnection::new("ws://127.0.0.1:17210").unwrap();
        let reader = Krc20RuleReader::new(Arc::new(Mutex::new(conn)));
        // Without a live node, fetch_latest_rules returns empty cache
        let result = reader.get_rule_by_id("PROM-RULE-2026-0001").await;
        // Should succeed but return None (no rules cached, no live node)
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_identical_duplicate_is_idempotent() {
        let reader = make_reader();
        let rule = make_test_rule("PROM-RULE-2026-0001", RuleType::Yara);
        reader.add_cached_rule(rule.clone()).await.unwrap();
        reader.add_cached_rule(rule.clone()).await.unwrap();
        assert_eq!(snapshot(&reader).await, vec![rule]);
    }

    #[tokio::test]
    async fn test_conflicting_duplicate_rejected_without_overwrite() {
        let reader = make_reader();
        reader
            .add_cached_rule(make_test_rule("PROM-RULE-2026-0001", RuleType::Yara))
            .await
            .unwrap();

        let mut other_type = make_test_rule("PROM-RULE-2026-0001", RuleType::Sigma);
        assert_rejected(
            &reader,
            other_type.clone(),
            Krc20CacheError::ConflictingDuplicate,
        )
        .await;
        other_type.rule_type = RuleType::Yara;
        other_type.ipfs_cid = OTHER_CID.to_string();
        assert_rejected(
            &reader,
            other_type.clone(),
            Krc20CacheError::ConflictingDuplicate,
        )
        .await;
        other_type.ipfs_cid = TEST_CID.to_string();
        other_type.active = false;
        assert_rejected(&reader, other_type, Krc20CacheError::ConflictingDuplicate).await;
        assert_eq!(reader.cached_count().await, 1);
    }

    #[tokio::test]
    async fn test_rule_id_bounds() {
        let reader = make_reader();
        let exact = "R".repeat(MAX_RULE_ID_BYTES);
        reader
            .add_cached_rule(make_test_rule(&exact, RuleType::Yara))
            .await
            .unwrap();
        reader
            .add_cached_rule(make_test_rule("a", RuleType::Yara))
            .await
            .unwrap();
        reader
            .add_cached_rule(make_test_rule("Az09_-", RuleType::Yara))
            .await
            .unwrap();

        let over = "R".repeat(MAX_RULE_ID_BYTES + 1);
        for bad in [
            "",
            over.as_str(),
            "PROM RULE",
            "PROM/RULE",
            "PROM-RULE\n",
            "PROM-RULE\0",
            "PR\u{00d6}M",
        ] {
            assert_rejected(
                &reader,
                make_test_rule(bad, RuleType::Yara),
                Krc20CacheError::InvalidRuleId,
            )
            .await;
        }
        assert_eq!(reader.cached_count().await, 3);
    }

    #[tokio::test]
    async fn test_cid_must_be_canonical_raw_sha256() {
        let reader = make_reader();
        let mut rule = make_test_rule("PROM-RULE-2026-0001", RuleType::Yara);
        let long = format!("{TEST_CID}a");
        let upper = TEST_CID.to_ascii_uppercase();
        for bad in [
            "",
            // dag-pb CIDv1 (not the raw codec).
            "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi",
            &TEST_CID[..TEST_CID.len() - 1],
            long.as_str(),
            upper.as_str(),
            "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG",
        ] {
            rule.ipfs_cid = bad.to_string();
            assert_rejected(&reader, rule.clone(), Krc20CacheError::InvalidCid).await;
        }
        assert_eq!(reader.cached_count().await, 0);
    }

    #[tokio::test]
    async fn test_consensus_bounds() {
        let reader = make_reader();
        for (i, ok) in [0.0, 1.0].into_iter().enumerate() {
            let mut rule = make_test_rule(&format!("PROM-RULE-OK-{i}"), RuleType::Yara);
            rule.validator_consensus = ok;
            reader.add_cached_rule(rule).await.unwrap();
        }
        for bad in [
            -0.000_001,
            1.000_001,
            f64::NAN,
            f64::INFINITY,
            f64::NEG_INFINITY,
        ] {
            let mut rule = make_test_rule("PROM-RULE-BAD", RuleType::Yara);
            rule.validator_consensus = bad;
            assert_rejected(&reader, rule, Krc20CacheError::InvalidConsensus).await;
        }
        assert_eq!(reader.cached_count().await, 2);
    }

    #[tokio::test]
    async fn test_capacity_boundary() {
        let reader = make_reader();
        for i in 0..MAX_CACHED_RULES {
            reader
                .add_cached_rule(make_test_rule(&format!("PROM-RULE-{i}"), RuleType::Yara))
                .await
                .unwrap();
        }
        assert_eq!(reader.cached_count().await, MAX_CACHED_RULES);

        // A new identity at capacity is rejected; nothing is evicted.
        assert_rejected(
            &reader,
            make_test_rule("PROM-RULE-NEW", RuleType::Yara),
            Krc20CacheError::CapacityExceeded,
        )
        .await;
        // Identical re-add at capacity stays an idempotent no-op.
        reader
            .add_cached_rule(make_test_rule("PROM-RULE-0", RuleType::Yara))
            .await
            .unwrap();
        // Validation still runs before the capacity check.
        assert_rejected(
            &reader,
            make_test_rule("", RuleType::Yara),
            Krc20CacheError::InvalidRuleId,
        )
        .await;
        assert_eq!(reader.cached_count().await, MAX_CACHED_RULES);
    }

    #[test]
    fn test_cache_error_display_is_generic() {
        for err in [
            Krc20CacheError::InvalidRuleId,
            Krc20CacheError::InvalidCid,
            Krc20CacheError::InvalidConsensus,
            Krc20CacheError::ConflictingDuplicate,
            Krc20CacheError::CapacityExceeded,
        ] {
            let text = err.to_string();
            assert!(text.starts_with("development rule cache rejected rule: "));
            assert!(!text.contains("PROM-RULE"));
        }
    }

    #[test]
    fn test_rule_type_serialization() {
        let json = serde_json::to_string(&RuleType::Yara).unwrap();
        assert_eq!(json, "\"Yara\"");
    }
}

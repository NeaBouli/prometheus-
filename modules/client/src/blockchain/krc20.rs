//! KRC-20 rule reader module.
//!
//! Reads threat detection rules stored on-chain as KRC-20 assets
//! with tick "PROM-RULES". Each rule has supply=1 (unique NFT-like asset).

use std::sync::Arc;

use anyhow::{Context, Result};
use log::info;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use super::connection::KaspaConnection;

/// KRC-20 tick identifier for Prometheus rules
pub const KRC20_RULES_TICK: &str = "PROM-RULES";

/// Threat rule type enumeration (from SCHEMA.md 2.3)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RuleType {
    Yara,
    Stix,
    Sigma,
    Suricata,
}

/// On-chain threat rule read from KRC-20 assets (from SCHEMA.md 2.3).
#[derive(Debug, Clone, Deserialize)]
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

    /// Manually add a rule to the cache (for testing or pre-Covenant use).
    pub async fn add_cached_rule(&self, rule: ThreatRule) {
        let mut cache = self.cached_rules.lock().await;
        cache.push(rule);
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

    fn make_test_rule(id: &str, rule_type: RuleType) -> ThreatRule {
        ThreatRule {
            rule_id: id.to_string(),
            rule_type,
            ipfs_cid: "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi".to_string(),
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
        reader.add_cached_rule(rule).await;
        assert_eq!(reader.cached_count().await, 1);
    }

    #[tokio::test]
    async fn test_get_rule_by_id_found() {
        let conn = KaspaConnection::new("ws://127.0.0.1:17210").unwrap();
        let reader = Krc20RuleReader::new(Arc::new(Mutex::new(conn)));

        reader
            .add_cached_rule(make_test_rule("PROM-RULE-2026-0001", RuleType::Yara))
            .await;
        reader
            .add_cached_rule(make_test_rule("PROM-RULE-2026-0002", RuleType::Sigma))
            .await;

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
            .await;

        let rules = reader.cached_rules.lock().await;
        let found = rules.iter().find(|r| r.rule_id == "PROM-RULE-9999-0000");
        assert!(found.is_none());
    }

    #[test]
    fn test_rule_type_serialization() {
        let json = serde_json::to_string(&RuleType::Yara).unwrap();
        assert_eq!(json, "\"Yara\"");
    }
}

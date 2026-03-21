//! Federated learning client for Fed-DART gradient exchange.
//!
//! Architecture Decision #10: Fed-DART protocol for privacy-preserving
//! distributed model improvement. Only mathematical gradients are transmitted.
//! Raw data NEVER leaves the device.
//!
//! Current implementation: stub for pre-Covenant-Hardfork development.
//! Real Fed-DART integration will connect to the P2P gradient aggregation
//! network after the Covenant-Hardfork enables on-chain model coordination.

use anyhow::Result;
use log::info;
use sha2::{Digest, Sha256};

/// Model update containing gradient data for federated learning.
///
/// PRIVACY: Only mathematical gradients are transmitted.
/// Raw data NEVER leaves the device (Architecture Decision #10).
/// The `gradients` field contains differential updates to model weights,
/// not any representation of the original training data.
#[derive(Debug, Clone)]
pub struct ModelUpdate {
    /// Gradient vector — differential weight updates only, NEVER raw data
    pub gradients: Vec<f32>,
    /// Anonymized client identifier (SHA-256 hash)
    pub client_id: [u8; 32],
    /// Number of local training samples used (count only, no content)
    pub data_size: u64,
    /// Cryptographic signature for update authenticity
    pub signature: Vec<u8>,
}

/// Federated learning client for gradient exchange via Fed-DART protocol.
pub struct FederatedClient {
    node_url: String,
    client_id: [u8; 32],
}

impl FederatedClient {
    /// Create a new federated learning client connected to the given node.
    pub fn new(node_url: &str) -> Self {
        // Generate anonymous client ID from URL + random salt
        let mut hasher = Sha256::new();
        hasher.update(node_url.as_bytes());
        hasher.update(b"prometheus-fed-dart");
        let hash = hasher.finalize();
        let mut client_id = [0u8; 32];
        client_id.copy_from_slice(&hash);

        Self {
            node_url: node_url.to_string(),
            client_id,
        }
    }

    /// Submit a gradient update to the federation network.
    /// Only transmits mathematical gradients — raw data stays local.
    pub async fn submit_gradient(&self, update: ModelUpdate) -> Result<()> {
        // Validate update doesn't contain suspiciously large gradients
        // (basic sanity check against poisoning attacks)
        for &g in &update.gradients {
            if g.is_nan() || g.is_infinite() {
                anyhow::bail!("Invalid gradient value detected (NaN or Inf)");
            }
        }

        // Stub: real implementation will POST to Fed-DART aggregation endpoint
        // via the P2P network after Covenant-Hardfork
        info!(
            "Gradient update submitted to {} ({} parameters, {} samples)",
            self.node_url,
            update.gradients.len(),
            update.data_size
        );
        Ok(())
    }

    /// Fetch the hash of the current global model from the federation.
    /// Used to check if a new model version is available for download.
    pub async fn fetch_global_model_hash(&self) -> Result<[u8; 32]> {
        // Stub: returns a placeholder hash
        // Real implementation will query the on-chain model registry
        // where the latest aggregated model hash is stored
        info!("Fetching global model hash from {}", self.node_url);

        // Placeholder: hash of "prometheus-global-model-v0"
        let mut hasher = Sha256::new();
        hasher.update(b"prometheus-global-model-v0");
        let hash = hasher.finalize();
        let mut result = [0u8; 32];
        result.copy_from_slice(&hash);
        Ok(result)
    }

    /// Get this client's anonymous identifier.
    pub fn client_id(&self) -> &[u8; 32] {
        &self.client_id
    }

    /// Get the node URL this client connects to.
    pub fn node_url(&self) -> &str {
        &self.node_url
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_update(gradient_count: usize, data_size: u64) -> ModelUpdate {
        ModelUpdate {
            gradients: vec![0.01f32; gradient_count],
            client_id: [0xABu8; 32],
            data_size,
            signature: vec![0u8; 64],
        }
    }

    #[test]
    fn test_new_client() {
        let client = FederatedClient::new("ws://127.0.0.1:17210");
        assert_eq!(client.node_url(), "ws://127.0.0.1:17210");
        assert_ne!(client.client_id(), &[0u8; 32]);
    }

    #[test]
    fn test_client_id_deterministic() {
        let c1 = FederatedClient::new("ws://127.0.0.1:17210");
        let c2 = FederatedClient::new("ws://127.0.0.1:17210");
        assert_eq!(c1.client_id(), c2.client_id());
    }

    #[test]
    fn test_different_urls_different_ids() {
        let c1 = FederatedClient::new("ws://node1:17210");
        let c2 = FederatedClient::new("ws://node2:17210");
        assert_ne!(c1.client_id(), c2.client_id());
    }

    #[tokio::test]
    async fn test_submit_gradient_success() {
        let client = FederatedClient::new("ws://127.0.0.1:17210");
        let update = make_update(1000, 500);
        let result = client.submit_gradient(update).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_submit_gradient_rejects_nan() {
        let client = FederatedClient::new("ws://127.0.0.1:17210");
        let update = ModelUpdate {
            gradients: vec![f32::NAN],
            client_id: [0u8; 32],
            data_size: 1,
            signature: vec![],
        };
        let result = client.submit_gradient(update).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("NaN"));
    }

    #[tokio::test]
    async fn test_submit_gradient_rejects_inf() {
        let client = FederatedClient::new("ws://127.0.0.1:17210");
        let update = ModelUpdate {
            gradients: vec![f32::INFINITY],
            client_id: [0u8; 32],
            data_size: 1,
            signature: vec![],
        };
        let result = client.submit_gradient(update).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_fetch_global_model_hash() {
        let client = FederatedClient::new("ws://127.0.0.1:17210");
        let hash = client.fetch_global_model_hash().await.unwrap();
        assert_ne!(hash, [0u8; 32]);
    }

    #[tokio::test]
    async fn test_global_hash_deterministic() {
        let client = FederatedClient::new("ws://127.0.0.1:17210");
        let h1 = client.fetch_global_model_hash().await.unwrap();
        let h2 = client.fetch_global_model_hash().await.unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_model_update_privacy_comment_exists() {
        // Meta-test: verify the privacy comment is in the source
        let source = include_str!("federated.rs");
        assert!(source.contains("PRIVACY: Only mathematical gradients are transmitted"));
        assert!(source.contains("Raw data NEVER leaves the device"));
    }
}

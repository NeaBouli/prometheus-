//! Kaspa RPC connection module.
//!
//! Connects to a Kaspa node via wRPC (WebSocket RPC) using Borsh encoding.
//! Target: ws://127.0.0.1:17210 (Testnet-10 node).
//! PATTERN-003 applied: tokio::sync::Mutex used throughout, never std::sync::Mutex.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use kaspa_rpc_core::api::rpc::RpcApi;
use kaspa_wrpc_client::client::{ConnectOptions, ConnectStrategy};
use kaspa_wrpc_client::prelude::{NetworkId, NetworkType};
use kaspa_wrpc_client::{KaspaRpcClient, WrpcEncoding};
use log::info;
use tokio::sync::Mutex;

/// Default wRPC endpoint for Testnet-10
pub const TESTNET_WRPC_URL: &str = "ws://127.0.0.1:17210";

/// Connection timeout in seconds
const CONNECT_TIMEOUT_SECS: u64 = 10;

/// Block DAG info returned by the node.
#[derive(Debug, Clone)]
pub struct BlockDagInfo {
    /// Network name (e.g. "kaspa-testnet-10")
    pub network: String,
    /// Total block count in the DAG
    pub block_count: u64,
    /// Total header count
    pub header_count: u64,
    /// Number of DAG tips
    pub tip_count: usize,
    /// Virtual DAA score
    pub virtual_daa_score: u64,
}

/// Kaspa node connection via wRPC.
/// Uses tokio::sync::Mutex (PATTERN-003) for async safety.
pub struct KaspaConnection {
    client: Arc<Mutex<KaspaRpcClient>>,
    url: String,
    connected: Arc<Mutex<bool>>,
}

impl KaspaConnection {
    /// Create a new connection instance for the given wRPC URL.
    pub fn new(url: &str) -> Result<Self> {
        let encoding = WrpcEncoding::Borsh;
        let network_id = NetworkId::with_suffix(NetworkType::Testnet, 10);

        let client = KaspaRpcClient::new(encoding, Some(url), None, Some(network_id), None)
            .context("Failed to create Kaspa RPC client")?;

        Ok(Self {
            client: Arc::new(Mutex::new(client)),
            url: url.to_string(),
            connected: Arc::new(Mutex::new(false)),
        })
    }

    /// Connect to the Kaspa node.
    pub async fn connect(&self) -> Result<()> {
        let options = ConnectOptions {
            block_async_connect: true,
            connect_timeout: Some(Duration::from_secs(CONNECT_TIMEOUT_SECS)),
            strategy: ConnectStrategy::Fallback,
            ..Default::default()
        };

        let client = self.client.lock().await;
        client
            .connect(Some(options))
            .await
            .context("Failed to connect to Kaspa node")?;
        drop(client);

        let mut connected = self.connected.lock().await;
        *connected = true;

        info!("Connected to Kaspa node at {}", self.url);
        Ok(())
    }

    /// Query the block DAG info from the connected node.
    pub async fn get_block_dag_info(&self) -> Result<BlockDagInfo> {
        let client = self.client.lock().await;
        let info = client
            .get_block_dag_info()
            .await
            .context("Failed to get block DAG info")?;

        Ok(BlockDagInfo {
            network: info.network.to_string(),
            block_count: info.block_count,
            header_count: info.header_count,
            tip_count: info.tip_hashes.len(),
            virtual_daa_score: info.virtual_daa_score,
        })
    }

    /// Check if currently connected to the node.
    pub async fn is_connected(&self) -> bool {
        *self.connected.lock().await
    }

    /// Get a reference to the underlying RPC client (for advanced use).
    pub fn rpc_client(&self) -> Arc<Mutex<KaspaRpcClient>> {
        Arc::clone(&self.client)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_connection() {
        let conn = KaspaConnection::new(TESTNET_WRPC_URL);
        assert!(conn.is_ok());
    }

    #[test]
    fn test_new_connection_custom_url() {
        let conn = KaspaConnection::new("ws://192.168.1.100:17210");
        assert!(conn.is_ok());
    }

    #[tokio::test]
    async fn test_initially_disconnected() {
        let conn = KaspaConnection::new(TESTNET_WRPC_URL).unwrap();
        assert!(!conn.is_connected().await);
    }

    /// Integration test: connects to a live testnet-10 node.
    /// Run with: cargo test -- --ignored test_live_connection
    #[tokio::test]
    #[ignore]
    async fn test_live_connection() {
        let conn = KaspaConnection::new(TESTNET_WRPC_URL).unwrap();
        conn.connect().await.unwrap();
        assert!(conn.is_connected().await);

        let info = conn.get_block_dag_info().await.unwrap();
        assert!(info.network.contains("testnet"));
        assert!(info.block_count > 0);
    }
}

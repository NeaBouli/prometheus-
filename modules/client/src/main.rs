//! Prometheus Light Client — Kaspa-based decentralized threat intelligence.
//!
//! Connects to the Kaspa network via wRPC, reads KRC-20 threat rules,
//! and provides local security scanning.

pub mod blockchain;
pub mod network;
pub mod security;

use log::info;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();
    info!("Prometheus Light Client starting");

    // Placeholder — full client loop will be implemented in Sprint 6 (E2E)
    info!("Client modules loaded: blockchain, security, network");
    Ok(())
}

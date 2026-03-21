//! Prometheus Light Client — Kaspa-based decentralized threat intelligence.
//!
//! Connects to the Kaspa network via wRPC, reads KRC-20 threat rules,
//! and provides local security scanning.

use log::info;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();
    info!("Prometheus Light Client starting");
    info!("Client modules loaded: blockchain, security, network, ai");
    Ok(())
}

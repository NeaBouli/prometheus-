//! Prometheus Light Client — Kaspa-based decentralized threat intelligence.
//!
//! Connects to the Kaspa network via wRPC, reads KRC-20 threat rules,
//! and provides local security scanning.

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use log::{info, warn};
use prometheus_client::miner_companion::MinerCompanionConfig;
use prometheus_client::runtime::RuntimeMode;
use tokio::time::{self, MissedTickBehavior};

#[derive(Debug, Parser)]
#[command(name = "prometheus-client", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Experimental local observer for Kaspa mining infrastructure.
    #[command(subcommand)]
    MinerCompanion(MinerCompanionCommand),
}

#[derive(Debug, Subcommand)]
enum MinerCompanionCommand {
    /// Validate config without starting background activity.
    Preflight {
        #[arg(long)]
        config: PathBuf,
        /// Also connect once and query BlockDAG information.
        #[arg(long)]
        connect: bool,
    },
    /// Observe local Testnet-10 BlockDAG health until interrupted.
    Run {
        #[arg(long)]
        config: PathBuf,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();
    match Cli::parse().command {
        Some(Command::MinerCompanion(MinerCompanionCommand::Preflight { config, connect })) => {
            preflight_miner_companion(config, connect).await?;
        }
        Some(Command::MinerCompanion(MinerCompanionCommand::Run { config })) => {
            run_miner_companion(config).await?;
        }
        None => {
            info!("Prometheus Light Client starting");
            info!("Client modules loaded: blockchain, security, network, ai");
        }
    }
    Ok(())
}

async fn preflight_miner_companion(config_path: PathBuf, connect: bool) -> anyhow::Result<()> {
    let config = MinerCompanionConfig::from_toml_file(&config_path)?;
    let validated = config.validate(RuntimeMode::from_env())?;

    if connect {
        let connection = validated.create_connection()?;
        connection.connect().await?;
        let dag = connection.get_block_dag_info().await?;
        info!(
            "Local Testnet-10 RPC healthy: network={}, blocks={}, daa={}",
            dag.network, dag.block_count, dag.virtual_daa_score
        );
    }

    println!(
        "{}",
        serde_json::to_string_pretty(&validated.preflight_report())?
    );
    Ok(())
}

async fn run_miner_companion(config_path: PathBuf) -> anyhow::Result<()> {
    let config = MinerCompanionConfig::from_toml_file(&config_path)?;
    let validated = config.validate(RuntimeMode::from_env())?;
    let connection = validated.create_connection()?;
    connection.connect().await?;

    warn!(
        "Experimental miner companion active: RPC observation only; scanning, reporting, and rewards are disabled"
    );
    let mut interval = time::interval(validated.poll_interval());
    interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = interval.tick() => {
                match connection.get_block_dag_info().await {
                    Ok(dag) => info!(
                        "Kaspa DAG health: network={}, blocks={}, headers={}, tips={}, daa={}",
                        dag.network,
                        dag.block_count,
                        dag.header_count,
                        dag.tip_count,
                        dag.virtual_daa_score
                    ),
                    Err(_) => warn!(
                        "Failed to query BlockDAG health; retrying on the next interval"
                    ),
                }
            }
            signal = tokio::signal::ctrl_c() => {
                signal?;
                info!("Miner companion stopped by operator");
                break;
            }
        }
    }

    Ok(())
}

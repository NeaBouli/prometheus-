//! Prometheus Light Client — Kaspa-based decentralized threat intelligence.
//!
//! Connects to the Kaspa network via wRPC, reads KRC-20 threat rules,
//! and provides local security scanning.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use clap::{Parser, Subcommand};
use log::{info, warn};
use prometheus_client::miner_companion::MinerCompanionConfig;
use prometheus_client::rule_sync_cli::{RuleSyncConfig, SystemRuleSnapshotClock};
use prometheus_client::runtime::RuntimeMode;
use prometheus_client::security::scanner::YaraScanner;
use tokio::sync::watch;
use tokio::time::{self, MissedTickBehavior};

const RULE_SYNC_PROBE_TIMEOUT: Duration = Duration::from_secs(15);

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
    /// Opt-in Development/Testnet-10 RuleStorage synchronization.
    #[command(subcommand)]
    RuleSync(RuleSyncCommand),
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

#[derive(Debug, Subcommand)]
enum RuleSyncCommand {
    /// Verify owner-local configuration and signed envelope without mutation.
    Preflight {
        #[arg(long)]
        config: PathBuf,
        /// Also perform one bounded read-only connection health query.
        #[arg(long)]
        connect: bool,
    },
    /// Run the bounded RuleStorage coordinator until an operator signal.
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
        Some(Command::RuleSync(RuleSyncCommand::Preflight { config, connect })) => {
            preflight_rule_sync(config, connect).await?;
        }
        Some(Command::RuleSync(RuleSyncCommand::Run { config })) => {
            run_rule_sync(config).await?;
        }
        None => {
            info!("Prometheus Light Client starting");
            info!("Client modules loaded: blockchain, security, network, ai");
        }
    }
    Ok(())
}

async fn preflight_rule_sync(config_path: PathBuf, connect: bool) -> anyhow::Result<()> {
    let config = RuleSyncConfig::from_toml_file(&config_path)?;
    let validated = config.validate(RuntimeMode::from_env())?;
    let report = validated.offline_preflight(Arc::new(SystemRuleSnapshotClock))?;

    if connect {
        let connection = validated.create_connection()?;
        time::timeout(RULE_SYNC_PROBE_TIMEOUT, async {
            connection.connect().await?;
            connection.get_block_dag_info().await?;
            Ok::<(), anyhow::Error>(())
        })
        .await
        .map_err(|_| anyhow::anyhow!("rule sync connection probe failed"))?
        .map_err(|_| anyhow::anyhow!("rule sync connection probe failed"))?;
    }

    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

async fn run_rule_sync(config_path: PathBuf) -> anyhow::Result<()> {
    let config = RuleSyncConfig::from_toml_file(&config_path)?;
    let validated = config.validate(RuntimeMode::from_env())?;
    let provider = validated.create_signed_provider(Arc::new(SystemRuleSnapshotClock))?;
    let coordinator = validated.create_coordinator()?;
    let status = coordinator.status_handle();
    let store = validated.open_checkpoint_store()?;
    let content_source = validated.create_content_source()?;
    let connection = validated.create_connection()?;
    let mut scanner = YaraScanner::new()?;
    connection
        .connect()
        .await
        .map_err(|_| anyhow::anyhow!("rule sync connection failed"))?;

    warn!(
        "Development/Testnet-10 RuleStorage sync active; production authority and chain writes remain disabled"
    );
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
    let run = coordinator.run(
        &mut shutdown_rx,
        &store,
        &mut scanner,
        &content_source,
        &connection,
        &provider,
    );
    tokio::pin!(run);
    let signal = shutdown_signal();
    tokio::pin!(signal);
    let mut status_interval = time::interval(Duration::from_secs(30));
    status_interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            result = &mut run => {
                result?;
                break;
            }
            result = &mut signal => {
                result?;
                shutdown_tx.send(true).map_err(|_| anyhow::anyhow!("rule sync shutdown failed"))?;
                run.await?;
                info!("RuleStorage sync stopped by operator");
                break;
            }
            _ = status_interval.tick() => {
                let snapshot = status.snapshot();
                println!(
                    "{}",
                    serde_json::json!({
                        "component": "rule-storage-sync",
                        "attempts": snapshot.attempts,
                        "successes": snapshot.successes,
                        "failures": snapshot.failures,
                        "consecutive_failures": snapshot.consecutive_failures,
                        "phase": format!("{:?}", snapshot.phase).to_ascii_lowercase(),
                        "last_outcome": snapshot.last_outcome.map(|value| format!("{value:?}").to_ascii_lowercase()),
                    })
                );
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
async fn shutdown_signal() -> std::io::Result<()> {
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        result = tokio::signal::ctrl_c() => result,
        _ = terminate.recv() => Ok(()),
    }
}

#[cfg(not(unix))]
async fn shutdown_signal() -> std::io::Result<()> {
    tokio::signal::ctrl_c().await
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

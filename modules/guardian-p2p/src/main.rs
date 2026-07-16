use std::{
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
    str::FromStr,
    time::Duration,
};

use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};
use libp2p_identity::PeerId;
use prometheus_guardian_p2p::{
    local_submit::submit_ballot,
    service::{run_service, ServiceConfig},
    BallotBytes, MAX_BALLOT_BYTES,
};
use serde::Serialize;

#[derive(Debug, Parser)]
#[command(name = "prometheus-guardian-p2p")]
#[command(about = "Operated Guardian ballot sidecar and relay")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Validate owner-only configuration and persistent identity without networking.
    Preflight {
        #[arg(long)]
        config: PathBuf,
    },
    /// Run a Guardian sidecar or relay until SIGINT or SIGTERM.
    Run {
        #[arg(long)]
        config: PathBuf,
    },
    /// Submit one opaque ballot to an owner-only local sidecar socket.
    Submit {
        #[arg(long)]
        socket: PathBuf,
        #[arg(long)]
        peer: String,
        #[arg(long)]
        ballot: PathBuf,
        #[arg(long, default_value_t = 10, value_parser = clap::value_parser!(u64).range(1..=60))]
        timeout_secs: u64,
    },
}

#[derive(Serialize)]
struct SubmitReport {
    schema_version: u8,
    service: &'static str,
    event: &'static str,
    status: &'static str,
    peer_id: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Preflight { config } => {
            let service = load_service(&config)?;
            write_json(&service.preflight_report())
        }
        Command::Run { config } => {
            let service = load_service(&config)?;
            run_service(service).await.map_err(|error| anyhow!(error))
        }
        Command::Submit {
            socket,
            peer,
            ballot,
            timeout_secs,
        } => {
            let peer_id = parse_peer_id(&peer)?;
            let ballot = read_ballot(&ballot)?;
            let status = submit_ballot(
                &socket,
                &peer_id,
                &ballot,
                Duration::from_secs(timeout_secs),
            )
            .await
            .map_err(|error| anyhow!(error))?;
            write_json(&SubmitReport {
                schema_version: 1,
                service: "prometheus-guardian-p2p",
                event: "local-submission",
                status: status.as_str(),
                peer_id: peer_id.to_string(),
            })
        }
    }
}

fn load_service(path: &Path) -> Result<prometheus_guardian_p2p::service::PreparedService> {
    ServiceConfig::from_toml_file(path)
        .and_then(ServiceConfig::prepare)
        .map_err(|error| anyhow!(error))
}

fn parse_peer_id(value: &str) -> Result<PeerId> {
    let peer = PeerId::from_str(value).map_err(|_| anyhow!("invalid transport peer id"))?;
    if value != peer.to_string() {
        return Err(anyhow!("transport peer id must be canonical"));
    }
    Ok(peer)
}

fn read_ballot(path: &Path) -> Result<BallotBytes> {
    let mut bytes = Vec::with_capacity(MAX_BALLOT_BYTES + 1);
    File::open(path)
        .map_err(|_| anyhow!("unable to open ballot file"))?
        .take((MAX_BALLOT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| anyhow!("unable to read ballot file"))?;
    BallotBytes::new(bytes).map_err(|_| anyhow!("ballot size is out of bounds"))
}

fn write_json(value: &impl Serialize) -> Result<()> {
    let stdout = std::io::stdout();
    let mut stdout = stdout.lock();
    serde_json::to_writer_pretty(&mut stdout, value)?;
    stdout.write_all(b"\n")?;
    stdout.flush()?;
    Ok(())
}

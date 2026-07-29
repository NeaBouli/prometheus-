#![deny(warnings)]

use std::io::{self, Read};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use prometheus_threat_hint::{MAX_CANONICAL_BYTES, MAX_CANONICAL_V2_PROOF_ENVELOPE_BYTES};
use prometheus_threat_proof::threat_hint_v2_groth16_verifier::TrustedGroth16V2Verifier;
use prometheus_threat_proof::TrustedGroth16Verifier;

const EXIT_INVALID_PROOF: u8 = 1;
const EXIT_UNAVAILABLE: u8 = 3;

#[derive(Debug, Parser)]
#[command(name = "prometheus-threat-proof")]
#[command(about = "Silent manifest-pinned KIP-16 ThreatHint verifier")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Verify {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        expected_manifest_sha256: String,
        #[arg(long)]
        network_id: String,
    },
    VerifyV2 {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        expected_manifest_sha256: String,
        #[arg(long)]
        network_id: String,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Verify {
            manifest,
            expected_manifest_sha256,
            network_id,
        } => verify(&manifest, &expected_manifest_sha256, &network_id),
        Command::VerifyV2 {
            manifest,
            expected_manifest_sha256,
            network_id,
        } => verify_v2(&manifest, &expected_manifest_sha256, &network_id),
    }
}

fn verify(manifest: &std::path::Path, expected_hash: &str, network_id: &str) -> ExitCode {
    let verifier = match TrustedGroth16Verifier::load(manifest, expected_hash) {
        Ok(verifier) => verifier,
        Err(_) => return ExitCode::from(EXIT_UNAVAILABLE),
    };
    let mut wire = Vec::with_capacity(MAX_CANONICAL_BYTES);
    if io::stdin()
        .take(MAX_CANONICAL_BYTES as u64 + 1)
        .read_to_end(&mut wire)
        .is_err()
        || wire.is_empty()
        || wire.len() > MAX_CANONICAL_BYTES
    {
        return ExitCode::from(EXIT_INVALID_PROOF);
    }
    match verifier.verify_wire(&wire, network_id) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(EXIT_INVALID_PROOF),
        Err(_) => ExitCode::from(EXIT_UNAVAILABLE),
    }
}

fn verify_v2(manifest: &std::path::Path, expected_hash: &str, network_id: &str) -> ExitCode {
    let verifier = match TrustedGroth16V2Verifier::load(manifest, expected_hash, network_id) {
        Ok(verifier) => verifier,
        Err(_) => return ExitCode::from(EXIT_UNAVAILABLE),
    };
    let mut wire = Vec::with_capacity(MAX_CANONICAL_V2_PROOF_ENVELOPE_BYTES);
    if io::stdin()
        .take(MAX_CANONICAL_V2_PROOF_ENVELOPE_BYTES as u64 + 1)
        .read_to_end(&mut wire)
        .is_err()
        || wire.is_empty()
        || wire.len() > MAX_CANONICAL_V2_PROOF_ENVELOPE_BYTES
    {
        return ExitCode::from(EXIT_INVALID_PROOF);
    }
    match verifier.verify_wire(&wire) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(EXIT_INVALID_PROOF),
        Err(_) => ExitCode::from(EXIT_UNAVAILABLE),
    }
}

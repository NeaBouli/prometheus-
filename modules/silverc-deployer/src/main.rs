use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use kaspa_wrpc_client::WrpcEncoding;
use prometheus_silverc_deployer::{
    broadcast_verified_transaction, load_artifact, load_deploy_request, load_funding_spec,
    load_signature_response, load_signing_request, observe_deployed_utxo, preflight_deploy_node,
    prepare_genesis, verify_signature_response, write_public_json,
};

#[derive(Debug, Clone, Copy, ValueEnum)]
enum Encoding {
    Borsh,
    Json,
}

impl From<Encoding> for WrpcEncoding {
    fn from(value: Encoding) -> Self {
        match value {
            Encoding::Borsh => WrpcEncoding::Borsh,
            Encoding::Json => WrpcEncoding::SerdeJson,
        }
    }
}

#[derive(Debug, Parser)]
#[command(
    name = "prometheus-silverc-deployer",
    about = "Keyless Prometheus SilverScript genesis operator for Toccata transaction v1"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Verify node network, sync state, UTXO index, and live Toccata activation.
    Preflight {
        #[arg(long)]
        request: PathBuf,
        #[arg(long)]
        funding: PathBuf,
        #[arg(long, value_enum, default_value_t = Encoding::Borsh)]
        encoding: Encoding,
        #[arg(long)]
        evidence_out: PathBuf,
    },
    /// Build and verify a public digest request for an external Schnorr signer.
    Prepare {
        #[arg(long)]
        request: PathBuf,
        #[arg(long)]
        artifact: PathBuf,
        #[arg(long)]
        funding: PathBuf,
        #[arg(long)]
        signing_request_out: PathBuf,
    },
    /// Verify an externally produced BIP340 signature and the complete transaction.
    VerifySignature {
        #[arg(long)]
        request: PathBuf,
        #[arg(long)]
        artifact: PathBuf,
        #[arg(long)]
        funding: PathBuf,
        #[arg(long)]
        signing_request: PathBuf,
        #[arg(long)]
        signature_response: PathBuf,
        #[arg(long)]
        verification_out: PathBuf,
    },
    /// Rebuild, verify, acknowledge, and submit the signed transaction.
    Broadcast {
        #[arg(long)]
        request: PathBuf,
        #[arg(long)]
        artifact: PathBuf,
        #[arg(long)]
        funding: PathBuf,
        #[arg(long)]
        signing_request: PathBuf,
        #[arg(long)]
        signature_response: PathBuf,
        #[arg(long)]
        acknowledge_signing_request_sha256: String,
        #[arg(long, value_enum, default_value_t = Encoding::Borsh)]
        encoding: Encoding,
        #[arg(long)]
        result_out: PathBuf,
    },
    /// Query the request-bound node for the deployed covenant UTXO.
    Observe {
        #[arg(long)]
        signing_request: PathBuf,
        #[arg(long, value_enum, default_value_t = Encoding::Borsh)]
        encoding: Encoding,
        #[arg(long)]
        evidence_out: PathBuf,
    },
}

fn rebuild_and_verify(
    request_path: &std::path::Path,
    artifact_path: &std::path::Path,
    funding_path: &std::path::Path,
    signing_request_path: &std::path::Path,
    signature_response_path: &std::path::Path,
) -> Result<(
    prometheus_silverc_deployer::VerifiedSignedTransaction,
    prometheus_silverc_deployer::SigningRequest,
)> {
    let request = load_deploy_request(request_path)?;
    let artifact = load_artifact(artifact_path, &request)?;
    let funding = load_funding_spec(funding_path)?;
    let prepared = prepare_genesis(&request, &artifact, &funding)?;
    let signing_request = load_signing_request(signing_request_path)?;
    let signature_response = load_signature_response(signature_response_path)?;
    let verified = verify_signature_response(prepared, &signing_request, &signature_response)?;
    Ok((verified, signing_request))
}

#[tokio::main]
async fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Preflight {
            request,
            funding,
            encoding,
            evidence_out,
        } => {
            let request = load_deploy_request(&request)?;
            let funding = load_funding_spec(&funding)?;
            let evidence = preflight_deploy_node(&request, &funding, encoding.into()).await?;
            write_public_json(&evidence_out, &evidence)?;
            println!("{}", serde_json::to_string_pretty(&evidence)?);
        }
        Command::Prepare {
            request,
            artifact,
            funding,
            signing_request_out,
        } => {
            let request = load_deploy_request(&request)?;
            let artifact = load_artifact(&artifact, &request)?;
            let funding = load_funding_spec(&funding)?;
            let prepared = prepare_genesis(&request, &artifact, &funding)?;
            write_public_json(&signing_request_out, &prepared.signing_request)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&prepared.signing_request)?
            );
        }
        Command::VerifySignature {
            request,
            artifact,
            funding,
            signing_request,
            signature_response,
            verification_out,
        } => {
            let (verified, _) = rebuild_and_verify(
                &request,
                &artifact,
                &funding,
                &signing_request,
                &signature_response,
            )?;
            write_public_json(&verification_out, &verified.verification)?;
            println!("{}", serde_json::to_string_pretty(&verified.verification)?);
        }
        Command::Broadcast {
            request,
            artifact,
            funding,
            signing_request,
            signature_response,
            acknowledge_signing_request_sha256,
            encoding,
            result_out,
        } => {
            let (verified, signing_request) = rebuild_and_verify(
                &request,
                &artifact,
                &funding,
                &signing_request,
                &signature_response,
            )?;
            let result = broadcast_verified_transaction(
                verified,
                &signing_request,
                &acknowledge_signing_request_sha256,
                encoding.into(),
            )
            .await?;
            write_public_json(&result_out, &result)?;
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        Command::Observe {
            signing_request,
            encoding,
            evidence_out,
        } => {
            let signing_request = load_signing_request(&signing_request)?;
            let evidence = observe_deployed_utxo(&signing_request, encoding.into()).await?;
            write_public_json(&evidence_out, &evidence)?;
            println!("{}", serde_json::to_string_pretty(&evidence)?);
        }
    }
    Ok(())
}

use std::path::PathBuf;
use std::str::FromStr;

use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use kaspa_consensus_core::network::NetworkId;
use kaspa_wrpc_client::WrpcEncoding;
use prometheus_silverc_deployer::oracle::{
    broadcast_verified_oracle_transition, finalize_oracle_broadcast_journal,
    import_oracle_signature_files, load_oracle_broadcast_journal, load_oracle_broadcast_result,
    load_transition_spec, observe_oracle_successor, preflight_oracle_transition,
    prepare_oracle_broadcast_journal, prepare_oracle_transition,
    rebuild_verified_oracle_transition, reject_oracle_output_collisions,
};
use prometheus_silverc_deployer::{
    acquire_broadcast_lock, broadcast_journal_path, broadcast_verified_transaction,
    create_public_json, finalize_broadcast_journal, import_external_signature_files, load_artifact,
    load_broadcast_journal, load_broadcast_result, load_deploy_request, load_funding_spec,
    load_signature_response, load_signing_request, observe_deployed_utxo, preflight_deploy_node,
    preflight_node, prepare_broadcast_journal, prepare_genesis, verify_signature_response,
    write_public_json,
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
    about = "Keyless Prometheus SilverScript genesis and state-transition operator for Toccata transaction v1"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Verify a read-only node, UTXO index, and live Toccata state without funding.
    Probe {
        #[arg(long)]
        rpc_url: String,
        #[arg(long)]
        network_id: String,
        #[arg(long, value_enum, default_value_t = Encoding::Borsh)]
        encoding: Encoding,
        #[arg(long)]
        evidence_out: PathBuf,
    },
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
    /// Bind a plain external BIP340 signature and verify the complete transaction.
    ImportSignature {
        #[arg(long)]
        request: PathBuf,
        #[arg(long)]
        artifact: PathBuf,
        #[arg(long)]
        funding: PathBuf,
        #[arg(long)]
        signing_request: PathBuf,
        #[arg(long)]
        signature_hex_file: PathBuf,
        #[arg(long)]
        signature_response_out: PathBuf,
        #[arg(long)]
        verification_out: PathBuf,
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
        request: PathBuf,
        #[arg(long)]
        artifact: PathBuf,
        #[arg(long)]
        funding: PathBuf,
        #[arg(long)]
        signing_request: PathBuf,
        #[arg(long)]
        signature_response: PathBuf,
        #[arg(long, value_enum, default_value_t = Encoding::Borsh)]
        encoding: Encoding,
        #[arg(long)]
        evidence_out: PathBuf,
    },
    /// Build a dual-signature request for a value-preserving reportMetrics transition.
    ReportMetricsPrepare {
        #[arg(long)]
        transition_spec: PathBuf,
        #[arg(long)]
        metrics_tx_request: PathBuf,
        #[arg(long)]
        contract_source: PathBuf,
        #[arg(long)]
        signing_request_out: PathBuf,
    },
    /// Verify the exact live state and fee-sponsor UTXOs without signing or broadcasting.
    ReportMetricsPreflight {
        #[arg(long)]
        transition_spec: PathBuf,
        #[arg(long)]
        metrics_tx_request: PathBuf,
        #[arg(long)]
        contract_source: PathBuf,
        #[arg(long, value_enum, default_value_t = Encoding::Borsh)]
        encoding: Encoding,
        #[arg(long)]
        evidence_out: PathBuf,
    },
    /// Import canonical oracle and sponsor signatures and verify every transaction input.
    ReportMetricsImportSignatures {
        #[arg(long)]
        transition_spec: PathBuf,
        #[arg(long)]
        metrics_tx_request: PathBuf,
        #[arg(long)]
        contract_source: PathBuf,
        #[arg(long)]
        signing_request: PathBuf,
        #[arg(long)]
        oracle_signature_hex_file: PathBuf,
        #[arg(long)]
        sponsor_signature_hex_file: PathBuf,
        #[arg(long)]
        verification_out: PathBuf,
    },
    /// Rebuild, fully verify, acknowledge, and submit the reportMetrics transition once.
    ReportMetricsBroadcast {
        #[arg(long)]
        transition_spec: PathBuf,
        #[arg(long)]
        metrics_tx_request: PathBuf,
        #[arg(long)]
        contract_source: PathBuf,
        #[arg(long)]
        signing_request: PathBuf,
        #[arg(long)]
        oracle_signature_hex_file: PathBuf,
        #[arg(long)]
        sponsor_signature_hex_file: PathBuf,
        #[arg(long)]
        acknowledge_signing_request_sha256: String,
        #[arg(long, value_enum, default_value_t = Encoding::Borsh)]
        encoding: Encoding,
        #[arg(long)]
        result_out: PathBuf,
    },
    /// Observe the exact confirmed successor covenant UTXO.
    ReportMetricsObserve {
        #[arg(long)]
        transition_spec: PathBuf,
        #[arg(long)]
        metrics_tx_request: PathBuf,
        #[arg(long)]
        contract_source: PathBuf,
        #[arg(long)]
        signing_request: PathBuf,
        #[arg(long)]
        oracle_signature_hex_file: PathBuf,
        #[arg(long)]
        sponsor_signature_hex_file: PathBuf,
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
        Command::Probe {
            rpc_url,
            network_id,
            encoding,
            evidence_out,
        } => {
            let network_id = NetworkId::from_str(&network_id)?;
            let evidence = preflight_node(&rpc_url, network_id, encoding.into(), true).await?;
            write_public_json(&evidence_out, &evidence)?;
            println!("{}", serde_json::to_string_pretty(&evidence)?);
        }
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
        Command::ImportSignature {
            request,
            artifact,
            funding,
            signing_request,
            signature_hex_file,
            signature_response_out,
            verification_out,
        } => {
            let verification = import_external_signature_files(
                &request,
                &artifact,
                &funding,
                &signing_request,
                &signature_hex_file,
                &signature_response_out,
                &verification_out,
            )?;
            println!("{}", serde_json::to_string_pretty(&verification)?);
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
            let expected_journal = prepare_broadcast_journal(
                &verified,
                &signing_request,
                &acknowledge_signing_request_sha256,
            )?;
            let _broadcast_lock = acquire_broadcast_lock(&result_out)?;
            let journal_path = broadcast_journal_path(&result_out);
            let mut journal = if create_public_json(&journal_path, &expected_journal)? {
                expected_journal
            } else {
                load_broadcast_journal(&journal_path, &expected_journal)?
            };

            if let Some(recorded_result) = journal.result.as_ref() {
                if result_out.try_exists()? {
                    let existing_result = load_broadcast_result(&result_out, &journal)?;
                    if existing_result != *recorded_result {
                        anyhow::bail!("broadcast result differs from the finalized intent journal");
                    }
                } else {
                    write_public_json(&result_out, recorded_result)?;
                }
                println!("{}", serde_json::to_string_pretty(recorded_result)?);
                return Ok(());
            }

            if result_out.try_exists()? {
                let result = load_broadcast_result(&result_out, &journal)?;
                let journal = finalize_broadcast_journal(journal, result.clone())?;
                write_public_json(&journal_path, &journal)?;
                println!("{}", serde_json::to_string_pretty(&result)?);
                return Ok(());
            }

            let result = broadcast_verified_transaction(
                verified,
                &signing_request,
                &acknowledge_signing_request_sha256,
                encoding.into(),
                &mut journal,
                &journal_path,
            )
            .await?;
            let journal = finalize_broadcast_journal(journal, result.clone())?;
            write_public_json(&journal_path, &journal)?;
            write_public_json(&result_out, &result)?;
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        Command::Observe {
            request,
            artifact,
            funding,
            signing_request,
            signature_response,
            encoding,
            evidence_out,
        } => {
            let (verified, signing_request) = rebuild_and_verify(
                &request,
                &artifact,
                &funding,
                &signing_request,
                &signature_response,
            )?;
            let evidence =
                observe_deployed_utxo(&verified, &signing_request, encoding.into()).await?;
            write_public_json(&evidence_out, &evidence)?;
            println!("{}", serde_json::to_string_pretty(&evidence)?);
        }
        Command::ReportMetricsPrepare {
            transition_spec,
            metrics_tx_request,
            contract_source,
            signing_request_out,
        } => {
            reject_oracle_output_collisions(
                &[
                    ("transition-spec input", &transition_spec),
                    ("metrics-tx-request input", &metrics_tx_request),
                    ("contract-source input", &contract_source),
                ],
                &[("signing-request output", &signing_request_out)],
            )?;
            let spec = load_transition_spec(&transition_spec)?;
            let source = std::fs::read_to_string(&contract_source)?;
            let prepared = prepare_oracle_transition(&spec, &metrics_tx_request, &source)?;
            write_public_json(&signing_request_out, &prepared.signing_request)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&prepared.signing_request)?
            );
        }
        Command::ReportMetricsPreflight {
            transition_spec,
            metrics_tx_request,
            contract_source,
            encoding,
            evidence_out,
        } => {
            reject_oracle_output_collisions(
                &[
                    ("transition-spec input", &transition_spec),
                    ("metrics-tx-request input", &metrics_tx_request),
                    ("contract-source input", &contract_source),
                ],
                &[("preflight evidence output", &evidence_out)],
            )?;
            let spec = load_transition_spec(&transition_spec)?;
            let source = std::fs::read_to_string(&contract_source)?;
            let evidence =
                preflight_oracle_transition(&spec, &metrics_tx_request, &source, encoding.into())
                    .await?;
            write_public_json(&evidence_out, &evidence)?;
            println!("{}", serde_json::to_string_pretty(&evidence)?);
        }
        Command::ReportMetricsImportSignatures {
            transition_spec,
            metrics_tx_request,
            contract_source,
            signing_request,
            oracle_signature_hex_file,
            sponsor_signature_hex_file,
            verification_out,
        } => {
            let verification = import_oracle_signature_files(
                &transition_spec,
                &metrics_tx_request,
                &contract_source,
                &signing_request,
                &oracle_signature_hex_file,
                &sponsor_signature_hex_file,
                &verification_out,
            )?;
            println!("{}", serde_json::to_string_pretty(&verification)?);
        }
        Command::ReportMetricsBroadcast {
            transition_spec,
            metrics_tx_request,
            contract_source,
            signing_request,
            oracle_signature_hex_file,
            sponsor_signature_hex_file,
            acknowledge_signing_request_sha256,
            encoding,
            result_out,
        } => {
            let journal_path = broadcast_journal_path(&result_out);
            reject_oracle_output_collisions(
                &[
                    ("transition-spec input", &transition_spec),
                    ("metrics-tx-request input", &metrics_tx_request),
                    ("contract-source input", &contract_source),
                    ("signing-request input", &signing_request),
                    ("oracle-signature input", &oracle_signature_hex_file),
                    ("sponsor-signature input", &sponsor_signature_hex_file),
                ],
                &[
                    ("broadcast result output", &result_out),
                    ("broadcast journal output", &journal_path),
                ],
            )?;
            let (spec, signing_request, verified) = rebuild_verified_oracle_transition(
                &transition_spec,
                &metrics_tx_request,
                &contract_source,
                &signing_request,
                &oracle_signature_hex_file,
                &sponsor_signature_hex_file,
            )?;
            let expected_journal = prepare_oracle_broadcast_journal(
                &verified,
                &signing_request,
                &acknowledge_signing_request_sha256,
            )?;
            let _broadcast_lock = acquire_broadcast_lock(&result_out)?;
            let mut journal = if create_public_json(&journal_path, &expected_journal)? {
                expected_journal
            } else {
                load_oracle_broadcast_journal(&journal_path, &expected_journal)?
            };
            if let Some(recorded_result) = journal.result.as_ref() {
                if result_out.try_exists()? {
                    let existing_result = load_oracle_broadcast_result(&result_out, &journal)?;
                    if existing_result != *recorded_result {
                        anyhow::bail!("oracle result differs from finalized intent journal");
                    }
                } else {
                    write_public_json(&result_out, recorded_result)?;
                }
                println!("{}", serde_json::to_string_pretty(recorded_result)?);
                return Ok(());
            }
            if result_out.try_exists()? {
                let result = load_oracle_broadcast_result(&result_out, &journal)?;
                let journal = finalize_oracle_broadcast_journal(journal, result.clone())?;
                write_public_json(&journal_path, &journal)?;
                println!("{}", serde_json::to_string_pretty(&result)?);
                return Ok(());
            }
            let result = broadcast_verified_oracle_transition(
                verified,
                &signing_request,
                &spec,
                &acknowledge_signing_request_sha256,
                encoding.into(),
                &mut journal,
                &journal_path,
            )
            .await?;
            let journal = finalize_oracle_broadcast_journal(journal, result.clone())?;
            write_public_json(&journal_path, &journal)?;
            write_public_json(&result_out, &result)?;
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        Command::ReportMetricsObserve {
            transition_spec,
            metrics_tx_request,
            contract_source,
            signing_request,
            oracle_signature_hex_file,
            sponsor_signature_hex_file,
            encoding,
            evidence_out,
        } => {
            reject_oracle_output_collisions(
                &[
                    ("transition-spec input", &transition_spec),
                    ("metrics-tx-request input", &metrics_tx_request),
                    ("contract-source input", &contract_source),
                    ("signing-request input", &signing_request),
                    ("oracle-signature input", &oracle_signature_hex_file),
                    ("sponsor-signature input", &sponsor_signature_hex_file),
                ],
                &[("observation evidence output", &evidence_out)],
            )?;
            let (_, signing_request, verified) = rebuild_verified_oracle_transition(
                &transition_spec,
                &metrics_tx_request,
                &contract_source,
                &signing_request,
                &oracle_signature_hex_file,
                &sponsor_signature_hex_file,
            )?;
            let evidence =
                observe_oracle_successor(&verified, &signing_request, encoding.into()).await?;
            write_public_json(&evidence_out, &evidence)?;
            println!("{}", serde_json::to_string_pretty(&evidence)?);
        }
    }
    Ok(())
}

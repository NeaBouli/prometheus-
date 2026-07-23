#![cfg(unix)]

use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output, Stdio};

use ark_bn254::{Bn254, Fr};
use ark_groth16::Groth16;
use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_serialize::CanonicalSerialize;
use ark_snark::{CircuitSpecificSetupSNARK, SNARK};
use ark_std::rand::{rngs::StdRng, SeedableRng};
use prometheus_threat_hint::{ThreatHintEnvelope, ThreatIndicatorType, ThreatProofSystem};
use prometheus_threat_proof::{
    sha256_hex, statement_public_inputs, RelationManifest, ARKWORKS_VERSION, KIP16_STATUS_COMMIT,
    KIP16_TAG, PROOF_SYSTEM, PUBLIC_INPUT_COUNT, PUBLIC_INPUT_ENCODING,
    RELATION_MANIFEST_SCHEMA_VERSION, RUSTY_KASPA_COMMIT, RUSTY_KASPA_TAG, VERIFICATION_DOMAIN,
    VERIFYING_KEY_FILE,
};
use tempfile::TempDir;

#[derive(Clone)]
struct TestBindingCircuit {
    values: [Option<Fr>; 2],
}

impl ConstraintSynthesizer<Fr> for TestBindingCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        for value in self.values {
            let witness =
                cs.new_witness_variable(|| value.ok_or(SynthesisError::AssignmentMissing))?;
            let public =
                cs.new_input_variable(|| value.ok_or(SynthesisError::AssignmentMissing))?;
            cs.enforce_r1cs_constraint(
                || ark_relations::lc!() + witness,
                || ark_relations::lc!() + ark_relations::gr1cs::Variable::One,
                || ark_relations::lc!() + public,
            )?;
        }
        Ok(())
    }
}

struct Fixture {
    _directory: TempDir,
    manifest_path: std::path::PathBuf,
    manifest_sha256: String,
    wire: Vec<u8>,
}

fn base_envelope(proof: Vec<u8>) -> ThreatHintEnvelope {
    ThreatHintEnvelope::new(
        "11".repeat(32),
        8_501,
        ThreatIndicatorType::Behavior,
        ThreatProofSystem::Groth16Kip16V1,
        proof,
        "22".repeat(32),
        1_800_000_000,
    )
    .expect("valid test envelope")
}

fn fixture() -> Fixture {
    let directory = tempfile::tempdir().expect("tempdir");
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
        .expect("secure tempdir");

    let placeholder = base_envelope(vec![0]);
    let inputs = statement_public_inputs(&placeholder, "testnet-10").expect("statement inputs");
    let mut rng = StdRng::seed_from_u64(0x5052_4f4d_4554_4845);
    let (proving_key, verifying_key) = Groth16::<Bn254>::setup(
        TestBindingCircuit {
            values: [None, None],
        },
        &mut rng,
    )
    .expect("test setup");
    let proof = Groth16::<Bn254>::prove(
        &proving_key,
        TestBindingCircuit {
            values: [Some(inputs[0]), Some(inputs[1])],
        },
        &mut rng,
    )
    .expect("test proof");

    let mut proof_bytes = Vec::new();
    proof
        .serialize_compressed(&mut proof_bytes)
        .expect("serialize proof");
    let wire = base_envelope(proof_bytes)
        .to_canonical_bytes()
        .expect("canonical wire");

    let mut key_bytes = Vec::new();
    verifying_key
        .serialize_compressed(&mut key_bytes)
        .expect("serialize verifying key");
    let key_path = directory.path().join(VERIFYING_KEY_FILE);
    secure_write(&key_path, &key_bytes);

    let manifest = RelationManifest {
        schema_version: RELATION_MANIFEST_SCHEMA_VERSION,
        relation_id: "prometheus-test-binding-v1".to_string(),
        relation_source_sha256: sha256_hex(b"test-only binding relation source"),
        proof_system: PROOF_SYSTEM.to_string(),
        verification_domain: VERIFICATION_DOMAIN.to_string(),
        network_id: "testnet-10".to_string(),
        public_input_encoding: PUBLIC_INPUT_ENCODING.to_string(),
        public_input_count: PUBLIC_INPUT_COUNT,
        kip16_tag: KIP16_TAG,
        kip16_status_commit: KIP16_STATUS_COMMIT.to_string(),
        rusty_kaspa_tag: RUSTY_KASPA_TAG.to_string(),
        rusty_kaspa_commit: RUSTY_KASPA_COMMIT.to_string(),
        arkworks_version: ARKWORKS_VERSION.to_string(),
        verifying_key_file: VERIFYING_KEY_FILE.to_string(),
        verifying_key_bytes: key_bytes.len() as u64,
        verifying_key_sha256: sha256_hex(&key_bytes),
    };
    let manifest_bytes = manifest.to_canonical_bytes().expect("canonical manifest");
    let manifest_sha256 = sha256_hex(&manifest_bytes);
    let manifest_path = directory.path().join("relation-manifest.json");
    secure_write(&manifest_path, &manifest_bytes);
    let manifest_path = manifest_path
        .canonicalize()
        .expect("canonical manifest path");

    Fixture {
        _directory: directory,
        manifest_path,
        manifest_sha256,
        wire,
    }
}

fn secure_write(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).expect("write fixture");
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("secure fixture");
}

fn run(fixture: &Fixture, wire: &[u8], network: &str, expected_hash: &str) -> Output {
    run_with_stdin_policy(fixture, wire, network, expected_hash, false)
}

fn run_allowing_preflight_exit(
    fixture: &Fixture,
    wire: &[u8],
    network: &str,
    expected_hash: &str,
) -> Output {
    run_with_stdin_policy(fixture, wire, network, expected_hash, true)
}

fn run_with_stdin_policy(
    fixture: &Fixture,
    wire: &[u8],
    network: &str,
    expected_hash: &str,
    allow_preflight_exit: bool,
) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_prometheus-threat-proof"))
        .args([
            "verify",
            "--manifest",
            fixture.manifest_path.to_str().expect("utf8 manifest path"),
            "--expected-manifest-sha256",
            expected_hash,
            "--network-id",
            network,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn verifier");
    let write_result = child.stdin.take().expect("child stdin").write_all(wire);
    match write_result {
        Ok(()) => {}
        Err(error) if allow_preflight_exit && error.kind() == std::io::ErrorKind::BrokenPipe => {}
        Err(error) => panic!("write wire: {error}"),
    }
    child.wait_with_output().expect("wait for verifier")
}

fn assert_preflight_unavailable(output: Output) {
    assert_eq!(output.status.code(), Some(3));
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
}

#[test]
fn exact_proof_verifies_silently() {
    let fixture = fixture();
    let output = run(
        &fixture,
        &fixture.wire,
        "testnet-10",
        &fixture.manifest_sha256,
    );
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
}

#[test]
fn semantic_tamper_and_trailing_proof_fail_as_invalid() {
    let fixture = fixture();
    let parsed = ThreatHintEnvelope::parse_canonical(&fixture.wire).expect("parse fixture");
    let tampered = ThreatHintEnvelope::new(
        parsed.threat_hash(),
        parsed.confidence_bps() - 1,
        parsed.indicator_type(),
        parsed.proof_system(),
        parsed.proof_bytes().expect("proof bytes"),
        parsed.report_nonce(),
        parsed.observed_at(),
    )
    .expect("tampered envelope")
    .to_canonical_bytes()
    .expect("tampered wire");
    assert_eq!(
        run(&fixture, &tampered, "testnet-10", &fixture.manifest_sha256)
            .status
            .code(),
        Some(1)
    );

    let mut trailing = parsed.proof_bytes().expect("proof bytes");
    trailing.push(0);
    let trailing_wire = ThreatHintEnvelope::new(
        parsed.threat_hash(),
        parsed.confidence_bps(),
        parsed.indicator_type(),
        parsed.proof_system(),
        trailing,
        parsed.report_nonce(),
        parsed.observed_at(),
    )
    .expect("trailing envelope")
    .to_canonical_bytes()
    .expect("trailing wire");
    assert_eq!(
        run(
            &fixture,
            &trailing_wire,
            "testnet-10",
            &fixture.manifest_sha256
        )
        .status
        .code(),
        Some(1)
    );
}

#[test]
fn wrong_network_or_manifest_anchor_is_unavailable() {
    let fixture = fixture();
    assert_preflight_unavailable(run_allowing_preflight_exit(
        &fixture,
        &fixture.wire,
        "testnet-11",
        &fixture.manifest_sha256,
    ));
    assert_preflight_unavailable(run_allowing_preflight_exit(
        &fixture,
        &fixture.wire,
        "testnet-10",
        &"00".repeat(32),
    ));
}

#[test]
fn unsafe_manifest_mode_is_unavailable() {
    let fixture = fixture();
    fs::set_permissions(&fixture.manifest_path, fs::Permissions::from_mode(0o644))
        .expect("make manifest unsafe");
    assert_preflight_unavailable(run_allowing_preflight_exit(
        &fixture,
        &fixture.wire,
        "testnet-10",
        &fixture.manifest_sha256,
    ));
}

#[test]
fn placeholder_relation_source_anchor_is_unavailable() {
    let fixture = fixture();
    let bytes = fs::read(&fixture.manifest_path).expect("read manifest");
    let mut manifest: RelationManifest = serde_json::from_slice(&bytes).expect("parse manifest");
    manifest.relation_source_sha256 = "00".repeat(32);
    let placeholder = serde_json::to_vec(&manifest).expect("serialize placeholder manifest");
    secure_write(&fixture.manifest_path, &placeholder);
    assert_preflight_unavailable(run_allowing_preflight_exit(
        &fixture,
        &fixture.wire,
        "testnet-10",
        &sha256_hex(&placeholder),
    ));
}

#[test]
fn command_syntax_exit_is_distinct_from_unavailable() {
    let output = Command::new(env!("CARGO_BIN_EXE_prometheus-threat-proof"))
        .output()
        .expect("run verifier without command");
    assert_eq!(output.status.code(), Some(2));
}

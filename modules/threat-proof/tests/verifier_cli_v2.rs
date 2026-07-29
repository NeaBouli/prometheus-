//! Non-production integration tests for the `verify-v2` CLI subcommand and
//! the `TrustedGroth16V2Verifier` library type.
//!
//! All keys, proofs, manifests, and relation sources here are deterministic
//! seeded test-only fixtures generated in temporary directories; nothing in
//! this file is production material or production configuration.

#![cfg(unix)]

use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output, Stdio};

use ark_bn254::{Bn254, Fr};
use ark_ff::PrimeField;
use ark_groth16::Groth16;
use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_serialize::CanonicalSerialize;
use ark_snark::{CircuitSpecificSetupSNARK, SNARK};
use ark_std::rand::{rngs::StdRng, SeedableRng};
use prometheus_threat_hint::{
    ThreatHintV2Statement, MAX_CANONICAL_V2_PROOF_ENVELOPE_BYTES, THREAT_HINT_V2_PROTOCOL_ID,
    THREAT_HINT_V2_RELATION_ID,
};
use prometheus_threat_proof::relation_manifest_v2::{
    RelationManifestV2, RELATION_MANIFEST_V2_KIP16_TAG, RELATION_MANIFEST_V2_PROOF_SYSTEM,
    RELATION_MANIFEST_V2_PROTOCOL_ID, RELATION_MANIFEST_V2_PUBLIC_INPUT_COUNT,
    RELATION_MANIFEST_V2_PUBLIC_INPUT_ENCODING, RELATION_MANIFEST_V2_RELATION_ID,
    RELATION_MANIFEST_V2_STATEMENT_DIGEST_DOMAIN_HEX,
};
use prometheus_threat_proof::threat_hint_v2_groth16_verifier::RELATION_SOURCE_V2_FILE;
use prometheus_threat_proof::{
    sha256_hex, ARKWORKS_VERSION, KIP16_STATUS_COMMIT, RUSTY_KASPA_COMMIT, RUSTY_KASPA_TAG,
    VERIFYING_KEY_FILE,
};
use tempfile::TempDir;

const NETWORK: &str = "testnet-10";
const MANIFEST_FILE: &str = "relation-manifest-v2.json";
const STATEMENT_WIRE: &[u8] = br#"{"schema_version":2,"artifact_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","observable_commitment":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","confidence_bps":7500,"disclosure_class":"review_required_v1","report_nonce":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","observed_at":1700000000,"network_id":"testnet-10"}"#;
const RELATION_SOURCE: &[u8] = b"test-only v2 relation source fixture";

#[derive(Clone)]
struct TestBindingCircuit {
    values: Vec<Option<Fr>>,
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
    directory: TempDir,
    manifest_path: std::path::PathBuf,
    manifest_sha256: String,
    wire: Vec<u8>,
}

fn statement_digest(statement_wire: &[u8]) -> [u8; 32] {
    ThreatHintV2Statement::parse_canonical(statement_wire, NETWORK)
        .expect("valid test statement")
        .statement_digest()
        .expect("test digest")
}

fn envelope_wire(statement_wire: &[u8], proof: &[u8]) -> Vec<u8> {
    let digest = hex::encode(statement_digest(statement_wire));
    let statement_text = String::from_utf8(statement_wire.to_vec()).expect("ASCII statement");
    format!(
        "{{\"schema_version\":2,\"protocol_id\":\"{THREAT_HINT_V2_PROTOCOL_ID}\",\"relation_id\":\"{THREAT_HINT_V2_RELATION_ID}\",\"statement\":{},\"statement_digest\":\"{digest}\",\"proof\":\"{}\"}}",
        serde_json::to_string(&statement_text).expect("statement string"),
        hex::encode(proof)
    )
    .into_bytes()
}

fn manifest_wire(relation_source: &[u8], key_bytes: &[u8]) -> Vec<u8> {
    let protocol_id = RELATION_MANIFEST_V2_PROTOCOL_ID;
    let relation_id = RELATION_MANIFEST_V2_RELATION_ID;
    let domain_hex = RELATION_MANIFEST_V2_STATEMENT_DIGEST_DOMAIN_HEX;
    let proof_system = RELATION_MANIFEST_V2_PROOF_SYSTEM;
    let kip16_tag = RELATION_MANIFEST_V2_KIP16_TAG;
    let input_encoding = RELATION_MANIFEST_V2_PUBLIC_INPUT_ENCODING;
    let input_count = RELATION_MANIFEST_V2_PUBLIC_INPUT_COUNT;
    let network_id = NETWORK;
    let source_bytes = relation_source.len();
    let source_sha256 = sha256_hex(relation_source);
    let proving_key_bytes = 1_048_576_u64;
    let proving_key_sha256 = sha256_hex(b"test-only inert proving key anchor");
    let verifying_key_bytes = key_bytes.len();
    let verifying_key_sha256 = sha256_hex(key_bytes);
    let kip16_commit = KIP16_STATUS_COMMIT;
    let kaspa_tag = RUSTY_KASPA_TAG;
    let kaspa_commit = RUSTY_KASPA_COMMIT;
    let arkworks = ARKWORKS_VERSION;
    let wire = format!(
        "{{\"schema_version\":2,\"protocol_id\":\"{protocol_id}\",\"relation_id\":\"{relation_id}\",\"statement_digest_domain_hex\":\"{domain_hex}\",\"proof_system\":\"{proof_system}\",\"kip16_tag\":{kip16_tag},\"public_input_encoding\":\"{input_encoding}\",\"public_input_count\":{input_count},\"network_id\":\"{network_id}\",\"relation_source_bytes\":{source_bytes},\"relation_source_sha256\":\"{source_sha256}\",\"proving_key_bytes\":{proving_key_bytes},\"proving_key_sha256\":\"{proving_key_sha256}\",\"verifying_key_bytes\":{verifying_key_bytes},\"verifying_key_sha256\":\"{verifying_key_sha256}\",\"kip16_status_commit\":\"{kip16_commit}\",\"rusty_kaspa_tag\":\"{kaspa_tag}\",\"rusty_kaspa_commit\":\"{kaspa_commit}\",\"arkworks_version\":\"{arkworks}\"}}"
    )
    .into_bytes();
    RelationManifestV2::parse_canonical(&wire, NETWORK).expect("canonical test manifest");
    wire
}

fn setup_keys(input_count: usize) -> (ark_groth16::ProvingKey<Bn254>, Vec<u8>) {
    let mut rng = StdRng::seed_from_u64(0x5052_4f4d_2d76_3207);
    let (proving_key, verifying_key) = Groth16::<Bn254>::setup(
        TestBindingCircuit {
            values: vec![None; input_count],
        },
        &mut rng,
    )
    .expect("test setup");
    let mut key_bytes = Vec::new();
    verifying_key
        .serialize_compressed(&mut key_bytes)
        .expect("serialize verifying key");
    (proving_key, key_bytes)
}

fn fixture() -> Fixture {
    let directory = tempfile::tempdir().expect("tempdir");
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
        .expect("secure tempdir");

    let (proving_key, key_bytes) = setup_keys(2);
    let digest = statement_digest(STATEMENT_WIRE);
    let inputs = [
        Fr::from_be_bytes_mod_order(&digest[..16]),
        Fr::from_be_bytes_mod_order(&digest[16..]),
    ];
    let mut rng = StdRng::seed_from_u64(0x5052_4f4d_2d76_3208);
    let proof = Groth16::<Bn254>::prove(
        &proving_key,
        TestBindingCircuit {
            values: vec![Some(inputs[0]), Some(inputs[1])],
        },
        &mut rng,
    )
    .expect("test proof");
    let mut proof_bytes = Vec::new();
    proof
        .serialize_compressed(&mut proof_bytes)
        .expect("serialize proof");
    let wire = envelope_wire(STATEMENT_WIRE, &proof_bytes);

    secure_write(
        &directory.path().join(RELATION_SOURCE_V2_FILE),
        RELATION_SOURCE,
    );
    secure_write(&directory.path().join(VERIFYING_KEY_FILE), &key_bytes);

    let manifest_bytes = manifest_wire(RELATION_SOURCE, &key_bytes);
    let manifest_sha256 = sha256_hex(&manifest_bytes);
    secure_write(&directory.path().join(MANIFEST_FILE), &manifest_bytes);
    let manifest_path = directory
        .path()
        .join(MANIFEST_FILE)
        .canonicalize()
        .expect("canonical manifest path");

    Fixture {
        directory,
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
            "verify-v2",
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

fn assert_valid_silently(output: Output) {
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
}

fn assert_invalid_silently(output: Output) {
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
}

fn assert_unavailable_silently(output: Output) {
    assert_eq!(output.status.code(), Some(3));
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
}

#[test]
fn exact_proof_verifies_silently_without_proving_key_file() {
    let fixture = fixture();
    assert!(!fixture.directory.path().join("proving-key.bin").exists());
    assert_valid_silently(run(
        &fixture,
        &fixture.wire,
        NETWORK,
        &fixture.manifest_sha256,
    ));
}

#[test]
fn semantic_statement_tamper_is_invalid() {
    let fixture = fixture();
    let parsed =
        prometheus_threat_hint::ThreatHintV2ProofEnvelope::parse_canonical(&fixture.wire, NETWORK)
            .expect("parse fixture wire");
    let tampered_statement = String::from_utf8(STATEMENT_WIRE.to_vec())
        .expect("ASCII")
        .replace("7500", "7501");
    let tampered_wire = envelope_wire(
        tampered_statement.as_bytes(),
        &parsed.proof_bytes().expect("proof bytes"),
    );
    assert_invalid_silently(run(
        &fixture,
        &tampered_wire,
        NETWORK,
        &fixture.manifest_sha256,
    ));
}

#[test]
fn proof_mismatch_is_invalid() {
    let fixture = fixture();
    let (proving_key, _) = setup_keys(2);
    let digest = statement_digest(STATEMENT_WIRE);
    let wrong_inputs = [
        Fr::from_be_bytes_mod_order(&digest[..16]) + Fr::from(1u64),
        Fr::from_be_bytes_mod_order(&digest[16..]),
    ];
    let mut rng = StdRng::seed_from_u64(0x5052_4f4d_2d76_3209);
    let proof = Groth16::<Bn254>::prove(
        &proving_key,
        TestBindingCircuit {
            values: vec![Some(wrong_inputs[0]), Some(wrong_inputs[1])],
        },
        &mut rng,
    )
    .expect("mismatched proof");
    let mut proof_bytes = Vec::new();
    proof
        .serialize_compressed(&mut proof_bytes)
        .expect("serialize proof");
    let mismatched_wire = envelope_wire(STATEMENT_WIRE, &proof_bytes);
    assert_invalid_silently(run(
        &fixture,
        &mismatched_wire,
        NETWORK,
        &fixture.manifest_sha256,
    ));
}

#[test]
fn trailing_proof_bytes_are_invalid() {
    let fixture = fixture();
    let parsed =
        prometheus_threat_hint::ThreatHintV2ProofEnvelope::parse_canonical(&fixture.wire, NETWORK)
            .expect("parse fixture wire");
    let mut trailing = parsed.proof_bytes().expect("proof bytes");
    trailing.push(0);
    let trailing_wire = envelope_wire(STATEMENT_WIRE, &trailing);
    assert_invalid_silently(run(
        &fixture,
        &trailing_wire,
        NETWORK,
        &fixture.manifest_sha256,
    ));
}

#[test]
fn malformed_canonical_length_proof_is_invalid() {
    let fixture = fixture();
    let malformed_wire = envelope_wire(STATEMENT_WIRE, &[0xff; 128]);
    assert_invalid_silently(run(
        &fixture,
        &malformed_wire,
        NETWORK,
        &fixture.manifest_sha256,
    ));
}

#[test]
fn empty_and_oversized_stdin_are_invalid() {
    let fixture = fixture();
    assert_invalid_silently(run(&fixture, b"", NETWORK, &fixture.manifest_sha256));
    let oversized = vec![b'x'; MAX_CANONICAL_V2_PROOF_ENVELOPE_BYTES + 1];
    assert_invalid_silently(run(&fixture, &oversized, NETWORK, &fixture.manifest_sha256));
}

#[test]
fn wrong_network_or_manifest_anchor_is_unavailable() {
    let fixture = fixture();
    assert_unavailable_silently(run_allowing_preflight_exit(
        &fixture,
        &fixture.wire,
        "testnet-11",
        &fixture.manifest_sha256,
    ));
    assert_unavailable_silently(run_allowing_preflight_exit(
        &fixture,
        &fixture.wire,
        NETWORK,
        &sha256_hex(b"test-only wrong manifest anchor"),
    ));
    assert_unavailable_silently(run_allowing_preflight_exit(
        &fixture,
        &fixture.wire,
        NETWORK,
        &fixture.manifest_sha256.to_uppercase(),
    ));
    assert_unavailable_silently(run_allowing_preflight_exit(
        &fixture,
        &fixture.wire,
        NETWORK,
        &"0".repeat(64),
    ));
}

#[test]
fn unsafe_manifest_mode_is_unavailable() {
    let fixture = fixture();
    fs::set_permissions(&fixture.manifest_path, fs::Permissions::from_mode(0o644))
        .expect("make manifest unsafe");
    assert_unavailable_silently(run_allowing_preflight_exit(
        &fixture,
        &fixture.wire,
        NETWORK,
        &fixture.manifest_sha256,
    ));
}

#[test]
fn unsafe_manifest_directory_mode_is_unavailable() {
    let fixture = fixture();
    fs::set_permissions(fixture.directory.path(), fs::Permissions::from_mode(0o755))
        .expect("make manifest directory unsafe");
    assert_unavailable_silently(run_allowing_preflight_exit(
        &fixture,
        &fixture.wire,
        NETWORK,
        &fixture.manifest_sha256,
    ));
}

#[test]
fn missing_tampered_or_unsafe_relation_source_is_unavailable() {
    let missing = fixture();
    fs::remove_file(missing.directory.path().join(RELATION_SOURCE_V2_FILE))
        .expect("remove relation source");
    assert_unavailable_silently(run_allowing_preflight_exit(
        &missing,
        &missing.wire,
        NETWORK,
        &missing.manifest_sha256,
    ));

    let tampered = fixture();
    secure_write(
        &tampered.directory.path().join(RELATION_SOURCE_V2_FILE),
        b"test-only tampered relation source",
    );
    assert_unavailable_silently(run_allowing_preflight_exit(
        &tampered,
        &tampered.wire,
        NETWORK,
        &tampered.manifest_sha256,
    ));

    let unsafe_mode = fixture();
    fs::set_permissions(
        unsafe_mode.directory.path().join(RELATION_SOURCE_V2_FILE),
        fs::Permissions::from_mode(0o644),
    )
    .expect("make relation source unsafe");
    assert_unavailable_silently(run_allowing_preflight_exit(
        &unsafe_mode,
        &unsafe_mode.wire,
        NETWORK,
        &unsafe_mode.manifest_sha256,
    ));
}

#[test]
fn missing_tampered_or_unsafe_verifying_key_is_unavailable() {
    let missing = fixture();
    fs::remove_file(missing.directory.path().join(VERIFYING_KEY_FILE))
        .expect("remove verifying key");
    assert_unavailable_silently(run_allowing_preflight_exit(
        &missing,
        &missing.wire,
        NETWORK,
        &missing.manifest_sha256,
    ));

    let tampered = fixture();
    secure_write(
        &tampered.directory.path().join(VERIFYING_KEY_FILE),
        b"test-only tampered verifying key",
    );
    assert_unavailable_silently(run_allowing_preflight_exit(
        &tampered,
        &tampered.wire,
        NETWORK,
        &tampered.manifest_sha256,
    ));

    let unsafe_mode = fixture();
    fs::set_permissions(
        unsafe_mode.directory.path().join(VERIFYING_KEY_FILE),
        fs::Permissions::from_mode(0o644),
    )
    .expect("make verifying key unsafe");
    assert_unavailable_silently(run_allowing_preflight_exit(
        &unsafe_mode,
        &unsafe_mode.wire,
        NETWORK,
        &unsafe_mode.manifest_sha256,
    ));
}

#[test]
fn anchor_matched_invalid_verifying_key_is_unavailable() {
    let directory = tempfile::tempdir().expect("tempdir");
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
        .expect("secure tempdir");
    let invalid_key_bytes = vec![0xff; 128];
    secure_write(
        &directory.path().join(RELATION_SOURCE_V2_FILE),
        RELATION_SOURCE,
    );
    secure_write(
        &directory.path().join(VERIFYING_KEY_FILE),
        &invalid_key_bytes,
    );
    let manifest_bytes = manifest_wire(RELATION_SOURCE, &invalid_key_bytes);
    let manifest_sha256 = sha256_hex(&manifest_bytes);
    secure_write(&directory.path().join(MANIFEST_FILE), &manifest_bytes);
    let manifest_path = directory
        .path()
        .join(MANIFEST_FILE)
        .canonicalize()
        .expect("canonical manifest path");
    let fixture = Fixture {
        directory,
        manifest_path,
        manifest_sha256,
        wire: envelope_wire(STATEMENT_WIRE, &[0xaa; 16]),
    };
    assert_unavailable_silently(run_allowing_preflight_exit(
        &fixture,
        &fixture.wire,
        NETWORK,
        &fixture.manifest_sha256,
    ));
}

#[test]
fn wrong_verifying_key_input_count_is_unavailable() {
    let directory = tempfile::tempdir().expect("tempdir");
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
        .expect("secure tempdir");
    let (_, key_bytes) = setup_keys(1);
    secure_write(
        &directory.path().join(RELATION_SOURCE_V2_FILE),
        RELATION_SOURCE,
    );
    secure_write(&directory.path().join(VERIFYING_KEY_FILE), &key_bytes);
    let manifest_bytes = manifest_wire(RELATION_SOURCE, &key_bytes);
    let manifest_sha256 = sha256_hex(&manifest_bytes);
    secure_write(&directory.path().join(MANIFEST_FILE), &manifest_bytes);
    let manifest_path = directory
        .path()
        .join(MANIFEST_FILE)
        .canonicalize()
        .expect("canonical manifest path");
    let wire = envelope_wire(STATEMENT_WIRE, &[0xaa; 16]);
    let fixture = Fixture {
        directory,
        manifest_path,
        manifest_sha256,
        wire,
    };
    assert_unavailable_silently(run_allowing_preflight_exit(
        &fixture,
        &fixture.wire,
        NETWORK,
        &fixture.manifest_sha256,
    ));
}

#[test]
fn symlink_or_noncanonical_manifest_path_is_unavailable() {
    let fixture = fixture();
    let link_path = fixture.directory.path().join("manifest-link.json");
    std::os::unix::fs::symlink(&fixture.manifest_path, &link_path).expect("symlink manifest");
    let linked = Fixture {
        directory: tempfile::tempdir().expect("placeholder tempdir"),
        manifest_path: link_path,
        manifest_sha256: fixture.manifest_sha256.clone(),
        wire: fixture.wire.clone(),
    };
    assert_unavailable_silently(run_allowing_preflight_exit(
        &linked,
        &linked.wire,
        NETWORK,
        &linked.manifest_sha256,
    ));

    let noncanonical = fixture
        .manifest_path
        .parent()
        .expect("manifest directory")
        .join("sub")
        .join("..")
        .join(MANIFEST_FILE);
    let noncanonical_fixture = Fixture {
        directory: tempfile::tempdir().expect("placeholder tempdir"),
        manifest_path: noncanonical,
        manifest_sha256: fixture.manifest_sha256.clone(),
        wire: fixture.wire.clone(),
    };
    assert_unavailable_silently(run_allowing_preflight_exit(
        &noncanonical_fixture,
        &noncanonical_fixture.wire,
        NETWORK,
        &noncanonical_fixture.manifest_sha256,
    ));
}

#[test]
fn command_syntax_exit_is_distinct_from_unavailable() {
    let output = Command::new(env!("CARGO_BIN_EXE_prometheus-threat-proof"))
        .arg("verify-v2")
        .output()
        .expect("run verifier without flags");
    assert_eq!(output.status.code(), Some(2));
}

#[test]
fn big_endian_halves_embed_into_fr_without_reduction() {
    // The BN254 scalar-field modulus exceeds 2^128, so every 16-byte
    // big-endian statement-digest half embeds into Fr without reduction.
    for half in [[0x00u8; 16], [0x01u8; 16], [0x7fu8; 16], [0xffu8; 16]] {
        assert_eq!(
            Fr::from_be_bytes_mod_order(&half),
            Fr::from(u128::from_be_bytes(half))
        );
    }
    let digest = statement_digest(STATEMENT_WIRE);
    assert_eq!(
        Fr::from_be_bytes_mod_order(&digest[..16]),
        Fr::from(u128::from_be_bytes(
            digest[..16].try_into().expect("first half")
        ))
    );
    assert_eq!(
        Fr::from_be_bytes_mod_order(&digest[16..]),
        Fr::from(u128::from_be_bytes(
            digest[16..].try_into().expect("second half")
        ))
    );
}

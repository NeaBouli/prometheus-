//! Adversarial tests for the GH-213 Development/Testnet-10 CLI boundary.

use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use prometheus_client::blockchain::rule_signed_snapshot::{
    RuleSnapshotEnvelopeError, RuleSnapshotTimeSource, MAX_ENVELOPE_BYTES,
};
use prometheus_client::rule_sync_cli::{RuleSyncCliError, RuleSyncConfig};
use prometheus_client::runtime::RuntimeMode;
use secp256k1::{Keypair, Message, Secp256k1, SecretKey};
use serde::Serialize;
use sha2::{Digest, Sha256};
use tempfile::TempDir;

const NOW: u64 = 1_700_000_000;
const SIGNING_DOMAIN: &[u8] = b"prometheus.rule-snapshot.envelope.v1\0";

#[derive(Serialize)]
struct Payload {
    schema_version: u64,
    kind: &'static str,
    network_id: &'static str,
    sequence: u64,
    valid_from: u64,
    valid_until: u64,
    empty_snapshot_order: Option<u64>,
    entries: Vec<serde_json::Value>,
}

struct FixedClock;

impl RuleSnapshotTimeSource for FixedClock {
    fn current_unix_seconds(&self) -> Result<u64, RuleSnapshotEnvelopeError> {
        Ok(NOW)
    }
}

fn secret() -> SecretKey {
    SecretKey::from_slice(&[0x42; 32]).unwrap()
}

fn public_key_hex() -> String {
    let secp = Secp256k1::new();
    let keypair = Keypair::from_secret_key(&secp, &secret());
    hex::encode(keypair.x_only_public_key().0.serialize())
}

fn signed_envelope_for(now: u64) -> Vec<u8> {
    let payload = Payload {
        schema_version: 1,
        kind: "prometheus.rule-snapshot.envelope.v1",
        network_id: "testnet-10",
        sequence: 7,
        valid_from: now - 300,
        valid_until: now + 300,
        empty_snapshot_order: Some(9),
        entries: Vec::new(),
    };
    let mut bytes = serde_json::to_vec(&payload).unwrap();
    let mut hasher = Sha256::new();
    hasher.update(SIGNING_DOMAIN);
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(&bytes);
    let message = Message::from_digest(hasher.finalize().into());
    let secp = Secp256k1::new();
    let keypair = Keypair::from_secret_key(&secp, &secret());
    let signature = secp.sign_schnorr_no_aux_rand(&message, &keypair);
    assert_eq!(bytes.pop(), Some(b'}'));
    bytes.extend_from_slice(
        format!(",\"signature\":\"{}\"}}", hex::encode(signature.as_ref())).as_bytes(),
    );
    bytes
}

fn signed_envelope() -> Vec<u8> {
    signed_envelope_for(NOW)
}

fn write_private(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

fn paths(temp: &TempDir) -> (PathBuf, PathBuf, PathBuf) {
    (
        temp.path().join("config.toml"),
        temp.path().join("snapshot.json"),
        temp.path().join("checkpoint"),
    )
}

fn valid_toml(envelope: &Path, checkpoint: &Path) -> String {
    format!(
        r#"enabled = true
network = "testnet10"
owner_xonly_public_key = "{}"
minimum_sequence = 1
signed_envelope_path = "{}"
rpc_url = "ws://127.0.0.1:17210"
ipfs_gateway_url = "http://127.0.0.1:8080/ipfs/"
checkpoint_dir = "{}"
success_interval_secs = 60
initial_failure_backoff_ms = 500
max_failure_backoff_ms = 30000
attempt_timeout_ms = 10000
"#,
        public_key_hex(),
        envelope.display(),
        checkpoint.display()
    )
}

fn load(
    temp: &TempDir,
    transform: impl FnOnce(String) -> String,
) -> Result<RuleSyncConfig, RuleSyncCliError> {
    let (config, envelope, checkpoint) = paths(temp);
    write_private(&envelope, &signed_envelope());
    write_private(
        &config,
        transform(valid_toml(&envelope, &checkpoint)).as_bytes(),
    );
    RuleSyncConfig::from_toml_file(&config)
}

#[test]
fn offline_preflight_verifies_without_checkpoint_mutation() {
    let temp = TempDir::new().unwrap();
    let (_, _, checkpoint) = paths(&temp);
    fs::create_dir(&checkpoint).unwrap();
    fs::set_permissions(&checkpoint, fs::Permissions::from_mode(0o700)).unwrap();
    let validated = load(&temp, |value| value)
        .unwrap()
        .validate(RuntimeMode::Development)
        .unwrap();

    let report = validated.offline_preflight(Arc::new(FixedClock)).unwrap();
    assert_eq!(report.status, "ready-for-development-rule-sync");
    assert_eq!(report.envelope, "verified");
    assert_eq!(report.checkpoint, "deferred-to-run");
    assert_eq!(fs::read_dir(&checkpoint).unwrap().count(), 0);
    assert!(validated.create_connection().is_ok());
    assert!(validated.create_content_source().is_ok());
    assert!(validated.create_coordinator().is_ok());
    assert!(validated.open_checkpoint_store().is_ok());
}

#[test]
fn rejects_unknown_and_secret_shaped_fields() {
    for extra in [
        "private_key = \"do-not-accept\"\n",
        "wallet = \"do-not-accept\"\n",
        "seed = \"do-not-accept\"\n",
        "unknown = true\n",
    ] {
        let temp = TempDir::new().unwrap();
        let result = load(&temp, |mut value| {
            value.push_str(extra);
            value
        });
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            RuleSyncCliError.to_string()
        );
    }
}

#[test]
fn rejects_non_development_key_sequence_and_timing_profiles() {
    let temp = TempDir::new().unwrap();
    let config = load(&temp, |value| value).unwrap();
    assert!(config.validate(RuntimeMode::Beta).is_err());
    assert!(config.validate(RuntimeMode::Mainnet).is_err());

    for (needle, replacement) in [
        ("minimum_sequence = 1", "minimum_sequence = 0"),
        (
            &format!("owner_xonly_public_key = \"{}\"", public_key_hex()),
            "owner_xonly_public_key = \"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\"",
        ),
        ("success_interval_secs = 60", "success_interval_secs = 0"),
        ("attempt_timeout_ms = 10000", "attempt_timeout_ms = 99"),
        (
            "initial_failure_backoff_ms = 500",
            "initial_failure_backoff_ms = 31000",
        ),
    ] {
        let temp = TempDir::new().unwrap();
        let config = load(&temp, |value| value.replace(needle, replacement)).unwrap();
        assert!(config.validate(RuntimeMode::Development).is_err());
    }
}

#[test]
fn rejects_remote_credentialed_and_malformed_endpoints() {
    for (needle, replacement) in [
        ("ws://127.0.0.1:17210", "ws://user:password@127.0.0.1:17210"),
        ("ws://127.0.0.1:17210", "ws://public.example:17210"),
        ("ws://127.0.0.1:17210", "http://127.0.0.1:17210"),
        ("http://127.0.0.1:8080/ipfs/", "http://localhost:8080/ipfs/"),
        (
            "http://127.0.0.1:8080/ipfs/",
            "https://127.0.0.1:8080/ipfs/",
        ),
        (
            "http://127.0.0.1:8080/ipfs/",
            "http://127.0.0.1:8080/other/",
        ),
    ] {
        let temp = TempDir::new().unwrap();
        let config = load(&temp, |value| value.replace(needle, replacement)).unwrap();
        assert!(config.validate(RuntimeMode::Development).is_err());
    }
}

#[test]
fn rejects_unsafe_config_and_envelope_files() {
    let temp = TempDir::new().unwrap();
    let (config_path, envelope, checkpoint) = paths(&temp);
    write_private(&envelope, &signed_envelope());
    write_private(&config_path, valid_toml(&envelope, &checkpoint).as_bytes());

    fs::set_permissions(&config_path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(RuleSyncConfig::from_toml_file(&config_path).is_err());
    fs::set_permissions(&config_path, fs::Permissions::from_mode(0o600)).unwrap();

    fs::set_permissions(&envelope, fs::Permissions::from_mode(0o644)).unwrap();
    let validated = RuleSyncConfig::from_toml_file(&config_path)
        .unwrap()
        .validate(RuntimeMode::Development)
        .unwrap();
    assert!(validated.offline_preflight(Arc::new(FixedClock)).is_err());

    fs::remove_file(&envelope).unwrap();
    let target = temp.path().join("target.json");
    write_private(&target, &signed_envelope());
    symlink(&target, &envelope).unwrap();
    assert!(validated.offline_preflight(Arc::new(FixedClock)).is_err());

    fs::remove_file(&envelope).unwrap();
    fs::hard_link(&target, &envelope).unwrap();
    assert!(validated.offline_preflight(Arc::new(FixedClock)).is_err());
}

#[test]
fn rejects_oversized_non_ascii_and_empty_inputs() {
    let temp = TempDir::new().unwrap();
    let (config, envelope, checkpoint) = paths(&temp);
    write_private(&config, &[0xff]);
    assert!(RuleSyncConfig::from_toml_file(&config).is_err());

    write_private(&config, &vec![b'x'; 64 * 1024 + 1]);
    assert!(RuleSyncConfig::from_toml_file(&config).is_err());

    write_private(&config, valid_toml(&envelope, &checkpoint).as_bytes());
    write_private(&envelope, &vec![b'x'; MAX_ENVELOPE_BYTES + 1]);
    let validated = RuleSyncConfig::from_toml_file(&config)
        .unwrap()
        .validate(RuntimeMode::Development)
        .unwrap();
    assert!(validated.offline_preflight(Arc::new(FixedClock)).is_err());

    write_private(&envelope, b"");
    assert!(validated.offline_preflight(Arc::new(FixedClock)).is_err());
}

#[test]
fn debug_and_errors_are_redacted() {
    let temp = TempDir::new().unwrap();
    let (_, envelope, _) = paths(&temp);
    let key = public_key_hex();
    let config = load(&temp, |value| value).unwrap();
    let validated = config.validate(RuntimeMode::Development).unwrap();

    for output in [format!("{config:?}"), format!("{validated:?}")] {
        assert!(!output.contains(&key));
        assert!(!output.contains(&envelope.display().to_string()));
        assert!(!output.contains("127.0.0.1"));
    }
    assert_eq!(
        RuleSyncCliError.to_string(),
        "RuleStorage sync CLI configuration rejected"
    );
}

#[test]
fn example_config_is_strict_and_statically_valid() {
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("rule-sync.example.toml");
    let temp = TempDir::new().unwrap();
    let private = temp.path().join("example.toml");
    write_private(&private, &fs::read(source).unwrap());
    assert!(RuleSyncConfig::from_toml_file(&private)
        .unwrap()
        .validate(RuntimeMode::Development)
        .is_ok());
}

#[test]
fn binary_preflight_is_offline_redacted_and_non_mutating() {
    let temp = TempDir::new().unwrap();
    let (config, envelope, checkpoint) = paths(&temp);
    fs::create_dir(&checkpoint).unwrap();
    fs::set_permissions(&checkpoint, fs::Permissions::from_mode(0o700)).unwrap();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    write_private(&envelope, &signed_envelope_for(now));
    write_private(&config, valid_toml(&envelope, &checkpoint).as_bytes());

    let output = Command::new(env!("CARGO_BIN_EXE_prometheus-client"))
        .args(["rule-sync", "preflight", "--config"])
        .arg(&config)
        .env("PROMETHEUS_RUNTIME", "development")
        .output()
        .unwrap();
    assert!(output.status.success(), "{:?}", output);
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("ready-for-development-rule-sync"));
    assert!(stdout.contains("\"checkpoint\": \"deferred-to-run\""));
    assert!(!stdout.contains(&public_key_hex()));
    assert!(!stdout.contains(&envelope.display().to_string()));
    assert!(!stdout.contains("127.0.0.1"));
    assert_eq!(fs::read_dir(&checkpoint).unwrap().count(), 0);
}

#[test]
fn binary_failures_are_redacted_and_runtime_modes_fail_closed() {
    let temp = TempDir::new().unwrap();
    let (config, envelope, checkpoint) = paths(&temp);
    write_private(&envelope, &signed_envelope());
    let secret_marker = "private-value-must-not-escape";
    let invalid = format!(
        "{}private_key = \"{secret_marker}\"\n",
        valid_toml(&envelope, &checkpoint)
    );
    write_private(&config, invalid.as_bytes());
    let output = Command::new(env!("CARGO_BIN_EXE_prometheus-client"))
        .args(["rule-sync", "preflight", "--config"])
        .arg(&config)
        .env("PROMETHEUS_RUNTIME", "development")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(!stderr.contains(secret_marker));
    assert!(!stderr.contains(&config.display().to_string()));
    assert!(!stderr.contains(&envelope.display().to_string()));

    write_private(&config, valid_toml(&envelope, &checkpoint).as_bytes());
    for mode in ["beta", "mainnet"] {
        let output = Command::new(env!("CARGO_BIN_EXE_prometheus-client"))
            .args(["rule-sync", "preflight", "--config"])
            .arg(&config)
            .env("PROMETHEUS_RUNTIME", mode)
            .output()
            .unwrap();
        assert!(!output.status.success());
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert_eq!(
            stderr
                .matches("RuleStorage sync CLI configuration rejected")
                .count(),
            1
        );
        assert!(!stderr.contains(&config.display().to_string()));
    }
}

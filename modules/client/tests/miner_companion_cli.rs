use std::fs;
use std::process::Command;

use tempfile::TempDir;

fn write_config(contents: &str) -> (TempDir, std::path::PathBuf) {
    let directory = TempDir::new().unwrap();
    let path = directory.path().join("miner-companion.toml");
    fs::write(&path, contents).unwrap();
    (directory, path)
}

#[test]
fn preflight_accepts_safe_local_profile_without_network_activity() {
    let (_directory, path) = write_config(
        r#"
enabled = true
role = "light"
network = "testnet10"
rpc_url = "ws://127.0.0.1:17210"
poll_interval_secs = 30

[features]
scanning = false
reporting = false
"#,
    );

    let output = Command::new(env!("CARGO_BIN_EXE_prometheus-client"))
        .args(["miner-companion", "preflight", "--config"])
        .arg(path)
        .env("PROMETHEUS_RUNTIME", "development")
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("ready-for-development-rpc-observer"));
    assert!(stdout.contains("not-implemented"));
    assert!(!stdout.contains("127.0.0.1"));
}

#[test]
fn preflight_fails_closed_for_mainnet_and_unsupported_features() {
    let (_directory, path) = write_config(
        r#"
enabled = true
role = "light"
network = "testnet10"
rpc_url = "ws://127.0.0.1:17210"

[features]
scanning = true
reporting = false
"#,
    );

    let output = Command::new(env!("CARGO_BIN_EXE_prometheus-client"))
        .args(["miner-companion", "preflight", "--config"])
        .arg(path)
        .env("PROMETHEUS_RUNTIME", "mainnet")
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("cannot run in beta or mainnet mode"));
    assert!(!stderr.contains("127.0.0.1"));
}

#[test]
fn missing_config_failure_does_not_echo_the_local_path() {
    let directory = TempDir::new().unwrap();
    let marker = "local-path-marker";
    let path = directory.path().join(marker);

    let output = Command::new(env!("CARGO_BIN_EXE_prometheus-client"))
        .args(["miner-companion", "preflight", "--config"])
        .arg(path)
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("failed to read companion config"));
    assert!(!stderr.contains(marker));
}

#[test]
fn failed_connect_does_not_echo_the_configured_endpoint() {
    let (_directory, path) = write_config(
        r#"
enabled = true
role = "light"
network = "testnet10"
rpc_url = "ws://127.0.0.1:1"
poll_interval_secs = 30
"#,
    );

    let output = Command::new(env!("CARGO_BIN_EXE_prometheus-client"))
        .args([
            "miner-companion",
            "preflight",
            "--config",
            path.to_str().unwrap(),
            "--connect",
        ])
        .env("PROMETHEUS_RUNTIME", "development")
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("Failed to connect to Kaspa node"));
    assert!(!stderr.contains("127.0.0.1"));
    assert!(!stderr.contains(":1"));
}

#[test]
fn no_args_preserves_the_existing_successful_fallback() {
    let output = Command::new(env!("CARGO_BIN_EXE_prometheus-client"))
        .output()
        .unwrap();

    assert!(output.status.success());
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
}

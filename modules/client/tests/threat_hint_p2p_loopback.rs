//! Binary-level Development-only evidence for the GH-226 v1 ThreatHint sender.
//!
//! The real `prometheus-client` binary drives the real Guardian libp2p stack
//! over literal QUIC loopback into an owner-only mock verifier boundary. Every
//! peer is an ephemeral loopback fixture. This is not public Testnet or
//! production evidence; the acknowledgement only reports a remote
//! local-boundary outcome, and no fixture value may appear in process output.

#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use prometheus_guardian_p2p::ingress::UnixBallotIngress;
use prometheus_guardian_p2p::threat_hint_ingress::UnixThreatHintIngress;
use prometheus_guardian_p2p::threat_hint_v2_ingress::UnixThreatHintV2Ingress;
use prometheus_guardian_p2p::transport_identity::load_or_create_transport_identity;
use prometheus_guardian_p2p::{GuardianP2p, GuardianP2pConfig, TransportError, TransportEvent};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixListener;
use tokio::process::Command;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tokio::time::timeout;

const VALID_HINT: &[u8] = br#"{"schema_version":1,"threat_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","confidence_bps":9000,"indicator_type":"file_hash","proof_system":"groth16_kip16_v1","proof":"010203","report_nonce":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","observed_at":1}"#;

struct Fixture {
    _temp: TempDir,
    guardian_dir: PathBuf,
    verifier_dir: PathBuf,
    verifier_socket: PathBuf,
    config_path: PathBuf,
    hint_path: PathBuf,
    identity_path: PathBuf,
}

fn owner_only_dir(path: &Path) {
    fs::create_dir(path).expect("create fixture directory");
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("owner-only directory");
}

fn write_private(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).expect("write fixture");
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("owner-only fixture");
}

fn fixture() -> Fixture {
    let temp = TempDir::new().expect("temporary directory");
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700))
        .expect("owner-only root directory");
    let guardian_dir = temp.path().join("guardian");
    let client_dir = temp.path().join("client");
    let verifier_dir = temp.path().join("verifier");
    owner_only_dir(&guardian_dir);
    owner_only_dir(&client_dir);
    owner_only_dir(&verifier_dir);
    Fixture {
        config_path: client_dir.join("threat-hint.toml"),
        hint_path: client_dir.join("hint.json"),
        identity_path: client_dir.join("client.identity"),
        verifier_socket: verifier_dir.join("threat-hint.sock"),
        _temp: temp,
        guardian_dir,
        verifier_dir,
    }
}

fn write_config(fixture: &Fixture, peer: &str, route: &str, timeout_secs: u64) {
    let text = format!(
        "enabled = true\nnetwork = \"testnet10\"\nguardian_peer_id = \"{peer}\"\nguardian_address = \"{route}\"\nidentity_path = \"{}\"\nsubmission_timeout_secs = {timeout_secs}\n",
        fixture.identity_path.display()
    );
    write_private(&fixture.config_path, text.as_bytes());
}

async fn start_guardian(fixture: &Fixture) -> (GuardianP2p, String, String) {
    let keypair =
        load_or_create_transport_identity(&fixture.guardian_dir.join("guardian.identity"))
            .expect("guardian identity");
    let peer_text = keypair.public().to_peer_id().to_string();
    let mut config = GuardianP2pConfig::default();
    config.listen_addresses.push(
        "/ip4/127.0.0.1/udp/0/quic-v1"
            .parse()
            .expect("loopback listen"),
    );
    config.request_timeout = Duration::from_secs(5);
    let mut node = GuardianP2p::new(keypair, config).expect("guardian initializes");
    let address = match timeout(Duration::from_secs(10), node.next_event())
        .await
        .expect("guardian listener readiness")
    {
        TransportEvent::Listening { address } => address,
        event => panic!("expected guardian listener address, got {event:?}"),
    };
    let route = format!("{address}/p2p/{peer_text}");
    (node, route, peer_text)
}

async fn bind_verifier(path: &Path) -> Arc<UnixListener> {
    let listener = UnixListener::bind(path).expect("bind mock verifier");
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("owner-only verifier");
    Arc::new(listener)
}

async fn serve_once(listener: Arc<UnixListener>, expected: Vec<u8>, status: &'static str) {
    let (mut stream, _) = listener.accept().await.expect("accept ThreatHint carrier");
    let length = stream.read_u32().await.expect("read hint length") as usize;
    let mut received = vec![0_u8; length];
    stream
        .read_exact(&mut received)
        .await
        .expect("read exact hint");
    assert_eq!(received, expected, "exact canonical hint bytes");
    let digest = if status == "busy" {
        String::new()
    } else {
        format!("{:x}", Sha256::digest(&received))
    };
    let ack = format!(
        "{{\"payload_digest\":\"{digest}\",\"protocol_version\":1,\"status\":\"{status}\"}}"
    );
    stream
        .write_u32(u32::try_from(ack.len()).expect("bounded ack"))
        .await
        .expect("write ack length");
    stream.write_all(ack.as_bytes()).await.expect("write ack");
    stream.shutdown().await.expect("close acknowledgement");
}

fn spawn_driver(
    fixture: &Fixture,
    mut node: GuardianP2p,
) -> (oneshot::Sender<()>, JoinHandle<Result<(), TransportError>>) {
    let ballot_ingress = UnixBallotIngress::configured(
        fixture.verifier_dir.join("unused-ballot.sock"),
        Duration::from_secs(2),
    )
    .expect("configured ballot ingress");
    let threat_hint_ingress =
        UnixThreatHintIngress::new(&fixture.verifier_socket, Duration::from_secs(2))
            .expect("owner-only ThreatHint ingress");
    let threat_hint_v2_ingress = UnixThreatHintV2Ingress::configured(
        fixture.verifier_dir.join("unused-threat-hint-v2.sock"),
        Duration::from_secs(2),
    )
    .expect("configured ThreatHint-v2 ingress");
    let (shutdown_tx, mut shutdown_rx) = oneshot::channel();
    let task = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => return Ok(()),
                event = node.next_verified_sidecar_event(
                    &ballot_ingress,
                    &threat_hint_ingress,
                    &threat_hint_v2_ingress,
                ) => {
                    event?;
                }
            }
        }
    });
    (shutdown_tx, task)
}

fn command() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_prometheus-client"));
    command
        .env("PROMETHEUS_RUNTIME", "development")
        .env_remove("RUST_LOG")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

fn cli(fixture: &Fixture, verb: &str) -> Command {
    let mut command = command();
    command.args(["threat-hint", verb, "--config"]);
    command.arg(&fixture.config_path);
    command.arg("--hint");
    command.arg(&fixture.hint_path);
    command
}

async fn run_to_output(mut command: Command) -> std::process::Output {
    command.kill_on_drop(true);
    timeout(Duration::from_secs(20), command.output())
        .await
        .expect("bounded CLI execution")
        .expect("CLI process")
}

fn assert_redacted(fixture: &Fixture, peer: &str, output: &std::process::Output) {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    for text in [stdout.as_ref(), stderr.as_ref()] {
        for forbidden in [
            peer,
            "127.0.0.1",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            fixture._temp.path().to_string_lossy().as_ref(),
            fixture.verifier_socket.to_string_lossy().as_ref(),
        ] {
            assert!(
                !text.contains(forbidden),
                "process output exposed {forbidden:?}"
            );
        }
    }
}

fn stdout_status(output: &std::process::Output) -> String {
    let report: Value = serde_json::from_slice(&output.stdout).expect("JSON status report");
    report["status"].as_str().expect("status field").to_owned()
}

#[tokio::test]
async fn real_binary_loopback_submit_maps_remote_boundary_status() {
    let fixture = fixture();
    write_private(&fixture.hint_path, VALID_HINT);
    let (guardian, route, peer) = start_guardian(&fixture).await;
    write_config(&fixture, &peer, &route, 10);

    // Offline preflight validates without creating the identity or dialing.
    let output = run_to_output(cli(&fixture, "preflight")).await;
    assert!(output.status.success());
    assert_eq!(
        stdout_status(&output),
        "ready-for-development-threat-hint-submit"
    );
    assert!(
        !fixture.identity_path.exists(),
        "preflight must not create the transport identity"
    );
    assert_eq!(guardian.pending_work(), (0, 0));
    assert_redacted(&fixture, &peer, &output);

    let listener = bind_verifier(&fixture.verifier_socket).await;
    let (shutdown, driver) = spawn_driver(&fixture, guardian);

    for status in ["accepted", "duplicate", "rejected", "busy"] {
        let serve = tokio::spawn(serve_once(
            Arc::clone(&listener),
            VALID_HINT.to_vec(),
            status,
        ));
        let output = run_to_output(cli(&fixture, "submit")).await;
        timeout(Duration::from_secs(20), serve)
            .await
            .expect("verifier observed the submission")
            .expect("verifier task");
        assert!(output.status.success(), "submit {status} exit status");
        assert_eq!(stdout_status(&output), status);
        assert_redacted(&fixture, &peer, &output);
        let mode = fs::metadata(&fixture.identity_path)
            .expect("identity created on submit")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    shutdown.send(()).expect("request clean Guardian shutdown");
    timeout(Duration::from_secs(10), driver)
        .await
        .expect("bounded Guardian shutdown")
        .expect("Guardian driver task")
        .expect("Guardian driver transport");

    // A stopped Guardian boundary maps to a bounded transport-failure.
    write_config(&fixture, &peer, &route, 2);
    let output = run_to_output(cli(&fixture, "submit")).await;
    assert!(!output.status.success());
    assert_eq!(stdout_status(&output), "transport-failure");
    assert_redacted(&fixture, &peer, &output);
}

#[tokio::test]
async fn beta_and_mainnet_reject_before_network_activity() {
    let fixture = fixture();
    write_private(&fixture.hint_path, VALID_HINT);
    // The route is syntactically valid but nothing is listening; the runtime
    // gate must reject before any dial is attempted.
    let (guardian, route, peer) = start_guardian(&fixture).await;
    drop(guardian);
    write_config(&fixture, &peer, &route, 2);

    for mode in ["beta", "mainnet"] {
        for verb in ["preflight", "submit"] {
            let mut command = cli(&fixture, verb);
            command.env("PROMETHEUS_RUNTIME", mode);
            let output = run_to_output(command).await;
            assert!(
                !output.status.success(),
                "{mode} {verb} must reject before network activity"
            );
            assert_redacted(&fixture, &peer, &output);
        }
    }
    assert!(
        !fixture.identity_path.exists(),
        "rejected runs must not create the transport identity"
    );
}

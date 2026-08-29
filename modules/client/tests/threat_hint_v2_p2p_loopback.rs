//! Binary-level Development-only evidence for the GH-234 ThreatHint-v2 sender.
//!
//! The real `prometheus-client` binary drives the real Guardian libp2p stack
//! over literal QUIC loopback into an owner-only mock verifier boundary,
//! sending exactly one canonical `ThreatHintV2TransportPayload` frame from the
//! shared threat-hint v2 transport vector corpus. Every peer is an ephemeral
//! loopback fixture. This is not public Testnet or production evidence; the
//! acknowledgement only reports a remote local-boundary outcome, never proof,
//! approval, membership, reward, or chain authority, and no fixture value may
//! appear in process output. Negative coverage for the GH-229
//! controlled-remote opt-in verifies that unsafe or non-Development remote
//! routes reject before identity mutation or any network activity; no remote
//! dial is ever attempted here.

#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicUsize, Ordering};
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

/// Exact canonical wire of the shared threat-hint v2 transport vector; no
/// second fixture is copied into this crate.
fn valid_payload_wire() -> Vec<u8> {
    let corpus: Value = serde_json::from_str(include_str!(
        "../../threat-hint/tests/vectors/threat-hint-v2-transport-v1.json"
    ))
    .expect("transport vector corpus");
    let vector = corpus["valid_cases"]
        .as_array()
        .expect("valid cases")
        .iter()
        .find(|entry| entry["name"] == "base_review_required")
        .expect("base_review_required vector");
    assert_eq!(
        vector["trusted_network_id"].as_str().expect("network id"),
        "testnet-10"
    );
    let encoded = vector["wire_hex"].as_str().expect("wire hex");
    assert!(encoded.len() % 2 == 0, "even-length hex");
    (0..encoded.len())
        .step_by(2)
        .map(|offset| u8::from_str_radix(&encoded[offset..offset + 2], 16).expect("hex pair"))
        .collect()
}

/// Hex of the untrusted 32-byte report nonce inside one canonical frame.
fn payload_nonce_hex(wire: &[u8]) -> String {
    wire[5..37]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

struct Fixture {
    _temp: TempDir,
    guardian_dir: PathBuf,
    verifier_dir: PathBuf,
    verifier_socket: PathBuf,
    config_path: PathBuf,
    payload_path: PathBuf,
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
        config_path: client_dir.join("threat-hint-v2.toml"),
        payload_path: client_dir.join("payload.bin"),
        identity_path: client_dir.join("client.identity"),
        verifier_socket: verifier_dir.join("threat-hint-v2.sock"),
        _temp: temp,
        guardian_dir,
        verifier_dir,
    }
}

fn write_config(fixture: &Fixture, peer: &str, route: &str, timeout_secs: u64) {
    write_config_with_mode(fixture, peer, route, timeout_secs, None);
}

fn write_config_with_mode(
    fixture: &Fixture,
    peer: &str,
    route: &str,
    timeout_secs: u64,
    route_mode: Option<&str>,
) {
    let mode_line = route_mode
        .map(|mode| format!("route_mode = \"{mode}\"\n"))
        .unwrap_or_default();
    let text = format!(
        "enabled = true\nnetwork = \"testnet10\"\n{mode_line}guardian_peer_id = \"{peer}\"\nguardian_address = \"{route}\"\nidentity_path = \"{}\"\nsubmission_timeout_secs = {timeout_secs}\n",
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
    config.threat_hint_v2_trusted_network_id = "testnet-10".to_owned();
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

async fn serve_once(
    listener: Arc<UnixListener>,
    connections: Arc<AtomicUsize>,
    expected: Vec<u8>,
    status: &'static str,
) {
    let (mut stream, _) = listener
        .accept()
        .await
        .expect("accept ThreatHint-v2 carrier");
    connections.fetch_add(1, Ordering::SeqCst);
    let length = stream.read_u32().await.expect("read payload length") as usize;
    let mut received = vec![0_u8; length];
    stream
        .read_exact(&mut received)
        .await
        .expect("read exact payload");
    assert_eq!(received, expected, "exact canonical v2 payload bytes");
    let digest = if status == "busy" {
        String::new()
    } else {
        format!("{:x}", Sha256::digest(&received))
    };
    let ack = format!(
        "{{\"payload_digest\":\"{digest}\",\"protocol_version\":2,\"status\":\"{status}\"}}"
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
    let threat_hint_ingress = UnixThreatHintIngress::configured(
        fixture.verifier_dir.join("unused-threat-hint.sock"),
        Duration::from_secs(2),
    )
    .expect("configured ThreatHint ingress");
    let threat_hint_v2_ingress =
        UnixThreatHintV2Ingress::new(&fixture.verifier_socket, Duration::from_secs(2))
            .expect("owner-only ThreatHint-v2 ingress");
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
    command.args(["threat-hint-v2", verb, "--config"]);
    command.arg(&fixture.config_path);
    command.arg("--payload");
    command.arg(&fixture.payload_path);
    command
}

async fn run_to_output(mut command: Command) -> std::process::Output {
    command.kill_on_drop(true);
    timeout(Duration::from_secs(20), command.output())
        .await
        .expect("bounded CLI execution")
        .expect("CLI process")
}

fn assert_redacted(fixture: &Fixture, peer: &str, nonce_hex: &str, output: &std::process::Output) {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    for text in [stdout.as_ref(), stderr.as_ref()] {
        for forbidden in [
            peer,
            "127.0.0.1",
            nonce_hex,
            "ThreatHint v1 submit CLI",
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
    let payload = valid_payload_wire();
    let nonce_hex = payload_nonce_hex(&payload);
    write_private(&fixture.payload_path, &payload);
    let listener = bind_verifier(&fixture.verifier_socket).await;
    let mut stopped_route = String::new();
    let mut stopped_peer = String::new();

    for (index, status) in ["accepted", "rejected", "busy"].into_iter().enumerate() {
        // Each short-lived real client gets a fresh Guardian lifecycle. This
        // avoids overlapping connection-close events in libp2p 0.29 while
        // preserving exact real-binary status coverage.
        let (guardian, route, peer) = start_guardian(&fixture).await;
        write_config(&fixture, &peer, &route, 10);

        if index == 0 {
            // Offline preflight validates without creating the identity or dialing.
            let output = run_to_output(cli(&fixture, "preflight")).await;
            assert!(output.status.success());
            assert_eq!(
                stdout_status(&output),
                "ready-for-development-threat-hint-v2-submit"
            );
            assert!(
                !fixture.identity_path.exists(),
                "preflight must not create the transport identity"
            );
            assert_eq!(guardian.pending_work(), (0, 0));
            assert_redacted(&fixture, &peer, &nonce_hex, &output);
        }

        let (shutdown, driver) = spawn_driver(&fixture, guardian);
        let connections = Arc::new(AtomicUsize::new(0));
        let serve = tokio::spawn(serve_once(
            Arc::clone(&listener),
            Arc::clone(&connections),
            payload.clone(),
            status,
        ));
        let output = run_to_output(cli(&fixture, "submit")).await;
        timeout(Duration::from_secs(20), serve)
            .await
            .expect("verifier observed the submission")
            .expect("verifier task");
        assert!(output.status.success(), "submit {status} exit status");
        assert_eq!(stdout_status(&output), status);
        assert_eq!(
            connections.load(Ordering::SeqCst),
            1,
            "exactly one submission attempt reached the boundary"
        );
        let report: Value = serde_json::from_slice(&output.stdout).expect("JSON submit report");
        assert_eq!(report["retries"].as_u64().expect("retries field"), 0);
        assert!(!report["persisted"].as_bool().expect("persisted field"));
        assert_eq!(
            report["ack_authority"]
                .as_str()
                .expect("ack_authority field"),
            "none"
        );
        assert_redacted(&fixture, &peer, &nonce_hex, &output);
        let mode = fs::metadata(&fixture.identity_path)
            .expect("identity created on submit")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);

        shutdown.send(()).expect("request clean Guardian shutdown");
        timeout(Duration::from_secs(10), driver)
            .await
            .expect("bounded Guardian shutdown")
            .expect("Guardian driver task")
            .expect("Guardian driver transport");
        stopped_route = route;
        stopped_peer = peer;
    }

    // A stopped Guardian boundary maps to a bounded transport-failure.
    write_config(&fixture, &stopped_peer, &stopped_route, 2);
    let output = run_to_output(cli(&fixture, "submit")).await;
    assert!(!output.status.success());
    assert_eq!(stdout_status(&output), "transport-failure");
    assert_redacted(&fixture, &stopped_peer, &nonce_hex, &output);
}

#[tokio::test]
async fn beta_and_mainnet_reject_before_network_activity() {
    let fixture = fixture();
    let payload = valid_payload_wire();
    let nonce_hex = payload_nonce_hex(&payload);
    write_private(&fixture.payload_path, &payload);
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
            assert_redacted(&fixture, &peer, &nonce_hex, &output);
        }
    }
    assert!(
        !fixture.identity_path.exists(),
        "rejected runs must not create the transport identity"
    );
}

#[tokio::test]
async fn controlled_remote_rejects_unsafe_routes_and_non_development_modes() {
    let fixture = fixture();
    let payload = valid_payload_wire();
    let nonce_hex = payload_nonce_hex(&payload);
    write_private(&fixture.payload_path, &payload);
    let (guardian, loopback_route, peer) = start_guardian(&fixture).await;
    drop(guardian);

    // Remote mode never accepts a loopback-shaped route.
    for route in [
        loopback_route.clone(),
        format!("/ip6/::ffff:7f00:1/udp/4001/quic-v1/p2p/{peer}"),
        format!("/ip6/::ffff:808:808/udp/4001/quic-v1/p2p/{peer}"),
        format!("/ip4/169.254.10.20/udp/4001/quic-v1/p2p/{peer}"),
        format!("/ip4/192.0.2.10/udp/4001/quic-v1/p2p/{peer}"),
        format!("/ip4/198.18.1.10/udp/4001/quic-v1/p2p/{peer}"),
        format!("/ip4/255.255.255.255/udp/4001/quic-v1/p2p/{peer}"),
        format!("/dns4/guardian.example.invalid/udp/4001/quic-v1/p2p/{peer}"),
    ] {
        write_config_with_mode(
            &fixture,
            &peer,
            &route,
            2,
            Some("controlled-remote-testnet10"),
        );
        for verb in ["preflight", "submit"] {
            let output = run_to_output(cli(&fixture, verb)).await;
            assert!(
                !output.status.success(),
                "remote mode must reject route {route} ({verb})"
            );
            assert_redacted(&fixture, &peer, &nonce_hex, &output);
        }
    }
    assert!(
        !fixture.identity_path.exists(),
        "rejected remote runs must not create the transport identity"
    );

    // A syntactically valid bounded remote route is gated by Beta and Mainnet
    // before identity mutation or any dial.
    let remote_route = format!("/ip4/10.8.0.1/udp/4001/quic-v1/p2p/{peer}");
    write_config_with_mode(
        &fixture,
        &peer,
        &remote_route,
        2,
        Some("controlled-remote-testnet10"),
    );
    for mode in ["beta", "mainnet"] {
        for verb in ["preflight", "submit"] {
            let mut command = cli(&fixture, verb);
            command.env("PROMETHEUS_RUNTIME", mode);
            let output = run_to_output(command).await;
            assert!(
                !output.status.success(),
                "{mode} {verb} must reject the remote route before network activity"
            );
            assert_redacted(&fixture, &peer, &nonce_hex, &output);
        }
    }
    assert!(
        !fixture.identity_path.exists(),
        "gated remote runs must not create the transport identity"
    );

    // Development offline preflight accepts the bounded remote route without
    // creating the identity or dialing.
    let output = run_to_output(cli(&fixture, "preflight")).await;
    assert!(output.status.success(), "remote preflight exit status");
    assert_eq!(
        stdout_status(&output),
        "ready-for-development-threat-hint-v2-submit"
    );
    let report: Value = serde_json::from_slice(&output.stdout).expect("JSON preflight report");
    assert_eq!(
        report["route_scope"].as_str().expect("route_scope field"),
        "single-static-controlled-remote-quic-peer"
    );
    assert!(
        !fixture.identity_path.exists(),
        "remote preflight must not create the transport identity"
    );
    assert_redacted(&fixture, &peer, &nonce_hex, &output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stdout.contains("10.8.0.1") && !stderr.contains("10.8.0.1"),
        "process output must not expose the remote literal"
    );
}

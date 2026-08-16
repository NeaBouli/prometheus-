//! Binary-level Development/Testnet-10 evidence for the RuleStorage sync CLI.
//!
//! Every peer is an ephemeral loopback fixture. This is not public Testnet or
//! production evidence, and no fixture value is written to diagnostic output.

#![cfg(unix)]

use std::fs;
use std::future::pending;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use kaspa_addresses::{Address, Prefix, Version};
use kaspa_hashes::Hash;
use kaspa_rpc_core::{
    api::ops::RpcApiOps, GetBlockDagInfoRequest, GetBlockDagInfoResponse,
    GetUtxosByAddressesRequest, GetUtxosByAddressesResponse, RpcScriptPublicKey,
    RpcTransactionOutpoint, RpcUtxoEntry, RpcUtxosByAddressesEntry,
};
use kaspa_wrpc_client::prelude::{NetworkId, NetworkType};
use prometheus_client::blockchain::rule_observation::{MANIFEST_KIND, OBSERVATION_NETWORK_ID};
use prometheus_client::security::scanner::compute_sha256;
use rustix::process::{kill_process, Pid, Signal};
use secp256k1::{Keypair, Message, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::process::{Child, Command};
use tokio::sync::Notify;
use tokio::time::{sleep, timeout, Instant};
use workflow_rpc::id::Id64;
use workflow_rpc::server::{
    Encoding, Interface, Messenger, Method, RpcHandler, RpcServer, SocketAddr, WebSocketReceiver,
    WebSocketResult, WebSocketSender,
};
use workflow_serializer::prelude::Serializable;

const SIGNING_DOMAIN: &[u8] = b"prometheus.rule-snapshot.envelope.v1\0";
const BLOCK_DAA: u64 = 1_000;
const OBSERVED_DAA: u64 = 1_200;
const AMOUNT: u64 = 100_000_000;
const CHECKPOINT_FILE: &str = "rule-storage.checkpoint.json";

#[derive(Clone, Serialize)]
struct EnvelopeEntry {
    expected_manifest_sha256: String,
    manifest_json: String,
    constructor_json: String,
    address: String,
}

#[derive(Serialize)]
struct EnvelopePayload<'a> {
    schema_version: u64,
    kind: &'static str,
    network_id: &'static str,
    sequence: u64,
    valid_from: u64,
    valid_until: u64,
    empty_snapshot_order: Option<u64>,
    entries: &'a [EnvelopeEntry],
}

#[derive(Deserialize, Serialize)]
struct CheckpointFixture {
    schema_version: u64,
    kind: String,
    network_id: String,
    order: u64,
    snapshot_digest: String,
}

struct Fixture {
    temp: TempDir,
    config: PathBuf,
    checkpoint: PathBuf,
    content: Vec<u8>,
    cid: String,
    address: Address,
    public_key: String,
    signature: String,
    utxo: RpcUtxosByAddressesEntry,
}

#[derive(Clone)]
struct RpcState {
    dag_calls: Arc<AtomicUsize>,
    utxo_calls: Arc<AtomicUsize>,
    connections: Arc<AtomicUsize>,
    utxo_started: Arc<Notify>,
    block_utxo: bool,
    virtual_daa: u64,
    utxo: RpcUtxosByAddressesEntry,
}

struct Handler {
    connections: Arc<AtomicUsize>,
}

#[async_trait]
impl RpcHandler for Handler {
    type Context = ();

    async fn connect(self: Arc<Self>, _peer: &SocketAddr) -> WebSocketResult<()> {
        self.connections.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    async fn handshake(
        self: Arc<Self>,
        _peer: &SocketAddr,
        _sender: &mut WebSocketSender,
        _receiver: &mut WebSocketReceiver,
        _messenger: Arc<Messenger>,
    ) -> WebSocketResult<Self::Context> {
        Ok(())
    }
}

struct RpcPeer {
    server: RpcServer,
    port: u16,
    state: RpcState,
    task: tokio::task::JoinHandle<()>,
}

impl RpcPeer {
    async fn start(utxo: RpcUtxosByAddressesEntry, block_utxo: bool, virtual_daa: u64) -> Self {
        let state = RpcState {
            dag_calls: Arc::new(AtomicUsize::new(0)),
            utxo_calls: Arc::new(AtomicUsize::new(0)),
            connections: Arc::new(AtomicUsize::new(0)),
            utxo_started: Arc::new(Notify::new()),
            block_utxo,
            virtual_daa,
            utxo,
        };
        let mut interface = Interface::<RpcState, (), RpcApiOps>::new(state.clone());
        interface.method(
            RpcApiOps::GetBlockDagInfo,
            Method::new(
                |state: RpcState, (), _request: Serializable<GetBlockDagInfoRequest>| {
                    Box::pin(async move {
                        state.dag_calls.fetch_add(1, Ordering::SeqCst);
                        Ok(Serializable(GetBlockDagInfoResponse::new(
                            NetworkId::with_suffix(NetworkType::Testnet, 10),
                            1,
                            1,
                            vec![Hash::from_bytes([1; 32])],
                            1.0,
                            1,
                            vec![Hash::from_bytes([2; 32])],
                            Hash::from_bytes([3; 32]),
                            state.virtual_daa,
                            Hash::from_bytes([4; 32]),
                        )))
                    })
                },
            ),
        );
        interface.method(
            RpcApiOps::GetUtxosByAddresses,
            Method::new(
                |state: RpcState, (), _request: Serializable<GetUtxosByAddressesRequest>| {
                    Box::pin(async move {
                        state.utxo_calls.fetch_add(1, Ordering::SeqCst);
                        state.utxo_started.notify_one();
                        if state.block_utxo {
                            pending::<()>().await;
                        }
                        Ok(Serializable(GetUtxosByAddressesResponse::new(vec![
                            state.utxo,
                        ])))
                    })
                },
            ),
        );

        let handler = Arc::new(Handler {
            connections: state.connections.clone(),
        });
        let server = RpcServer::new_with_encoding::<RpcState, (), RpcApiOps, Id64>(
            Encoding::Borsh,
            handler,
            Arc::new(interface),
            None,
            true,
        );
        let listener = server.bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let listening_server = server.clone();
        let task = tokio::spawn(async move {
            let _ = listening_server.listen(listener, None).await;
        });
        Self {
            server,
            port,
            state,
            task,
        }
    }

    fn stop(&self) {
        self.server.stop().unwrap();
        self.task.abort();
    }
}

struct HttpPeer {
    port: u16,
    requests: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

struct DisconnectPeer {
    port: u16,
    task: tokio::task::JoinHandle<()>,
}

impl DisconnectPeer {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                drop(stream);
            }
        });
        Self { port, task }
    }

    fn stop(self) {
        self.task.abort();
    }
}

impl HttpPeer {
    async fn start(content: Vec<u8>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let requests = Arc::new(AtomicUsize::new(0));
        let counter = requests.clone();
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let body = content.clone();
                let counter = counter.clone();
                tokio::spawn(async move {
                    let mut request = vec![0; 4096];
                    if stream.read(&mut request).await.is_err() {
                        return;
                    }
                    counter.fetch_add(1, Ordering::SeqCst);
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Encoding: identity\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    if stream.write_all(response.as_bytes()).await.is_ok() {
                        let _ = stream.write_all(&body).await;
                    }
                });
            }
        });
        Self {
            port,
            requests,
            task,
        }
    }

    fn stop(self) {
        self.task.abort();
    }
}

fn int(value: i64) -> Value {
    json!({"kind": "int", "data": value})
}

fn bytes(values: &[u8]) -> Value {
    json!({
        "kind": "array",
        "data": values.iter().map(|value| json!({"kind": "byte", "data": value})).collect::<Vec<_>>()
    })
}

fn cid_for(content: &[u8]) -> String {
    let mut bytes = vec![0x01, 0x55, 0x12, 0x20];
    bytes.extend(compute_sha256(content));
    multibase::encode(multibase::Base::Base32Lower, &bytes)
}

fn constructor_document(content: &[u8]) -> String {
    let mut cid = vec![0x01, 0x55, 0x12, 0x20];
    cid.extend(compute_sha256(content));
    serde_json::to_string(&json!([
        bytes(&[4; 32]), int(8), int(7), bytes(&[5; 32]), bytes(&[6; 32]), int(0),
        bytes(&cid), int(9_000), int(100_000), int(3), int(1), int(964_000), int(2),
        int(3), int(2), int(50_000), int(7_500), int(965_000),
        {"kind": "bool", "data": true}, int(1)
    ]))
    .unwrap()
}

fn manifest_json(constructor_hash: &str) -> String {
    format!(
        "{{\"schema_version\":1,\"kind\":\"{MANIFEST_KIND}\",\"network_id\":\"{OBSERVATION_NETWORK_ID}\",\"outpoint\":{{\"transaction_id\":\"{}\",\"index\":1}},\"covenant_id\":\"{}\",\"script_public_key\":{{\"version\":0,\"script_hex\":\"51\"}},\"amount_sompi\":{AMOUNT},\"block_daa_score\":{BLOCK_DAA},\"minimum_virtual_daa_maturity\":100,\"constructor_json_sha256\":\"{constructor_hash}\"}}",
        "11".repeat(32),
        "22".repeat(32)
    )
}

fn write_private(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

fn fixture() -> Fixture {
    let temp = TempDir::new().unwrap();
    let config = temp.path().join("config.toml");
    let envelope = temp.path().join("snapshot.json");
    let checkpoint = temp.path().join("checkpoint");
    fs::create_dir(&checkpoint).unwrap();
    fs::set_permissions(&checkpoint, fs::Permissions::from_mode(0o700)).unwrap();
    let content =
        b"rule PROM-RULE-0007 {\nstrings:\n$a = \"loopback-marker\"\ncondition:\nany of them\n}\n"
            .to_vec();
    let cid = cid_for(&content);
    let address = Address::new(Prefix::Testnet, Version::PubKey, &[7; 32]);
    let constructor = constructor_document(&content);
    let manifest = manifest_json(&hex::encode(Sha256::digest(constructor.as_bytes())));
    let entry = EnvelopeEntry {
        expected_manifest_sha256: hex::encode(Sha256::digest(manifest.as_bytes())),
        manifest_json: manifest,
        constructor_json: constructor,
        address: address.to_string(),
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let payload = EnvelopePayload {
        schema_version: 1,
        kind: "prometheus.rule-snapshot.envelope.v1",
        network_id: "testnet-10",
        sequence: 7,
        valid_from: now - 300,
        valid_until: now + 300,
        empty_snapshot_order: None,
        entries: std::slice::from_ref(&entry),
    };
    let mut envelope_bytes = serde_json::to_vec(&payload).unwrap();
    let secret = SecretKey::from_slice(&[0x42; 32]).unwrap();
    let secp = Secp256k1::new();
    let keypair = Keypair::from_secret_key(&secp, &secret);
    let public_key = hex::encode(keypair.x_only_public_key().0.serialize());
    let mut hasher = Sha256::new();
    hasher.update(SIGNING_DOMAIN);
    hasher.update((envelope_bytes.len() as u64).to_be_bytes());
    hasher.update(&envelope_bytes);
    let message = Message::from_digest(hasher.finalize().into());
    let signature_value = secp.sign_schnorr_no_aux_rand(&message, &keypair);
    let signature = hex::encode(signature_value.as_ref());
    assert_eq!(envelope_bytes.pop(), Some(b'}'));
    envelope_bytes.extend_from_slice(format!(",\"signature\":\"{signature}\"}}").as_bytes());
    write_private(&envelope, &envelope_bytes);

    let utxo = RpcUtxosByAddressesEntry {
        address: Some(address.clone()),
        outpoint: RpcTransactionOutpoint {
            transaction_id: Hash::from_bytes([0x11; 32]),
            index: 1,
        },
        utxo_entry: RpcUtxoEntry::new(
            AMOUNT,
            RpcScriptPublicKey::from_vec(0, vec![0x51]),
            BLOCK_DAA,
            false,
            Some(Hash::from_bytes([0x22; 32])),
        ),
    };
    Fixture {
        temp,
        config,
        checkpoint,
        content,
        cid,
        address,
        public_key,
        signature,
        utxo,
    }
}

fn write_config(fixture: &Fixture, rpc_port: u16, http_port: u16) {
    write_config_with_timeout(fixture, rpc_port, http_port, 10_000);
}

fn write_config_with_timeout(
    fixture: &Fixture,
    rpc_port: u16,
    http_port: u16,
    attempt_timeout_ms: u64,
) {
    let envelope = fixture.temp.path().join("snapshot.json");
    let config = format!(
        "enabled = true\nnetwork = \"testnet10\"\nowner_xonly_public_key = \"{}\"\nminimum_sequence = 1\nsigned_envelope_path = \"{}\"\nrpc_url = \"ws://127.0.0.1:{rpc_port}\"\nipfs_gateway_url = \"http://127.0.0.1:{http_port}/ipfs/\"\ncheckpoint_dir = \"{}\"\nsuccess_interval_secs = 60\ninitial_failure_backoff_ms = 100\nmax_failure_backoff_ms = 1000\nattempt_timeout_ms = {attempt_timeout_ms}\n",
        fixture.public_key,
        envelope.display(),
        fixture.checkpoint.display()
    );
    write_private(&fixture.config, config.as_bytes());
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

fn assert_redacted(fixture: &Fixture, output: &[u8]) {
    let text = String::from_utf8_lossy(output);
    for forbidden in [
        fixture.cid.as_str(),
        fixture.address.to_string().as_str(),
        fixture.public_key.as_str(),
        fixture.signature.as_str(),
        "loopback-marker",
        fixture.temp.path().to_string_lossy().as_ref(),
        "127.0.0.1",
    ] {
        assert!(
            !text.contains(forbidden),
            "process output exposed fixture data"
        );
    }
}

async fn run_to_output(mut command: Command) -> std::process::Output {
    command.kill_on_drop(true);
    timeout(Duration::from_secs(20), command.output())
        .await
        .expect("bounded CLI execution")
        .expect("CLI process")
}

async fn wait_for_checkpoint(path: &Path) -> bool {
    let deadline = Instant::now() + Duration::from_secs(20);
    while !path.exists() {
        if Instant::now() >= deadline {
            return false;
        }
        sleep(Duration::from_millis(20)).await;
    }
    true
}

async fn wait_for_requests(counter: &AtomicUsize, minimum: usize) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while counter.load(Ordering::SeqCst) < minimum {
        assert!(
            Instant::now() < deadline,
            "peer request was not observed in time"
        );
        sleep(Duration::from_millis(20)).await;
    }
}

fn signal(child: &Child, signal: Signal) {
    let pid = child.id().and_then(|id| Pid::from_raw(id as i32)).unwrap();
    kill_process(pid, signal).unwrap();
}

async fn finish_child(child: Child) -> std::process::Output {
    timeout(Duration::from_secs(10), child.wait_with_output())
        .await
        .expect("bounded signal drain")
        .expect("child output")
}

#[tokio::test]
async fn real_binary_loopback_preflight_sync_and_signal_drain() {
    let fixture = fixture();
    let rpc_probe = RpcPeer::start(fixture.utxo.clone(), false, OBSERVED_DAA).await;
    let http = HttpPeer::start(fixture.content.clone()).await;
    write_config(&fixture, rpc_probe.port, http.port);

    let mut offline = command();
    offline.args(["rule-sync", "preflight", "--config"]);
    offline.arg(&fixture.config);
    let output = run_to_output(offline).await;
    assert!(output.status.success());
    assert_eq!(rpc_probe.state.connections.load(Ordering::SeqCst), 0);
    assert_eq!(http.requests.load(Ordering::SeqCst), 0);
    assert_eq!(fs::read_dir(&fixture.checkpoint).unwrap().count(), 0);
    assert_redacted(&fixture, &output.stdout);
    assert_redacted(&fixture, &output.stderr);

    let mut connected = command();
    connected.args(["rule-sync", "preflight", "--connect", "--config"]);
    connected.arg(&fixture.config);
    let output = run_to_output(connected).await;
    assert!(output.status.success());
    assert_eq!(rpc_probe.state.dag_calls.load(Ordering::SeqCst), 1);
    assert_eq!(rpc_probe.state.utxo_calls.load(Ordering::SeqCst), 0);
    assert_eq!(http.requests.load(Ordering::SeqCst), 0);
    assert_redacted(&fixture, &output.stdout);
    assert_redacted(&fixture, &output.stderr);
    rpc_probe.stop();

    let rpc_run = RpcPeer::start(fixture.utxo.clone(), false, OBSERVED_DAA).await;
    write_config(&fixture, rpc_run.port, http.port);

    let mut run = command();
    run.args(["rule-sync", "run", "--config"]);
    run.arg(&fixture.config).kill_on_drop(true);
    let child = run.spawn().unwrap();
    let checkpoint = fixture.checkpoint.join(CHECKPOINT_FILE);
    let checkpoint_created = wait_for_checkpoint(&checkpoint).await;
    signal(&child, Signal::TERM);
    let output = finish_child(child).await;
    assert_redacted(&fixture, &output.stdout);
    assert_redacted(&fixture, &output.stderr);
    assert!(
        checkpoint_created,
        "checkpoint missing; rpc dag={}, utxo={}, http={}, status={}",
        rpc_run.state.dag_calls.load(Ordering::SeqCst),
        rpc_run.state.utxo_calls.load(Ordering::SeqCst),
        http.requests.load(Ordering::SeqCst),
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("\"component\":\"rule-storage-sync\""));
    let metadata = fs::metadata(&checkpoint).unwrap();
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    let checkpoint_json: Value = serde_json::from_slice(&fs::read(&checkpoint).unwrap()).unwrap();
    assert_eq!(
        checkpoint_json["kind"],
        "prometheus.rule-storage.checkpoint.v1"
    );
    assert!(checkpoint_json["order"].as_u64().unwrap() > 0);
    assert_eq!(
        checkpoint_json["snapshot_digest"].as_str().unwrap().len(),
        64
    );
    let checkpoint_bytes = fs::read(&checkpoint).unwrap();
    rpc_run.stop();

    let requests_before_replay = http.requests.load(Ordering::SeqCst);
    let rpc_replay = RpcPeer::start(fixture.utxo.clone(), false, OBSERVED_DAA).await;
    write_config(&fixture, rpc_replay.port, http.port);
    let mut replay = command();
    replay.args(["rule-sync", "run", "--config"]);
    replay.arg(&fixture.config).kill_on_drop(true);
    let replay_child = replay.spawn().unwrap();
    wait_for_requests(&http.requests, requests_before_replay + 1).await;
    sleep(Duration::from_millis(400)).await;
    signal(&replay_child, Signal::INT);
    let replay_output = finish_child(replay_child).await;
    assert!(replay_output.status.success());
    assert_eq!(
        http.requests.load(Ordering::SeqCst),
        requests_before_replay + 1
    );
    assert_eq!(fs::read(&checkpoint).unwrap(), checkpoint_bytes);
    assert_redacted(&fixture, &replay_output.stdout);
    assert_redacted(&fixture, &replay_output.stderr);
    rpc_replay.stop();

    let mut equivocation: CheckpointFixture = serde_json::from_slice(&checkpoint_bytes).unwrap();
    let alternate_digest = if equivocation.snapshot_digest.starts_with('a') {
        "b".repeat(64)
    } else {
        "a".repeat(64)
    };
    equivocation.snapshot_digest = alternate_digest;
    let equivocation_bytes = serde_json::to_vec(&equivocation).unwrap();
    write_private(&checkpoint, &equivocation_bytes);
    let requests_before_equivocation = http.requests.load(Ordering::SeqCst);
    let rpc_equivocation = RpcPeer::start(fixture.utxo.clone(), false, OBSERVED_DAA).await;
    write_config(&fixture, rpc_equivocation.port, http.port);
    let mut equivocation_run = command();
    equivocation_run.args(["rule-sync", "run", "--config"]);
    equivocation_run.arg(&fixture.config).kill_on_drop(true);
    let equivocation_child = equivocation_run.spawn().unwrap();
    wait_for_requests(&http.requests, requests_before_equivocation + 2).await;
    signal(&equivocation_child, Signal::TERM);
    let equivocation_output = finish_child(equivocation_child).await;
    assert!(equivocation_output.status.success());
    assert_eq!(fs::read(&checkpoint).unwrap(), equivocation_bytes);
    assert_redacted(&fixture, &equivocation_output.stdout);
    assert_redacted(&fixture, &equivocation_output.stderr);
    rpc_equivocation.stop();
    write_private(&checkpoint, &checkpoint_bytes);

    let requests_before_downgrade = http.requests.load(Ordering::SeqCst);
    let rpc_downgrade = RpcPeer::start(fixture.utxo.clone(), false, 1_100).await;
    write_config(&fixture, rpc_downgrade.port, http.port);
    let mut downgrade = command();
    downgrade.args(["rule-sync", "run", "--config"]);
    downgrade.arg(&fixture.config).kill_on_drop(true);
    let downgrade_child = downgrade.spawn().unwrap();
    wait_for_requests(&http.requests, requests_before_downgrade + 2).await;
    signal(&downgrade_child, Signal::TERM);
    let downgrade_output = finish_child(downgrade_child).await;
    assert!(downgrade_output.status.success());
    assert_eq!(fs::read(&checkpoint).unwrap(), checkpoint_bytes);
    assert_redacted(&fixture, &downgrade_output.stdout);
    assert_redacted(&fixture, &downgrade_output.stderr);
    rpc_downgrade.stop();
    http.stop();
}

#[tokio::test]
async fn sigterm_cancels_blocked_attempt_without_checkpoint_mutation() {
    let fixture = fixture();
    let rpc = RpcPeer::start(fixture.utxo.clone(), true, OBSERVED_DAA).await;
    let http = HttpPeer::start(fixture.content.clone()).await;
    write_config(&fixture, rpc.port, http.port);

    let mut run = command();
    run.args(["rule-sync", "run", "--config"]);
    run.arg(&fixture.config).kill_on_drop(true);
    let child = run.spawn().unwrap();
    timeout(Duration::from_secs(20), rpc.state.utxo_started.notified())
        .await
        .expect("blocked UTXO request was not observed");
    signal(&child, Signal::TERM);
    let output = finish_child(child).await;
    assert!(output.status.success());
    assert_redacted(&fixture, &output.stdout);
    assert_redacted(&fixture, &output.stderr);
    assert_eq!(fs::read_dir(&fixture.checkpoint).unwrap().count(), 0);

    rpc.stop();
    http.stop();
}

#[tokio::test]
async fn malformed_ipfs_bytes_retry_without_checkpoint_mutation() {
    let fixture = fixture();
    let rpc = RpcPeer::start(fixture.utxo.clone(), false, OBSERVED_DAA).await;
    let http = HttpPeer::start(b"not-the-cid-bound-rule".to_vec()).await;
    write_config(&fixture, rpc.port, http.port);

    let mut run = command();
    run.args(["rule-sync", "run", "--config"]);
    run.arg(&fixture.config).kill_on_drop(true);
    let child = run.spawn().unwrap();
    wait_for_requests(&http.requests, 2).await;
    signal(&child, Signal::TERM);
    let output = finish_child(child).await;
    assert!(output.status.success());
    assert_redacted(&fixture, &output.stdout);
    assert_redacted(&fixture, &output.stderr);
    assert_eq!(fs::read_dir(&fixture.checkpoint).unwrap().count(), 0);

    rpc.stop();
    http.stop();
}

#[tokio::test]
async fn blocked_attempt_times_out_and_retries_without_checkpoint_mutation() {
    let fixture = fixture();
    let rpc = RpcPeer::start(fixture.utxo.clone(), true, OBSERVED_DAA).await;
    let http = HttpPeer::start(fixture.content.clone()).await;
    write_config_with_timeout(&fixture, rpc.port, http.port, 300);

    let mut run = command();
    run.args(["rule-sync", "run", "--config"]);
    run.arg(&fixture.config).kill_on_drop(true);
    let child = run.spawn().unwrap();
    wait_for_requests(&rpc.state.utxo_calls, 2).await;
    signal(&child, Signal::TERM);
    let output = finish_child(child).await;
    assert!(output.status.success());
    assert_redacted(&fixture, &output.stdout);
    assert_redacted(&fixture, &output.stderr);
    assert_eq!(fs::read_dir(&fixture.checkpoint).unwrap().count(), 0);

    rpc.stop();
    http.stop();
}

#[tokio::test]
async fn disconnected_wrpc_preflight_fails_bounded_and_redacted() {
    let fixture = fixture();
    let rpc = DisconnectPeer::start().await;
    let http = HttpPeer::start(fixture.content.clone()).await;
    write_config(&fixture, rpc.port, http.port);

    let mut preflight = command();
    preflight.args(["rule-sync", "preflight", "--connect", "--config"]);
    preflight.arg(&fixture.config);
    let output = run_to_output(preflight).await;
    assert!(!output.status.success());
    assert_redacted(&fixture, &output.stdout);
    assert_redacted(&fixture, &output.stderr);
    assert_eq!(http.requests.load(Ordering::SeqCst), 0);
    assert_eq!(fs::read_dir(&fixture.checkpoint).unwrap().count(), 0);

    rpc.stop();
    http.stop();
}

#![cfg(unix)]

use std::{
    fs,
    io::{BufRead, BufReader, Read},
    net::{Ipv4Addr, UdpSocket},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Output, Stdio},
    sync::mpsc::{self, Receiver, RecvTimeoutError},
    thread,
    time::{Duration, Instant},
};

use rustix::process::{kill_process, Pid, Signal};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::UnixListener,
    sync::{oneshot, Mutex, MutexGuard},
    task::JoinHandle,
};

use prometheus_guardian_p2p::MAX_BALLOT_BYTES;

const BINARY: &str = env!("CARGO_BIN_EXE_prometheus-guardian-p2p");
const SERVICE_EVENT_TIMEOUT: Duration = Duration::from_secs(10);
const SERVICE_EXIT_TIMEOUT: Duration = Duration::from_secs(10);
const RELAY_RESERVATION_TIMEOUT: Duration = Duration::from_secs(15);
const SUBMIT_PROCESS_TIMEOUT: Duration = Duration::from_secs(15);
const SUBMIT_REQUEST_TIMEOUT_SECS: &str = "10";
const CHILD_POLL_INTERVAL: Duration = Duration::from_millis(20);
const MAX_STDERR_DIAGNOSTIC_BYTES: usize = 64 * 1024;
const MAX_SUBMIT_OUTPUT_BYTES: usize = 64 * 1024;
static PROCESS_TEST_LOCK: Mutex<()> = Mutex::const_new(());

struct ServiceProcess {
    child: Child,
    events: Receiver<Value>,
}

impl ServiceProcess {
    fn spawn(config: &Path) -> Self {
        let mut child = Command::new(BINARY)
            .args(["run", "--config"])
            .arg(config)
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn operated service");
        let stdout = child.stdout.take().expect("capture service stdout");
        let (event_tx, events) = mpsc::channel();
        thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let line = line.expect("read service JSON line");
                let event: Value = serde_json::from_str(&line).expect("parse service JSON line");
                if event_tx.send(event).is_err() {
                    break;
                }
            }
        });
        Self { child, events }
    }

    fn wait_for(&self, timeout: Duration, mut predicate: impl FnMut(&Value) -> bool) -> Value {
        let deadline = Instant::now() + timeout;
        let mut observed = Vec::new();
        loop {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .unwrap_or_else(|| panic!("service event timed out after observing {observed:?}"));
            let event = match self.events.recv_timeout(remaining) {
                Ok(event) => event,
                Err(RecvTimeoutError::Timeout) => {
                    panic!("service event timed out after observing {observed:?}")
                }
                Err(RecvTimeoutError::Disconnected) => {
                    panic!("service event channel disconnected after observing {observed:?}")
                }
            };
            if predicate(&event) {
                return event;
            }
            observed.push(event["event"].clone());
        }
    }

    fn terminate(&mut self, timeout: Duration) -> ExitStatus {
        let pid = Pid::from_raw(self.child.id() as i32).expect("non-zero child process id");
        kill_process(pid, Signal::TERM).expect("send SIGTERM");
        let started = Instant::now();
        let deadline = started + timeout;
        loop {
            if let Some(status) = self.child.try_wait().expect("poll service exit") {
                return status;
            }
            assert!(
                Instant::now() < deadline,
                "service did not stop after SIGTERM within {timeout:?}; elapsed: {:?}",
                started.elapsed()
            );
            thread::sleep(CHILD_POLL_INTERVAL);
        }
    }

    fn drain_events(&self) -> Vec<Value> {
        self.events.try_iter().collect()
    }
}

impl Drop for ServiceProcess {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

#[derive(Serialize)]
struct CollectorAck {
    payload_digest: String,
    protocol_version: u8,
    session_id: String,
    status: &'static str,
}

#[derive(Serialize)]
struct ThreatHintV2Ack {
    payload_digest: String,
    protocol_version: u8,
    status: &'static str,
}

fn secure_directory() -> TempDir {
    let directory = tempfile::tempdir().expect("temporary sidecar directory");
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
        .expect("owner-only sidecar directory");
    directory
}

fn write_owner_only(path: &Path, contents: impl AsRef<[u8]>) {
    fs::write(path, contents).expect("write owner-only fixture");
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .expect("set owner-only fixture permissions");
}

fn reserve_udp_port() -> UdpSocket {
    UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).expect("reserve local UDP port")
}

fn preflight(config: &Path) -> Value {
    let output = Command::new(BINARY)
        .args(["preflight", "--config"])
        .arg(config)
        .output()
        .expect("run service preflight");
    assert!(
        output.status.success(),
        "preflight failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("parse preflight report")
}

async fn bind_collector(path: &Path) -> UnixListener {
    let listener = UnixListener::bind(path).expect("bind collector socket");
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .expect("owner-only collector socket");
    listener
}

async fn collect_once(listener: UnixListener, received_tx: oneshot::Sender<Vec<u8>>) {
    let (mut stream, _) = listener.accept().await.expect("accept sidecar ingress");
    let length = stream.read_u32().await.expect("read ballot length") as usize;
    assert!(
        (1..=MAX_BALLOT_BYTES).contains(&length),
        "collector ballot length is out of bounds"
    );
    let mut ballot = vec![0_u8; length];
    stream
        .read_exact(&mut ballot)
        .await
        .expect("read exact ballot bytes");
    let mut trailing = [0_u8; 1];
    assert_eq!(
        stream.read(&mut trailing).await.expect("read ballot EOF"),
        0,
        "collector ballot contained trailing bytes"
    );
    let ack = serde_json::to_vec(&CollectorAck {
        payload_digest: format!("{:x}", Sha256::digest(&ballot)),
        protocol_version: 1,
        session_id: "a".repeat(64),
        status: "accepted",
    })
    .expect("serialize collector acknowledgement");
    stream
        .write_u32(u32::try_from(ack.len()).expect("bounded acknowledgement"))
        .await
        .expect("write acknowledgement length");
    stream.write_all(&ack).await.expect("write acknowledgement");
    stream
        .shutdown()
        .await
        .expect("shutdown acknowledgement stream");
    received_tx.send(ballot).expect("record received ballot");
}

async fn collect_v2_once(
    listener: UnixListener,
    expected: Vec<u8>,
    received_tx: oneshot::Sender<Vec<u8>>,
) {
    let (mut stream, _) = listener.accept().await.expect("accept v2 ingress");
    let length = stream.read_u32().await.expect("read v2 payload length") as usize;
    assert!(
        (1..=prometheus_guardian_p2p::MAX_THREAT_HINT_V2_BYTES).contains(&length),
        "v2 payload length is out of bounds"
    );
    let mut payload = vec![0_u8; length];
    stream
        .read_exact(&mut payload)
        .await
        .expect("read exact v2 payload bytes");
    let mut trailing = [0_u8; 1];
    assert_eq!(
        stream.read(&mut trailing).await.expect("read v2 EOF"),
        0,
        "v2 payload contained trailing bytes"
    );
    assert_eq!(
        payload, expected,
        "v2 ingress received exact canonical bytes"
    );
    let ack = serde_json::to_vec(&ThreatHintV2Ack {
        payload_digest: format!("{:x}", Sha256::digest(&payload)),
        protocol_version: 2,
        status: "accepted",
    })
    .expect("serialize v2 acknowledgement");
    stream
        .write_u32(u32::try_from(ack.len()).expect("bounded acknowledgement"))
        .await
        .expect("write acknowledgement length");
    stream.write_all(&ack).await.expect("write acknowledgement");
    stream
        .shutdown()
        .await
        .expect("shutdown acknowledgement stream");
    received_tx
        .send(payload)
        .expect("record received v2 payload");
}

fn hex_decode(encoded: &str) -> Vec<u8> {
    assert!(encoded.len().is_multiple_of(2), "even-length hex");
    (0..encoded.len())
        .step_by(2)
        .map(|offset| u8::from_str_radix(&encoded[offset..offset + 2], 16).expect("hex pair"))
        .collect()
}

fn threat_hint_v2_vector_wire(case: &str) -> (Vec<u8>, String) {
    let corpus: Value = serde_json::from_str(include_str!(
        "../../threat-hint/tests/vectors/threat-hint-v2-transport-v1.json"
    ))
    .expect("transport vector corpus");
    let vector = corpus["valid_cases"]
        .as_array()
        .expect("valid cases")
        .iter()
        .find(|entry| entry["name"] == case)
        .expect("named vector case");
    (
        hex_decode(vector["wire_hex"].as_str().expect("wire hex")),
        vector["trusted_network_id"]
            .as_str()
            .expect("trusted network id")
            .to_owned(),
    )
}

fn capture_child_stderr(child: &mut Child) -> thread::JoinHandle<String> {
    let mut stderr = child.stderr.take().expect("capture child stderr");
    thread::spawn(move || {
        let mut contents = Vec::new();
        let mut truncated = false;
        let mut chunk = [0_u8; 8 * 1024];
        loop {
            let count = stderr.read(&mut chunk).expect("read child stderr");
            if count == 0 {
                break;
            }
            let retained = count.min(MAX_STDERR_DIAGNOSTIC_BYTES.saturating_sub(contents.len()));
            contents.extend_from_slice(&chunk[..retained]);
            truncated |= retained < count;
        }
        let mut rendered = String::from_utf8_lossy(&contents).into_owned();
        if truncated {
            rendered.push_str("<stderr truncated>");
        }
        rendered
    })
}

fn wait_for_child_exit(
    child: &mut Child,
    timeout: Duration,
    context: &str,
) -> (ExitStatus, String) {
    let stderr_capture = capture_child_stderr(child);
    let started = Instant::now();
    let deadline = started + timeout;
    loop {
        if let Some(status) = child.try_wait().expect("poll child exit") {
            let stderr = stderr_capture.join().expect("join child stderr capture");
            return (status, stderr);
        }
        if Instant::now() >= deadline {
            child.kill().expect("kill timed-out child");
            let forced_status = child.wait().expect("reap timed-out child");
            let stderr = stderr_capture.join().expect("join child stderr capture");
            panic!(
                "{context} within {timeout:?}; elapsed: {:?}; forced status: {forced_status}; stderr: {stderr:?}",
                started.elapsed()
            );
        }
        thread::sleep(CHILD_POLL_INTERVAL);
    }
}

async fn serialize_process_test() -> MutexGuard<'static, ()> {
    PROCESS_TEST_LOCK.lock().await
}

async fn capture_bounded<R>(mut reader: R, limit: usize) -> Vec<u8>
where
    R: AsyncRead + Unpin,
{
    let mut contents = Vec::new();
    let mut truncated = false;
    let mut chunk = [0_u8; 8 * 1024];
    loop {
        let count = reader.read(&mut chunk).await.expect("read submit output");
        if count == 0 {
            break;
        }
        let retained = count.min(limit.saturating_sub(contents.len()));
        contents.extend_from_slice(&chunk[..retained]);
        truncated |= retained < count;
    }
    if truncated {
        contents.extend_from_slice(b"<output truncated>");
    }
    contents
}

async fn join_capture(task: JoinHandle<Vec<u8>>) -> Vec<u8> {
    task.await.expect("join submit output capture")
}

async fn wait_for_submit_output(
    mut child: tokio::process::Child,
    timeout: Duration,
) -> Result<Output, String> {
    let stdout = child.stdout.take().expect("capture submit stdout");
    let stderr = child.stderr.take().expect("capture submit stderr");
    let stdout_capture = tokio::spawn(capture_bounded(stdout, MAX_SUBMIT_OUTPUT_BYTES));
    let stderr_capture = tokio::spawn(capture_bounded(stderr, MAX_SUBMIT_OUTPUT_BYTES));

    match tokio::time::timeout(timeout, child.wait()).await {
        Ok(status) => {
            let status = status.expect("wait for local submit client");
            Ok(Output {
                status,
                stdout: join_capture(stdout_capture).await,
                stderr: join_capture(stderr_capture).await,
            })
        }
        Err(_) => {
            let kill_result = child.start_kill();
            let forced_status = child.wait().await;
            let stdout = join_capture(stdout_capture).await;
            let stderr = join_capture(stderr_capture).await;
            Err(format!(
                "timed out after {timeout:?}; kill_result={kill_result:?}; forced_status={forced_status:?}; stdout={:?}; stderr={:?}",
                String::from_utf8_lossy(&stdout),
                String::from_utf8_lossy(&stderr),
            ))
        }
    }
}

#[tokio::test]
async fn submit_timeout_kills_and_reaps_child() {
    let _process_test_guard = serialize_process_test().await;
    let child = tokio::process::Command::new("/bin/sleep")
        .arg("60")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn timeout fixture");

    let error = wait_for_submit_output(child, Duration::from_millis(50))
        .await
        .expect_err("sleep fixture must time out");
    assert!(error.contains("forced_status=Ok"), "{error}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sigterm_during_collector_wait_stops_cleanly() {
    let _process_test_guard = serialize_process_test().await;
    let directory = secure_directory();
    let collector = directory.path().join("missing-collector.sock");
    let submission = directory.path().join("waiting-submit.sock");
    let config = guardian_config(
        directory.path(),
        "waiting",
        &collector,
        &submission,
        &["/ip4/127.0.0.1/udp/0/quic-v1".to_owned()],
        None,
    );
    let mut service = ServiceProcess::spawn(&config);
    service.wait_for(SERVICE_EVENT_TIMEOUT, |event| {
        event["event"] == "waiting-for-collector"
    });

    assert!(service.terminate(SERVICE_EXIT_TIMEOUT).success());
    let stopped = service.wait_for(SERVICE_EVENT_TIMEOUT, |event| event["event"] == "stopped");
    assert_eq!(stopped["ready"], false);
    assert!(!submission.exists());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn broken_stdout_fails_without_blocking_the_service() {
    let _process_test_guard = serialize_process_test().await;
    let directory = secure_directory();
    let collector_path = directory.path().join("collector.sock");
    let _collector = bind_collector(&collector_path).await;
    let submission = directory.path().join("broken-output-submit.sock");
    let config = guardian_config(
        directory.path(),
        "broken-output",
        &collector_path,
        &submission,
        &["/ip4/127.0.0.1/udp/0/quic-v1".to_owned()],
        None,
    );
    let mut child = Command::new(BINARY)
        .args(["run", "--config"])
        .arg(&config)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn service with breakable stdout");
    drop(child.stdout.take().expect("capture service stdout"));

    let (status, stderr) = wait_for_child_exit(
        &mut child,
        SERVICE_EXIT_TIMEOUT,
        "service remained blocked after stdout closed",
    );
    assert!(
        !status.success(),
        "broken stdout must fail closed; status: {status}; stderr: {stderr:?}"
    );
}

fn guardian_config(
    directory: &Path,
    name: &str,
    collector_socket: &Path,
    submission_socket: &Path,
    listen_addresses: &[String],
    static_peer: Option<(&str, &str)>,
) -> PathBuf {
    let static_peers = static_peer.map_or_else(
        || "static_peers = []\n".to_owned(),
        |(peer, address)| {
            format!("[[static_peers]]\npeer_id = \"{peer}\"\naddress = \"{address}\"\n")
        },
    );
    let listeners = listen_addresses
        .iter()
        .map(|address| format!("\"{address}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let config = format!(
        "role = \"guardian\"\nidentity_path = \"{}\"\ncollector_socket = \"{}\"\nthreat_hint_socket = \"{}\"\nthreat_hint_v2_socket = \"{}\"\nthreat_hint_v2_trusted_network_id = \"testnet-10\"\nsubmission_socket = \"{}\"\nlisten_addresses = [{listeners}]\nhealth_interval_secs = 1\ningress_timeout_secs = 5\ncollector_startup_timeout_secs = 5\nshutdown_drain_timeout_secs = 5\n{static_peers}",
        directory.join(format!("{name}.identity")).display(),
        collector_socket.display(),
        directory.join(format!("{name}-threat-hint.sock")).display(),
        directory.join(format!("{name}-threat-hint-v2.sock")).display(),
        submission_socket.display(),
    );
    let path = directory.join(format!("{name}.toml"));
    write_owner_only(&path, config);
    path
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn separate_processes_relay_exact_ballot_and_shutdown_cleanly() {
    let _process_test_guard = serialize_process_test().await;
    let directory = secure_directory();
    let relay_config = directory.path().join("relay.toml");
    let relay_port_reservation = reserve_udp_port();
    let relay_port = relay_port_reservation
        .local_addr()
        .expect("read reserved local UDP address")
        .port();
    let relay_dial_address = format!("/ip4/127.0.0.1/udp/{relay_port}/quic-v1");
    write_owner_only(
        &relay_config,
        format!(
            "role = \"relay\"\nidentity_path = \"{}\"\nlisten_addresses = [\"/ip4/0.0.0.0/udp/{relay_port}/quic-v1\"]\nadvertise_addresses = [\"{relay_dial_address}\"]\nhealth_interval_secs = 1\nshutdown_drain_timeout_secs = 5\nallow_private_autonat_addresses = true\n",
            directory.path().join("relay.identity").display(),
        ),
    );
    let relay_preflight = preflight(&relay_config);
    assert_eq!(relay_preflight["schema_version"], 2);
    assert_eq!(relay_preflight["advertise_address_count"], 1);
    let relay_peer = relay_preflight["peer_id"]
        .as_str()
        .expect("relay peer id")
        .to_owned();
    drop(relay_port_reservation);
    let mut relay = ServiceProcess::spawn(&relay_config);
    let bootstrap = relay.wait_for(SERVICE_EVENT_TIMEOUT, |event| {
        event["event"] == "bootstrap-route"
    });
    assert_eq!(
        bootstrap["address"],
        format!("{relay_dial_address}/p2p/{relay_peer}")
    );
    assert_eq!(bootstrap["schema_version"], 2);
    assert_eq!(bootstrap["ready"], false);
    let relay_listening = relay.wait_for(SERVICE_EVENT_TIMEOUT, |event| {
        event["event"] == "listening" && event["ready"] == true
    });
    assert!(relay_listening["address"]
        .as_str()
        .expect("relay listen address")
        .contains(&relay_port.to_string()));

    let receiver_collector_path = directory.path().join("receiver-collector.sock");
    let sender_collector_path = directory.path().join("sender-collector.sock");
    let receiver_collector = bind_collector(&receiver_collector_path).await;
    let _sender_collector = bind_collector(&sender_collector_path).await;
    let receiver_submit = directory.path().join("receiver-submit.sock");
    let sender_submit = directory.path().join("sender-submit.sock");
    let reservation_address = format!("{relay_dial_address}/p2p/{relay_peer}/p2p-circuit");

    let receiver_config = guardian_config(
        directory.path(),
        "receiver",
        &receiver_collector_path,
        &receiver_submit,
        std::slice::from_ref(&reservation_address),
        None,
    );
    let receiver_preflight = preflight(&receiver_config);
    let receiver_peer = receiver_preflight["peer_id"]
        .as_str()
        .expect("receiver peer id")
        .to_owned();
    let mut receiver = ServiceProcess::spawn(&receiver_config);
    receiver.wait_for(RELAY_RESERVATION_TIMEOUT, |event| {
        event["event"] == "relay-reservation-accepted"
    });
    receiver.wait_for(SERVICE_EVENT_TIMEOUT, |event| event["ready"] == true);

    let receiver_route = format!("{reservation_address}/p2p/{receiver_peer}");
    let sender_listener = "/ip4/127.0.0.1/udp/0/quic-v1".to_owned();
    let sender_config = guardian_config(
        directory.path(),
        "sender",
        &sender_collector_path,
        &sender_submit,
        &[sender_listener],
        Some((&receiver_peer, &receiver_route)),
    );
    let sender_preflight = preflight(&sender_config);
    let sender_peer = sender_preflight["peer_id"]
        .as_str()
        .expect("sender peer id")
        .to_owned();
    let mut sender = ServiceProcess::spawn(&sender_config);
    sender.wait_for(SERVICE_EVENT_TIMEOUT, |event| {
        event["event"] == "listening" && event["ready"] == true
    });

    let ballot = b"separate-process exact Guardian ballot".to_vec();
    let ballot_path = directory.path().join("ballot.bin");
    write_owner_only(&ballot_path, &ballot);
    let (received_tx, mut received_rx) = oneshot::channel();
    let mut collector_task = tokio::spawn(collect_once(receiver_collector, received_tx));
    // Output is drained concurrently to avoid pipe backpressure. The timeout
    // path explicitly kills and waits for the child; kill_on_drop remains the
    // cancellation safeguard if the surrounding test future is dropped.
    let submit_child = tokio::process::Command::new(BINARY)
        .args(["submit", "--socket"])
        .arg(&sender_submit)
        .args(["--peer", &receiver_peer, "--ballot"])
        .arg(&ballot_path)
        .args(["--timeout-secs", SUBMIT_REQUEST_TIMEOUT_SECS])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn local submit client");
    let submit_output: Output = match wait_for_submit_output(submit_child, SUBMIT_PROCESS_TIMEOUT)
        .await
    {
        Ok(output) => output,
        Err(submit_error) => {
            tokio::time::sleep(Duration::from_millis(100)).await;
            let collector_result =
                tokio::time::timeout(Duration::from_secs(1), &mut collector_task).await;
            let received_result = received_rx.try_recv();
            panic!(
                "local submit client failed: {submit_error}; collector_result={collector_result:?}; received_result={received_result:?}; relay_events={:?}; receiver_events={:?}; sender_events={:?}",
                relay.drain_events(),
                receiver.drain_events(),
                sender.drain_events(),
            );
        }
    };
    assert!(
        submit_output.status.success(),
        "local submit failed: {}",
        String::from_utf8_lossy(&submit_output.stderr)
    );
    let submit_report: Value =
        serde_json::from_slice(&submit_output.stdout).expect("parse submit report");
    if submit_report["status"] != "accepted" {
        tokio::time::sleep(Duration::from_millis(100)).await;
        let collector_result =
            tokio::time::timeout(Duration::from_secs(1), &mut collector_task).await;
        let received_result = received_rx.try_recv();
        panic!(
            "local submit was not accepted: report={submit_report}; stderr={:?}; collector_result={collector_result:?}; received_result={received_result:?}; relay_events={:?}; receiver_events={:?}; sender_events={:?}",
            String::from_utf8_lossy(&submit_output.stderr),
            relay.drain_events(),
            receiver.drain_events(),
            sender.drain_events(),
        );
    }
    assert_eq!(submit_report["peer_id"], receiver_peer);
    let received_ballot = tokio::time::timeout(SERVICE_EVENT_TIMEOUT, &mut received_rx)
        .await
        .expect("collector evidence timed out")
        .expect("receive collector evidence");
    assert_eq!(received_ballot, ballot);
    tokio::time::timeout(SERVICE_EVENT_TIMEOUT, &mut collector_task)
        .await
        .expect("collector task timed out")
        .expect("collector task");

    relay.wait_for(SERVICE_EVENT_TIMEOUT, |event| {
        event["event"] == "circuit-accepted"
    });
    receiver.wait_for(SERVICE_EVENT_TIMEOUT, |event| {
        event["event"] == "inbound-processed" && event["status"] == "accepted"
    });
    sender.wait_for(SERVICE_EVENT_TIMEOUT, |event| {
        event["event"] == "outbound-ack" && event["status"] == "accepted"
    });

    assert!(sender.terminate(SERVICE_EXIT_TIMEOUT).success());
    assert!(receiver.terminate(SERVICE_EXIT_TIMEOUT).success());
    assert!(relay.terminate(SERVICE_EXIT_TIMEOUT).success());
    assert!(!sender_submit.exists());
    assert!(!receiver_submit.exists());
    assert_eq!(preflight(&relay_config)["peer_id"], relay_peer);
    assert_eq!(preflight(&receiver_config)["peer_id"], receiver_peer);
    assert_eq!(preflight(&sender_config)["peer_id"], sender_peer);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn separate_process_delivers_canonical_threat_hint_v2() {
    let _process_test_guard = serialize_process_test().await;
    let directory = secure_directory();
    let collector_path = directory.path().join("v2-receiver-collector.sock");
    let _collector = bind_collector(&collector_path).await;
    let v2_path = directory.path().join("v2-receiver-threat-hint-v2.sock");
    let v2_listener = bind_collector(&v2_path).await;
    let submission = directory.path().join("v2-receiver-submit.sock");
    let config = guardian_config(
        directory.path(),
        "v2-receiver",
        &collector_path,
        &submission,
        &["/ip4/127.0.0.1/udp/0/quic-v1".to_owned()],
        None,
    );
    let receiver_preflight = preflight(&config);
    let receiver_peer = receiver_preflight["peer_id"]
        .as_str()
        .expect("receiver peer id")
        .to_owned();
    let mut receiver = ServiceProcess::spawn(&config);
    let listening = receiver.wait_for(SERVICE_EVENT_TIMEOUT, |event| {
        event["event"] == "listening" && event["ready"] == true
    });
    let receiver_address = listening["address"]
        .as_str()
        .expect("receiver listen address")
        .to_owned();

    let (wire, network) = threat_hint_v2_vector_wire("base_review_required");
    assert_eq!(network, "testnet-10");
    let payload =
        prometheus_guardian_p2p::ThreatHintV2TransportPayload::parse_canonical(&wire, &network)
            .expect("valid vector payload");
    let (received_tx, received_rx) = oneshot::channel();
    let collector_task = tokio::spawn(collect_v2_once(v2_listener, wire.clone(), received_tx));

    let sender_config = prometheus_guardian_p2p::GuardianP2pConfig {
        request_timeout: Duration::from_secs(5),
        idle_connection_timeout: Duration::from_secs(5),
        static_peers: vec![prometheus_guardian_p2p::StaticPeer {
            peer_id: receiver_peer.parse().expect("receiver peer id parses"),
            address: receiver_address.parse().expect("receiver address parses"),
        }],
        threat_hint_v2_trusted_network_id: network,
        ..prometheus_guardian_p2p::GuardianP2pConfig::default()
    };
    let mut sender = prometheus_guardian_p2p::GuardianP2p::new(
        libp2p_identity::Keypair::generate_ed25519(),
        sender_config,
    )
    .expect("in-process sender initializes");
    sender
        .send_threat_hint_v2(
            receiver_peer.parse().expect("receiver peer id parses"),
            payload,
        )
        .expect("send canonical ThreatHint-v2");

    tokio::time::timeout(SERVICE_EVENT_TIMEOUT, async {
        loop {
            match sender.next_event().await {
                prometheus_guardian_p2p::TransportEvent::OutboundThreatHintV2Ack {
                    status, ..
                } => {
                    assert_eq!(
                        status,
                        prometheus_guardian_p2p::ThreatHintV2AckStatus::Accepted
                    );
                    break;
                }
                prometheus_guardian_p2p::TransportEvent::OutboundThreatHintV2Failure {
                    failure,
                    ..
                } => panic!("ThreatHint-v2 delivery failed: {failure:?}"),
                _ => {}
            }
        }
    })
    .await
    .expect("separate-process ThreatHint-v2 acknowledgement timed out");

    let received = tokio::time::timeout(SERVICE_EVENT_TIMEOUT, received_rx)
        .await
        .expect("v2 ingress evidence timed out")
        .expect("receive v2 ingress evidence");
    assert_eq!(received, wire);
    collector_task.await.expect("v2 ingress task");
    receiver.wait_for(SERVICE_EVENT_TIMEOUT, |event| {
        event["event"] == "inbound-threat-hint-v2-processed" && event["status"] == "accepted"
    });

    assert!(receiver.terminate(SERVICE_EXIT_TIMEOUT).success());
    assert!(!submission.exists());
    assert_eq!(preflight(&config)["peer_id"], receiver_peer);
}

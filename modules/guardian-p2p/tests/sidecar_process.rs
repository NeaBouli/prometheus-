#![cfg(unix)]

use std::{
    fs,
    io::{BufRead, BufReader},
    net::{Ipv4Addr, UdpSocket},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    sync::mpsc::{self, Receiver},
    thread,
    time::{Duration, Instant},
};

use rustix::process::{kill_process, Pid, Signal};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixListener,
    sync::oneshot,
};

use prometheus_guardian_p2p::MAX_BALLOT_BYTES;

const BINARY: &str = env!("CARGO_BIN_EXE_prometheus-guardian-p2p");

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
            let event = self
                .events
                .recv_timeout(remaining)
                .unwrap_or_else(|_| panic!("service event timed out after observing {observed:?}"));
            if predicate(&event) {
                return event;
            }
            observed.push(event["event"].clone());
        }
    }

    fn terminate(&mut self, timeout: Duration) -> ExitStatus {
        let pid = Pid::from_raw(self.child.id() as i32).expect("non-zero child process id");
        kill_process(pid, Signal::TERM).expect("send SIGTERM");
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(status) = self.child.try_wait().expect("poll service exit") {
                return status;
            }
            assert!(
                Instant::now() < deadline,
                "service did not stop after SIGTERM"
            );
            thread::sleep(Duration::from_millis(20));
        }
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

fn available_udp_port() -> u16 {
    UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .expect("reserve local UDP port")
        .local_addr()
        .expect("read local UDP address")
        .port()
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
    received_tx.send(ballot).expect("record received ballot");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sigterm_during_collector_wait_stops_cleanly() {
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
    service.wait_for(Duration::from_secs(5), |event| {
        event["event"] == "waiting-for-collector"
    });

    assert!(service.terminate(Duration::from_secs(5)).success());
    let stopped = service.wait_for(Duration::from_secs(5), |event| event["event"] == "stopped");
    assert_eq!(stopped["ready"], false);
    assert!(!submission.exists());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn broken_stdout_fails_without_blocking_the_service() {
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
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn service with breakable stdout");
    drop(child.stdout.take().expect("capture service stdout"));

    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = child.try_wait().expect("poll service exit") {
            assert!(!status.success(), "broken stdout must fail closed");
            break;
        }
        assert!(
            Instant::now() < deadline,
            "service remained blocked after stdout closed"
        );
        thread::sleep(Duration::from_millis(20));
    }
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
        "role = \"guardian\"\nidentity_path = \"{}\"\ncollector_socket = \"{}\"\nsubmission_socket = \"{}\"\nlisten_addresses = [{listeners}]\nhealth_interval_secs = 1\ningress_timeout_secs = 5\ncollector_startup_timeout_secs = 5\nshutdown_drain_timeout_secs = 5\n{static_peers}",
        directory.join(format!("{name}.identity")).display(),
        collector_socket.display(),
        submission_socket.display(),
    );
    let path = directory.join(format!("{name}.toml"));
    write_owner_only(&path, config);
    path
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn separate_processes_relay_exact_ballot_and_shutdown_cleanly() {
    let directory = secure_directory();
    let relay_config = directory.path().join("relay.toml");
    let relay_port = available_udp_port();
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
    let mut relay = ServiceProcess::spawn(&relay_config);
    let bootstrap = relay.wait_for(Duration::from_secs(10), |event| {
        event["event"] == "bootstrap-route"
    });
    assert_eq!(
        bootstrap["address"],
        format!("{relay_dial_address}/p2p/{relay_peer}")
    );
    assert_eq!(bootstrap["schema_version"], 2);
    assert_eq!(bootstrap["ready"], false);
    let relay_listening = relay.wait_for(Duration::from_secs(10), |event| {
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
    receiver.wait_for(Duration::from_secs(15), |event| {
        event["event"] == "relay-reservation-accepted"
    });
    receiver.wait_for(Duration::from_secs(10), |event| event["ready"] == true);

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
    sender.wait_for(Duration::from_secs(10), |event| {
        event["event"] == "listening" && event["ready"] == true
    });

    let ballot = b"separate-process exact Guardian ballot".to_vec();
    let ballot_path = directory.path().join("ballot.bin");
    write_owner_only(&ballot_path, &ballot);
    let (received_tx, received_rx) = oneshot::channel();
    let collector_task = tokio::spawn(collect_once(receiver_collector, received_tx));
    let submit_output = tokio::process::Command::new(BINARY)
        .args(["submit", "--socket"])
        .arg(&sender_submit)
        .args(["--peer", &receiver_peer, "--ballot"])
        .arg(&ballot_path)
        .args(["--timeout-secs", "10"])
        .output()
        .await
        .expect("run local submit client");
    assert!(
        submit_output.status.success(),
        "local submit failed: {}",
        String::from_utf8_lossy(&submit_output.stderr)
    );
    let submit_report: Value =
        serde_json::from_slice(&submit_output.stdout).expect("parse submit report");
    assert_eq!(submit_report["status"], "accepted");
    assert_eq!(submit_report["peer_id"], receiver_peer);
    assert_eq!(
        received_rx.await.expect("receive collector evidence"),
        ballot
    );
    collector_task.await.expect("collector task");

    relay.wait_for(Duration::from_secs(10), |event| {
        event["event"] == "circuit-accepted"
    });
    receiver.wait_for(Duration::from_secs(10), |event| {
        event["event"] == "inbound-processed" && event["status"] == "accepted"
    });
    sender.wait_for(Duration::from_secs(10), |event| {
        event["event"] == "outbound-ack" && event["status"] == "accepted"
    });

    assert!(sender.terminate(Duration::from_secs(10)).success());
    assert!(receiver.terminate(Duration::from_secs(10)).success());
    assert!(relay.terminate(Duration::from_secs(10)).success());
    assert!(!sender_submit.exists());
    assert!(!receiver_submit.exists());
    assert_eq!(preflight(&relay_config)["peer_id"], relay_peer);
    assert_eq!(preflight(&receiver_config)["peer_id"], receiver_peer);
    assert_eq!(preflight(&sender_config)["peer_id"], sender_peer);
}

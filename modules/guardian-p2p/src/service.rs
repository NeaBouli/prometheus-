//! Operated Guardian P2P sidecar and relay process orchestration.

use std::{
    collections::HashMap,
    fs::File,
    future::Future,
    io::{Read, Write},
    path::{Component, Path, PathBuf},
    pin::Pin,
    str::FromStr,
    sync::mpsc::{self, SyncSender, TrySendError},
    thread,
    time::Duration,
};

use libp2p_core::Multiaddr;
use libp2p_identity::{Keypair, PeerId};
use libp2p_request_response::OutboundRequestId;
use rustix::{
    fs::{self, FileType, Mode, OFlags},
    process,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::{
    sync::{oneshot, watch},
    task::JoinHandle,
    time::{self, MissedTickBehavior},
};

use crate::{
    ingress::{IngressError, UnixBallotIngress},
    local_submit::{
        validate_submission_path, LocalSubmission, LocalSubmissionError, LocalSubmissionResult,
        SubmissionServer, MAX_CONCURRENT_SUBMISSIONS,
    },
    relay_service::{RelayService, RelayServiceConfig, RelayServiceEvent},
    threat_hint_ingress::{ThreatHintIngressError, UnixThreatHintIngress},
    transport_identity::{load_or_create_transport_identity, IdentityError},
    AckStatus, ConnectionPath, GuardianP2p, GuardianP2pConfig, HolePunchOutcome, NatReachability,
    RequestFailure, StaticPeer, TransportError, TransportEvent,
};

const MAX_CONFIG_BYTES: usize = 64 * 1024;
const MAX_HEALTH_INTERVAL_SECS: u64 = 3_600;
const MAX_COLLECTOR_STARTUP_SECS: u64 = 5 * 60;
const MAX_SHUTDOWN_DRAIN_SECS: u64 = 60;
const MAX_LOCAL_TIMEOUT_SECS: u64 = 60;
const OPERATOR_OUTPUT_QUEUE_CAPACITY: usize = 256;

type ShutdownFuture = Pin<Box<dyn Future<Output = Result<(), std::io::Error>> + Send>>;

/// Strict role selected by an operated configuration.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ServiceRole {
    Guardian,
    Relay,
}

/// Strict role-specific TOML configuration.
#[derive(Debug, Deserialize)]
#[serde(tag = "role", rename_all = "kebab-case")]
pub enum ServiceConfig {
    Guardian(GuardianServiceConfig),
    Relay(RelayServiceFileConfig),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuardianServiceConfig {
    identity_path: PathBuf,
    collector_socket: PathBuf,
    threat_hint_socket: PathBuf,
    submission_socket: PathBuf,
    listen_addresses: Vec<String>,
    #[serde(default)]
    static_peers: Vec<PeerRoute>,
    #[serde(default)]
    autonat_servers: Vec<PeerRoute>,
    #[serde(default = "default_health_interval_secs")]
    health_interval_secs: u64,
    #[serde(default = "default_ingress_timeout_secs")]
    ingress_timeout_secs: u64,
    #[serde(default = "default_collector_startup_secs")]
    collector_startup_timeout_secs: u64,
    #[serde(default = "default_shutdown_drain_secs")]
    shutdown_drain_timeout_secs: u64,
    #[serde(default = "default_local_submission_limit")]
    max_local_submissions: usize,
    #[serde(default)]
    allow_private_autonat_addresses: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayServiceFileConfig {
    identity_path: PathBuf,
    listen_addresses: Vec<String>,
    #[serde(default)]
    advertise_addresses: Vec<String>,
    #[serde(default = "default_health_interval_secs")]
    health_interval_secs: u64,
    #[serde(default = "default_shutdown_drain_secs")]
    shutdown_drain_timeout_secs: u64,
    #[serde(default)]
    allow_private_autonat_addresses: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PeerRoute {
    peer_id: String,
    address: String,
}

/// Validated runtime state plus the persistent transport identity.
pub enum PreparedService {
    Guardian(Box<PreparedGuardian>),
    Relay(Box<PreparedRelay>),
}

pub struct PreparedGuardian {
    keypair: Keypair,
    collector_socket: PathBuf,
    threat_hint_socket: PathBuf,
    submission_socket: PathBuf,
    transport: GuardianP2pConfig,
    health_interval: Duration,
    ingress_timeout: Duration,
    collector_startup_timeout: Duration,
    shutdown_drain_timeout: Duration,
    max_local_submissions: usize,
}

pub struct PreparedRelay {
    keypair: Keypair,
    relay: RelayServiceConfig,
    health_interval: Duration,
    shutdown_drain_timeout: Duration,
}

/// Data-minimal result of a network-free preflight.
#[derive(Debug, Serialize)]
pub struct PreflightReport {
    schema_version: u8,
    service: &'static str,
    status: &'static str,
    role: ServiceRole,
    peer_id: String,
    listener_count: usize,
    advertise_address_count: usize,
    static_peer_count: usize,
    autonat_server_count: usize,
    identity_storage: &'static str,
    collector_boundary: &'static str,
    threat_hint_boundary: &'static str,
    submission_boundary: &'static str,
    public_multi_host_evidence: &'static str,
}

/// Stable JSON-line operator record. It never contains ballot or collector bytes.
#[derive(Debug, Serialize)]
struct OperatorRecord {
    schema_version: u8,
    service: &'static str,
    role: ServiceRole,
    event: &'static str,
    ready: bool,
    peer_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    remote_peer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    connections: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pending_inbound: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pending_outbound: Option<usize>,
}

#[derive(Clone, Debug)]
struct OutputFailure {
    kind: std::io::ErrorKind,
    message: String,
}

impl OutputFailure {
    fn into_error(self) -> std::io::Error {
        std::io::Error::new(self.kind, self.message)
    }
}

struct OperatorOutput {
    sender: Option<SyncSender<Vec<u8>>>,
    failure: watch::Receiver<Option<OutputFailure>>,
    completed: oneshot::Receiver<()>,
}

impl OperatorOutput {
    fn start() -> Result<Self, ServiceError> {
        let (sender, receiver) = mpsc::sync_channel::<Vec<u8>>(OPERATOR_OUTPUT_QUEUE_CAPACITY);
        let (failure_tx, failure) = watch::channel(None);
        let (completed_tx, completed) = oneshot::channel();
        thread::Builder::new()
            .name("guardian-operator-output".to_owned())
            .spawn(move || {
                let stdout = std::io::stdout();
                let mut stdout = stdout.lock();
                while let Ok(record) = receiver.recv() {
                    if let Err(error) = stdout.write_all(&record).and_then(|()| stdout.flush()) {
                        failure_tx.send_replace(Some(OutputFailure {
                            kind: error.kind(),
                            message: error.to_string(),
                        }));
                        break;
                    }
                }
                let _ = completed_tx.send(());
            })
            .map_err(ServiceError::Io)?;
        Ok(Self {
            sender: Some(sender),
            failure,
            completed,
        })
    }

    fn emit(&self, record: OperatorRecord) -> Result<(), ServiceError> {
        self.check_failure()?;
        let mut encoded = serde_json::to_vec(&record).map_err(ServiceError::Json)?;
        encoded.push(b'\n');
        match self
            .sender
            .as_ref()
            .ok_or(ServiceError::OutputTask)?
            .try_send(encoded)
        {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(_)) => Err(ServiceError::OutputBackpressure),
            Err(TrySendError::Disconnected(_)) => {
                self.check_failure().and(Err(ServiceError::OutputTask))
            }
        }
    }

    async fn failed(&mut self) -> ServiceError {
        loop {
            if let Some(failure) = self.failure.borrow().clone() {
                return ServiceError::Io(failure.into_error());
            }
            if self.failure.changed().await.is_err() {
                return ServiceError::OutputTask;
            }
        }
    }

    fn check_failure(&self) -> Result<(), ServiceError> {
        match self.failure.borrow().clone() {
            Some(failure) => Err(ServiceError::Io(failure.into_error())),
            None => Ok(()),
        }
    }

    async fn shutdown(mut self, timeout: Duration) -> Result<(), ServiceError> {
        self.sender.take();
        match time::timeout(timeout, &mut self.completed).await {
            Ok(Ok(())) => self.check_failure(),
            Ok(Err(_)) => Err(ServiceError::OutputTask),
            Err(_) => Err(ServiceError::OutputShutdownTimeout),
        }
    }
}

impl ServiceConfig {
    /// Reads owner-only TOML without following the config file or direct parent symlinks.
    pub fn from_toml_file(path: &Path) -> Result<Self, ServiceError> {
        let contents = read_owner_only_config(path)?;
        let text = std::str::from_utf8(&contents)
            .map_err(|_| ServiceError::InvalidConfig("config must be UTF-8 TOML"))?;
        toml::from_str(text).map_err(|_| ServiceError::InvalidConfig("invalid service config"))
    }

    /// Validates every path, route and bound before creating network listeners.
    pub fn prepare(self) -> Result<PreparedService, ServiceError> {
        match self {
            Self::Guardian(config) => config
                .prepare()
                .map(Box::new)
                .map(PreparedService::Guardian),
            Self::Relay(config) => config.prepare().map(Box::new).map(PreparedService::Relay),
        }
    }
}

impl GuardianServiceConfig {
    fn prepare(self) -> Result<PreparedGuardian, ServiceError> {
        validate_absolute_file_path(&self.identity_path)?;
        validate_absolute_file_path(&self.collector_socket)?;
        validate_absolute_file_path(&self.threat_hint_socket)?;
        validate_absolute_file_path(&self.submission_socket)?;
        if self.identity_path == self.collector_socket
            || self.identity_path == self.threat_hint_socket
            || self.identity_path == self.submission_socket
            || self.collector_socket == self.threat_hint_socket
            || self.collector_socket == self.submission_socket
            || self.threat_hint_socket == self.submission_socket
        {
            return Err(ServiceError::InvalidConfig(
                "identity, collector, ThreatHint and submission paths must be distinct",
            ));
        }
        if self.listen_addresses.is_empty() {
            return Err(ServiceError::InvalidConfig(
                "guardian service requires at least one listener",
            ));
        }
        validate_submission_path(&self.submission_socket)?;
        let ingress_timeout = bounded_seconds(
            self.ingress_timeout_secs,
            MAX_LOCAL_TIMEOUT_SECS,
            "ingress timeout is out of bounds",
        )?;
        UnixBallotIngress::configured(&self.collector_socket, ingress_timeout)?;
        UnixThreatHintIngress::configured(&self.threat_hint_socket, ingress_timeout)?;
        let collector_startup_timeout = bounded_seconds(
            self.collector_startup_timeout_secs,
            MAX_COLLECTOR_STARTUP_SECS,
            "collector startup timeout is out of bounds",
        )?;
        let health_interval = bounded_seconds(
            self.health_interval_secs,
            MAX_HEALTH_INTERVAL_SECS,
            "health interval is out of bounds",
        )?;
        let shutdown_drain_timeout = bounded_seconds(
            self.shutdown_drain_timeout_secs,
            MAX_SHUTDOWN_DRAIN_SECS,
            "shutdown drain timeout is out of bounds",
        )?;
        if shutdown_drain_timeout < ingress_timeout {
            return Err(ServiceError::InvalidConfig(
                "shutdown drain timeout must cover ingress timeout",
            ));
        }
        if !(1..=MAX_CONCURRENT_SUBMISSIONS).contains(&self.max_local_submissions) {
            return Err(ServiceError::InvalidConfig(
                "local submission limit is out of bounds",
            ));
        }

        let mut transport = GuardianP2pConfig {
            listen_addresses: parse_addresses(&self.listen_addresses)?,
            static_peers: parse_routes(&self.static_peers)?,
            autonat_servers: parse_routes(&self.autonat_servers)?,
            autonat_allow_private_addresses: self.allow_private_autonat_addresses,
            ..GuardianP2pConfig::default()
        };
        transport.request_timeout = ingress_timeout;
        transport.validate()?;
        let keypair = load_or_create_transport_identity(&self.identity_path)?;

        Ok(PreparedGuardian {
            keypair,
            collector_socket: self.collector_socket,
            threat_hint_socket: self.threat_hint_socket,
            submission_socket: self.submission_socket,
            transport,
            health_interval,
            ingress_timeout,
            collector_startup_timeout,
            shutdown_drain_timeout,
            max_local_submissions: self.max_local_submissions,
        })
    }
}

impl RelayServiceFileConfig {
    fn prepare(self) -> Result<PreparedRelay, ServiceError> {
        validate_absolute_file_path(&self.identity_path)?;
        if self.listen_addresses.is_empty() {
            return Err(ServiceError::InvalidConfig(
                "relay service requires at least one listener",
            ));
        }
        let health_interval = bounded_seconds(
            self.health_interval_secs,
            MAX_HEALTH_INTERVAL_SECS,
            "health interval is out of bounds",
        )?;
        let shutdown_drain_timeout = bounded_seconds(
            self.shutdown_drain_timeout_secs,
            MAX_SHUTDOWN_DRAIN_SECS,
            "shutdown drain timeout is out of bounds",
        )?;
        let relay = RelayServiceConfig {
            listen_addresses: parse_addresses(&self.listen_addresses)?,
            advertise_addresses: parse_canonical_addresses(&self.advertise_addresses)?,
            allow_private_autonat_addresses: self.allow_private_autonat_addresses,
            ..RelayServiceConfig::default()
        };
        relay.validate()?;
        let keypair = load_or_create_transport_identity(&self.identity_path)?;
        Ok(PreparedRelay {
            keypair,
            relay,
            health_interval,
            shutdown_drain_timeout,
        })
    }
}

impl PreparedService {
    /// Builds a public, path-free preflight report.
    pub fn preflight_report(&self) -> PreflightReport {
        match self {
            Self::Guardian(service) => PreflightReport {
                schema_version: 2,
                service: "prometheus-guardian-p2p",
                status: "ready-for-operated-sidecar",
                role: ServiceRole::Guardian,
                peer_id: service.keypair.public().to_peer_id().to_string(),
                listener_count: service.transport.listen_addresses.len(),
                advertise_address_count: 0,
                static_peer_count: service.transport.static_peers.len(),
                autonat_server_count: service.transport.autonat_servers.len(),
                identity_storage: "owner-only-persistent-ed25519",
                collector_boundary: "owner-only-af-unix",
                threat_hint_boundary: "owner-only-af-unix-fail-closed",
                submission_boundary: "owner-only-af-unix",
                public_multi_host_evidence: "not-proven",
            },
            Self::Relay(service) => PreflightReport {
                schema_version: 2,
                service: "prometheus-guardian-p2p",
                status: "ready-for-operated-relay",
                role: ServiceRole::Relay,
                peer_id: service.keypair.public().to_peer_id().to_string(),
                listener_count: service.relay.listen_addresses.len(),
                advertise_address_count: service.relay.advertise_addresses.len(),
                static_peer_count: 0,
                autonat_server_count: 0,
                identity_storage: "owner-only-persistent-ed25519",
                collector_boundary: "not-applicable",
                threat_hint_boundary: "not-applicable",
                submission_boundary: "not-applicable",
                public_multi_host_evidence: "not-proven",
            },
        }
    }
}

/// Runs the prepared service until SIGINT or SIGTERM.
pub async fn run_service(service: PreparedService) -> Result<(), ServiceError> {
    let output_timeout = match &service {
        PreparedService::Guardian(service) => service.shutdown_drain_timeout,
        PreparedService::Relay(service) => service.shutdown_drain_timeout,
    };
    // Install process signal listeners before any operator record can report readiness.
    let shutdown = shutdown_signal().map_err(ServiceError::Signal)?;
    let mut output = OperatorOutput::start()?;
    let service_result = match service {
        PreparedService::Guardian(service) => run_guardian(*service, shutdown, &mut output).await,
        PreparedService::Relay(service) => run_relay(*service, shutdown, &mut output).await,
    };
    let output_result = output.shutdown(output_timeout).await;
    match service_result {
        Err(error) => Err(error),
        Ok(()) => output_result,
    }
}

async fn run_guardian(
    service: PreparedGuardian,
    mut shutdown: ShutdownFuture,
    output: &mut OperatorOutput,
) -> Result<(), ServiceError> {
    let peer_id = service.keypair.public().to_peer_id();
    let ingress =
        UnixBallotIngress::configured(&service.collector_socket, service.ingress_timeout)?;
    let threat_hint_ingress =
        UnixThreatHintIngress::configured(&service.threat_hint_socket, service.ingress_timeout)?;
    output.emit(OperatorRecord::basic(
        ServiceRole::Guardian,
        "waiting-for-collector",
        false,
        peer_id,
    ))?;
    tokio::select! {
        result = ingress.wait_ready(
            service.collector_startup_timeout,
            Duration::from_millis(100),
        ) => result?,
        error = output.failed() => return Err(error),
        signal = &mut shutdown => {
            signal.map_err(ServiceError::Signal)?;
            output.emit(OperatorRecord::basic(
                ServiceRole::Guardian,
                "stopped",
                false,
                peer_id,
            ))?;
            return Ok(());
        }
    }

    let mut node = GuardianP2p::new(service.keypair, service.transport)?;
    let (submission_server, mut submissions) = SubmissionServer::bind(
        &service.submission_socket,
        service.max_local_submissions,
        service.ingress_timeout,
    )?;
    let (submission_shutdown_tx, submission_shutdown_rx) = oneshot::channel();
    let submission_task = tokio::spawn(submission_server.run(submission_shutdown_rx));
    let mut pending_submissions: HashMap<
        OutboundRequestId,
        oneshot::Sender<LocalSubmissionResult>,
    > = HashMap::new();
    let mut connections = 0_usize;
    let mut health = time::interval(service.health_interval);
    health.set_missed_tick_behavior(MissedTickBehavior::Skip);
    health.tick().await;
    output.emit(OperatorRecord::basic(
        ServiceRole::Guardian,
        "starting",
        false,
        peer_id,
    ))?;

    loop {
        tokio::select! {
            error = output.failed() => return Err(error),
            signal = &mut shutdown => {
                signal.map_err(ServiceError::Signal)?;
                break;
            }
            _ = health.tick() => {
                let (pending_inbound, pending_outbound) = node.pending_work();
                let mut record = OperatorRecord::basic(
                    ServiceRole::Guardian,
                    "health",
                    node.is_ready(),
                    peer_id,
                );
                record.connections = Some(connections);
                record.pending_inbound = Some(pending_inbound);
                record.pending_outbound = Some(pending_outbound);
                output.emit(record)?;
            }
            submission = submissions.recv() => {
                let Some(submission) = submission else {
                    return Err(ServiceError::Submission(LocalSubmissionError::TransportFailure));
                };
                admit_submission(&mut node, &mut pending_submissions, submission);
            }
            event = node.next_verified_sidecar_event(&ingress, &threat_hint_ingress) => {
                let event = event?;
                update_connection_count(&event, &mut connections);
                complete_local_submission(&event, &mut pending_submissions);
                output.emit(guardian_event_record(&event, node.is_ready(), peer_id, connections))?;
            }
        }
    }

    let _ = submission_shutdown_tx.send(());
    submissions.close();
    while let Ok(submission) = submissions.try_recv() {
        let _ = submission.response.send(LocalSubmissionResult::Busy);
    }
    node.shutdown_listeners();
    let deadline = time::Instant::now() + service.shutdown_drain_timeout;
    while node.pending_work() != (0, 0) && time::Instant::now() < deadline {
        match time::timeout_at(
            deadline,
            node.next_verified_sidecar_event(&ingress, &threat_hint_ingress),
        )
        .await
        {
            Ok(Ok(event)) => {
                update_connection_count(&event, &mut connections);
                complete_local_submission(&event, &mut pending_submissions);
                output.emit(guardian_event_record(
                    &event,
                    node.is_ready(),
                    peer_id,
                    connections,
                ))?;
            }
            Ok(Err(error)) => return Err(ServiceError::Transport(error)),
            Err(_) => break,
        }
    }
    for (_, response) in pending_submissions.drain() {
        let _ = response.send(LocalSubmissionResult::TransportFailure);
    }
    let (pending_inbound, pending_outbound) = node.pending_work();
    let mut stopping = OperatorRecord::basic(ServiceRole::Guardian, "stopped", false, peer_id);
    stopping.connections = Some(connections);
    stopping.pending_inbound = Some(pending_inbound);
    stopping.pending_outbound = Some(pending_outbound);
    await_submission_server(submission_task, service.shutdown_drain_timeout).await?;
    output.emit(stopping)
}

async fn run_relay(
    service: PreparedRelay,
    mut shutdown: ShutdownFuture,
    output: &mut OperatorOutput,
) -> Result<(), ServiceError> {
    let mut relay = RelayService::new(service.keypair, service.relay)?;
    let peer_id = relay.local_peer_id();
    let mut health = time::interval(service.health_interval);
    health.set_missed_tick_behavior(MissedTickBehavior::Skip);
    health.tick().await;
    let mut connections = 0_usize;
    output.emit(OperatorRecord::basic(
        ServiceRole::Relay,
        "starting",
        false,
        peer_id,
    ))?;

    loop {
        tokio::select! {
            error = output.failed() => return Err(error),
            signal = &mut shutdown => {
                signal.map_err(ServiceError::Signal)?;
                break;
            }
            _ = health.tick() => {
                let mut record = OperatorRecord::basic(
                    ServiceRole::Relay,
                    "health",
                    relay.is_ready(),
                    peer_id,
                );
                record.connections = Some(connections);
                output.emit(record)?;
            }
            event = relay.next_event() => {
                update_relay_connection_count(&event, &mut connections);
                output.emit(relay_event_record(&event, relay.is_ready(), peer_id, connections))?;
            }
        }
    }

    relay.shutdown_listeners();
    let deadline = time::Instant::now() + service.shutdown_drain_timeout;
    while relay.is_ready() && time::Instant::now() < deadline {
        match time::timeout_at(deadline, relay.next_event()).await {
            Ok(event) => {
                update_relay_connection_count(&event, &mut connections);
                output.emit(relay_event_record(
                    &event,
                    relay.is_ready(),
                    peer_id,
                    connections,
                ))?;
            }
            Err(_) => break,
        }
    }
    let mut stopped = OperatorRecord::basic(ServiceRole::Relay, "stopped", false, peer_id);
    stopped.connections = Some(connections);
    output.emit(stopped)
}

fn admit_submission(
    node: &mut GuardianP2p,
    pending: &mut HashMap<OutboundRequestId, oneshot::Sender<LocalSubmissionResult>>,
    submission: LocalSubmission,
) {
    match node.send_ballot(submission.peer, submission.ballot) {
        Ok(request_id) => {
            pending.insert(request_id, submission.response);
        }
        Err(TransportError::OutboundBusy { .. }) => {
            let _ = submission.response.send(LocalSubmissionResult::Busy);
        }
        Err(_) => {
            let _ = submission
                .response
                .send(LocalSubmissionResult::TransportFailure);
        }
    }
}

fn complete_local_submission(
    event: &TransportEvent,
    pending: &mut HashMap<OutboundRequestId, oneshot::Sender<LocalSubmissionResult>>,
) {
    match event {
        TransportEvent::OutboundAck {
            request_id, status, ..
        } => {
            if let Some(response) = pending.remove(request_id) {
                let result = match status {
                    AckStatus::Accepted => LocalSubmissionResult::Accepted,
                    AckStatus::Duplicate => LocalSubmissionResult::Duplicate,
                    AckStatus::Rejected => LocalSubmissionResult::Rejected,
                    AckStatus::Busy => LocalSubmissionResult::Busy,
                };
                let _ = response.send(result);
            }
        }
        TransportEvent::OutboundFailure { request_id, .. } => {
            if let Some(response) = pending.remove(request_id) {
                let _ = response.send(LocalSubmissionResult::TransportFailure);
            }
        }
        _ => {}
    }
}

fn update_connection_count(event: &TransportEvent, connections: &mut usize) {
    match event {
        TransportEvent::ConnectionEstablished { .. } => {
            *connections = connections.saturating_add(1)
        }
        TransportEvent::ConnectionClosed { .. } => *connections = connections.saturating_sub(1),
        _ => {}
    }
}

fn update_relay_connection_count(event: &RelayServiceEvent, connections: &mut usize) {
    match event {
        RelayServiceEvent::ConnectionEstablished { .. } => {
            *connections = connections.saturating_add(1)
        }
        RelayServiceEvent::ConnectionClosed { .. } => *connections = connections.saturating_sub(1),
        _ => {}
    }
}

fn guardian_event_record(
    event: &TransportEvent,
    ready: bool,
    local_peer: PeerId,
    connections: usize,
) -> OperatorRecord {
    let mut record = OperatorRecord::basic(
        ServiceRole::Guardian,
        guardian_event_name(event),
        ready,
        local_peer,
    );
    record.connections = Some(connections);
    match event {
        TransportEvent::Listening { address }
        | TransportEvent::ListenerClosed { address, .. }
        | TransportEvent::ListenerFailed { address } => record.address = Some(address.to_string()),
        TransportEvent::InboundBallot { peer, .. }
        | TransportEvent::InboundProcessed { peer, .. }
        | TransportEvent::InboundThreatHint { peer, .. }
        | TransportEvent::InboundThreatHintProcessed { peer, .. }
        | TransportEvent::OutboundAck { peer, .. }
        | TransportEvent::OutboundFailure { peer, .. }
        | TransportEvent::OutboundThreatHintAck { peer, .. }
        | TransportEvent::OutboundThreatHintFailure { peer, .. }
        | TransportEvent::ConnectionEstablished { peer, .. }
        | TransportEvent::ConnectionClosed { peer, .. }
        | TransportEvent::HolePunchFinished { peer, .. } => {
            record.remote_peer = Some(peer.to_string())
        }
        TransportEvent::RelayReservationAccepted { relay_peer, .. }
        | TransportEvent::RelayOutboundCircuit { relay_peer } => {
            record.remote_peer = Some(relay_peer.to_string())
        }
        TransportEvent::RelayInboundCircuit { source_peer } => {
            record.remote_peer = Some(source_peer.to_string())
        }
        _ => {}
    }
    match event {
        TransportEvent::InboundProcessed { status, .. }
        | TransportEvent::OutboundAck { status, .. } => record.status = Some(status.as_str()),
        TransportEvent::InboundThreatHintProcessed { status, .. }
        | TransportEvent::OutboundThreatHintAck { status, .. } => {
            record.status = Some(status.as_str())
        }
        TransportEvent::OutboundFailure { failure, .. } => {
            record.status = Some(request_failure_name(*failure))
        }
        TransportEvent::OutboundThreatHintFailure { failure, .. } => {
            record.status = Some(request_failure_name(*failure))
        }
        TransportEvent::NatStatusChanged { new, .. } => record.status = Some(nat_name(*new)),
        TransportEvent::HolePunchFinished { outcome, .. } => {
            record.status = Some(hole_punch_name(*outcome))
        }
        TransportEvent::ConnectionEstablished { path, .. }
        | TransportEvent::ConnectionClosed { path, .. }
        | TransportEvent::ExternalAddressConfirmed { path } => record.path = Some(path_name(*path)),
        TransportEvent::ListenerClosed { failed, .. } => {
            record.status = Some(if *failed { "failed" } else { "closed" })
        }
        _ => {}
    }
    record
}

fn relay_event_record(
    event: &RelayServiceEvent,
    ready: bool,
    local_peer: PeerId,
    connections: usize,
) -> OperatorRecord {
    let mut record = OperatorRecord::basic(
        ServiceRole::Relay,
        relay_event_name(event),
        ready,
        local_peer,
    );
    record.connections = Some(connections);
    match event {
        RelayServiceEvent::Listening { address }
        | RelayServiceEvent::BootstrapRoute { address }
        | RelayServiceEvent::ListenerClosed { address, .. }
        | RelayServiceEvent::ListenerFailed { address } => {
            record.address = Some(address.to_string())
        }
        RelayServiceEvent::ConnectionEstablished { peer, path }
        | RelayServiceEvent::ConnectionClosed { peer, path, .. } => {
            record.remote_peer = Some(peer.to_string());
            record.path = Some(path_name(*path));
        }
        RelayServiceEvent::ReservationAccepted { peer, .. }
        | RelayServiceEvent::ReservationClosed { peer } => {
            record.remote_peer = Some(peer.to_string())
        }
        RelayServiceEvent::CircuitAccepted { source, .. }
        | RelayServiceEvent::CircuitClosed { source, .. } => {
            record.remote_peer = Some(source.to_string())
        }
    }
    match event {
        RelayServiceEvent::ListenerClosed { failed, .. }
        | RelayServiceEvent::ConnectionClosed { failed, .. }
        | RelayServiceEvent::CircuitClosed { failed, .. } => {
            record.status = Some(if *failed { "failed" } else { "closed" })
        }
        _ => {}
    }
    record
}

fn guardian_event_name(event: &TransportEvent) -> &'static str {
    match event {
        TransportEvent::Listening { .. } => "listening",
        TransportEvent::ListenerClosed { .. } => "listener-closed",
        TransportEvent::ListenerFailed { .. } => "listener-failed",
        TransportEvent::InboundBallot { .. } => "inbound-ballot",
        TransportEvent::InboundProcessed { .. } => "inbound-processed",
        TransportEvent::InboundThreatHint { .. } => "inbound-threat-hint",
        TransportEvent::InboundThreatHintProcessed { .. } => "inbound-threat-hint-processed",
        TransportEvent::OutboundAck { .. } => "outbound-ack",
        TransportEvent::OutboundFailure { .. } => "outbound-failure",
        TransportEvent::OutboundThreatHintAck { .. } => "outbound-threat-hint-ack",
        TransportEvent::OutboundThreatHintFailure { .. } => "outbound-threat-hint-failure",
        TransportEvent::ConnectionEstablished { .. } => "connection-established",
        TransportEvent::ConnectionClosed { .. } => "connection-closed",
        TransportEvent::RelayReservationAccepted { .. } => "relay-reservation-accepted",
        TransportEvent::RelayOutboundCircuit { .. } => "relay-outbound-circuit",
        TransportEvent::RelayInboundCircuit { .. } => "relay-inbound-circuit",
        TransportEvent::NatStatusChanged { .. } => "nat-status-changed",
        TransportEvent::HolePunchFinished { .. } => "hole-punch-finished",
        TransportEvent::ExternalAddressConfirmed { .. } => "external-address-confirmed",
    }
}

fn relay_event_name(event: &RelayServiceEvent) -> &'static str {
    match event {
        RelayServiceEvent::BootstrapRoute { .. } => "bootstrap-route",
        RelayServiceEvent::Listening { .. } => "listening",
        RelayServiceEvent::ListenerClosed { .. } => "listener-closed",
        RelayServiceEvent::ListenerFailed { .. } => "listener-failed",
        RelayServiceEvent::ConnectionEstablished { .. } => "connection-established",
        RelayServiceEvent::ConnectionClosed { .. } => "connection-closed",
        RelayServiceEvent::ReservationAccepted { .. } => "reservation-accepted",
        RelayServiceEvent::ReservationClosed { .. } => "reservation-closed",
        RelayServiceEvent::CircuitAccepted { .. } => "circuit-accepted",
        RelayServiceEvent::CircuitClosed { .. } => "circuit-closed",
    }
}

impl OperatorRecord {
    fn basic(role: ServiceRole, event: &'static str, ready: bool, peer_id: PeerId) -> Self {
        Self {
            schema_version: 2,
            service: "prometheus-guardian-p2p",
            role,
            event,
            ready,
            peer_id: peer_id.to_string(),
            address: None,
            remote_peer: None,
            path: None,
            status: None,
            connections: None,
            pending_inbound: None,
            pending_outbound: None,
        }
    }
}

async fn await_submission_server(
    task: JoinHandle<Result<(), LocalSubmissionError>>,
    timeout: Duration,
) -> Result<(), ServiceError> {
    match time::timeout(timeout, task).await {
        Ok(Ok(result)) => result.map_err(ServiceError::Submission),
        Ok(Err(_)) => Err(ServiceError::SubmissionTask),
        Err(_) => Err(ServiceError::ShutdownTimeout),
    }
}

fn shutdown_signal() -> Result<ShutdownFuture, std::io::Error> {
    #[cfg(unix)]
    {
        let mut interrupt =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        Ok(Box::pin(async move {
            tokio::select! {
                signal = interrupt.recv() => {
                    if signal.is_some() {
                        Ok(())
                    } else {
                        Err(std::io::Error::other("SIGINT listener closed"))
                    }
                },
                signal = terminate.recv() => {
                    if signal.is_some() {
                        Ok(())
                    } else {
                        Err(std::io::Error::other("SIGTERM listener closed"))
                    }
                }
            }
        }))
    }
    #[cfg(not(unix))]
    {
        Ok(Box::pin(tokio::signal::ctrl_c()))
    }
}

fn parse_addresses(values: &[String]) -> Result<Vec<Multiaddr>, ServiceError> {
    values
        .iter()
        .map(|value| {
            Multiaddr::from_str(value)
                .map_err(|_| ServiceError::InvalidConfig("invalid multiaddress"))
        })
        .collect()
}

fn parse_canonical_addresses(values: &[String]) -> Result<Vec<Multiaddr>, ServiceError> {
    values
        .iter()
        .map(|value| {
            let address = Multiaddr::from_str(value)
                .map_err(|_| ServiceError::InvalidConfig("invalid multiaddress"))?;
            if value != &address.to_string() {
                return Err(ServiceError::InvalidConfig(
                    "advertised multiaddress must be canonical",
                ));
            }
            Ok(address)
        })
        .collect()
}

fn parse_routes(values: &[PeerRoute]) -> Result<Vec<StaticPeer>, ServiceError> {
    values
        .iter()
        .map(|route| {
            let peer_id = PeerId::from_str(&route.peer_id)
                .map_err(|_| ServiceError::InvalidConfig("invalid transport peer id"))?;
            if route.peer_id != peer_id.to_string() {
                return Err(ServiceError::InvalidConfig(
                    "transport peer id must be canonical",
                ));
            }
            let address = Multiaddr::from_str(&route.address)
                .map_err(|_| ServiceError::InvalidConfig("invalid multiaddress"))?;
            Ok(StaticPeer { peer_id, address })
        })
        .collect()
}

fn bounded_seconds(
    seconds: u64,
    max: u64,
    message: &'static str,
) -> Result<Duration, ServiceError> {
    if seconds == 0 || seconds > max {
        return Err(ServiceError::InvalidConfig(message));
    }
    Ok(Duration::from_secs(seconds))
}

fn validate_absolute_file_path(path: &Path) -> Result<(), ServiceError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| component == Component::ParentDir)
        || !matches!(path.components().next_back(), Some(Component::Normal(_)))
    {
        return Err(ServiceError::InvalidConfig(
            "service paths must be absolute file paths",
        ));
    }
    Ok(())
}

fn read_owner_only_config(path: &Path) -> Result<Vec<u8>, ServiceError> {
    validate_absolute_file_path(path)?;
    let parent = path.parent().ok_or(ServiceError::UnsafeConfig)?;
    let file_name = path.file_name().ok_or(ServiceError::UnsafeConfig)?;
    let parent_fd = fs::open(
        parent,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| ServiceError::UnsafeConfig)?;
    validate_owner_only_parent(&parent_fd)?;
    let config_fd = fs::openat(
        &parent_fd,
        file_name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| ServiceError::UnsafeConfig)?;
    let stat = fs::fstat(&config_fd).map_err(|_| ServiceError::UnsafeConfig)?;
    let mode = stat.st_mode as u32;
    if !FileType::from_raw_mode(stat.st_mode).is_file()
        || stat.st_uid != process::geteuid().as_raw()
        || mode & 0o177 != 0
        || mode & 0o400 == 0
    {
        return Err(ServiceError::UnsafeConfig);
    }
    let mut contents = Vec::with_capacity(MAX_CONFIG_BYTES + 1);
    File::from(config_fd)
        .take((MAX_CONFIG_BYTES + 1) as u64)
        .read_to_end(&mut contents)
        .map_err(ServiceError::Io)?;
    if contents.is_empty() || contents.len() > MAX_CONFIG_BYTES {
        return Err(ServiceError::InvalidConfig(
            "config is empty or exceeds 64 KiB",
        ));
    }
    Ok(contents)
}

fn validate_owner_only_parent(parent: &impl std::os::fd::AsFd) -> Result<(), ServiceError> {
    let stat = fs::fstat(parent).map_err(|_| ServiceError::UnsafeConfig)?;
    let mode = stat.st_mode as u32;
    if !FileType::from_raw_mode(stat.st_mode).is_dir()
        || stat.st_uid != process::geteuid().as_raw()
        || mode & 0o077 != 0
        || mode & 0o700 != 0o700
    {
        return Err(ServiceError::UnsafeConfig);
    }
    Ok(())
}

const fn default_health_interval_secs() -> u64 {
    30
}

const fn default_ingress_timeout_secs() -> u64 {
    10
}

const fn default_collector_startup_secs() -> u64 {
    30
}

const fn default_shutdown_drain_secs() -> u64 {
    10
}

const fn default_local_submission_limit() -> usize {
    32
}

const fn path_name(path: ConnectionPath) -> &'static str {
    match path {
        ConnectionPath::Direct => "direct",
        ConnectionPath::Relayed => "relayed",
    }
}

const fn nat_name(status: NatReachability) -> &'static str {
    match status {
        NatReachability::Unknown => "unknown",
        NatReachability::Private => "private",
        NatReachability::Public => "public",
    }
}

const fn hole_punch_name(outcome: HolePunchOutcome) -> &'static str {
    match outcome {
        HolePunchOutcome::DirectEstablished => "direct-established",
        HolePunchOutcome::RelayFallback => "relay-fallback",
    }
}

const fn request_failure_name(failure: RequestFailure) -> &'static str {
    match failure {
        RequestFailure::Dial => "dial-failure",
        RequestFailure::Timeout => "timeout",
        RequestFailure::ConnectionClosed => "connection-closed",
        RequestFailure::UnsupportedProtocol => "unsupported-protocol",
        RequestFailure::Io => "io-failure",
    }
}

/// Service startup, local IPC, transport and shutdown failures.
#[derive(Debug, Error)]
pub enum ServiceError {
    #[error("invalid Guardian P2P service configuration: {0}")]
    InvalidConfig(&'static str),
    #[error("Guardian P2P config file must be an owner-only regular file")]
    UnsafeConfig,
    #[error("Guardian P2P identity is unavailable")]
    Identity(#[from] IdentityError),
    #[error("Guardian collector ingress is unavailable")]
    Ingress(#[from] IngressError),
    #[error("Guardian ThreatHint ingress is unavailable")]
    ThreatHintIngress(#[from] ThreatHintIngressError),
    #[error("Guardian local submission service failed")]
    Submission(#[from] LocalSubmissionError),
    #[error("Guardian P2P transport failed")]
    Transport(#[from] TransportError),
    #[error("Guardian P2P JSON output failed")]
    Json(#[source] serde_json::Error),
    #[error("Guardian P2P I/O failed")]
    Io(#[source] std::io::Error),
    #[error("Guardian P2P signal handling failed")]
    Signal(#[source] std::io::Error),
    #[error("Guardian local submission task terminated unexpectedly")]
    SubmissionTask,
    #[error("Guardian P2P operator output task terminated unexpectedly")]
    OutputTask,
    #[error("Guardian P2P operator output queue is full")]
    OutputBackpressure,
    #[error("Guardian P2P operator output shutdown timed out")]
    OutputShutdownTimeout,
    #[error("Guardian P2P shutdown drain timed out")]
    ShutdownTimeout,
}

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::PermissionsExt};

    use tempfile::TempDir;

    use super::*;

    fn secure_directory() -> TempDir {
        let directory = tempfile::tempdir().expect("temporary directory");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("owner-only directory");
        directory
    }

    fn write_config(directory: &TempDir, contents: &str) -> PathBuf {
        let path = directory.path().join("guardian-p2p.toml");
        fs::write(&path, contents).expect("write config");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("owner-only config");
        path
    }

    #[test]
    fn strict_guardian_preflight_is_path_free() {
        let directory = secure_directory();
        let config = write_config(
            &directory,
            &format!(
                r#"role = "guardian"
identity_path = "{}"
collector_socket = "{}"
threat_hint_socket = "{}"
submission_socket = "{}"
listen_addresses = ["/ip4/127.0.0.1/udp/0/quic-v1"]
"#,
                directory.path().join("identity").display(),
                directory.path().join("collector.sock").display(),
                directory.path().join("threat-hint.sock").display(),
                directory.path().join("submit.sock").display(),
            ),
        );
        let prepared = ServiceConfig::from_toml_file(&config)
            .expect("parse config")
            .prepare()
            .expect("prepare config");
        let report = serde_json::to_string(&prepared.preflight_report()).expect("report");
        assert!(report.contains("ready-for-operated-sidecar"));
        assert!(!report.contains(directory.path().to_str().expect("UTF-8 temp path")));
        assert!(!report.contains("collector.sock"));
    }

    #[test]
    fn guardian_local_boundaries_must_use_distinct_paths() {
        let directory = secure_directory();
        let shared_socket = directory.path().join("shared.sock");
        let config = write_config(
            &directory,
            &format!(
                r#"role = "guardian"
identity_path = "{}"
collector_socket = "{}"
threat_hint_socket = "{}"
submission_socket = "{}"
listen_addresses = ["/ip4/127.0.0.1/udp/0/quic-v1"]
"#,
                directory.path().join("identity").display(),
                shared_socket.display(),
                shared_socket.display(),
                directory.path().join("submit.sock").display(),
            ),
        );
        assert!(matches!(
            ServiceConfig::from_toml_file(&config)
                .expect("parse config")
                .prepare(),
            Err(ServiceError::InvalidConfig(
                "identity, collector, ThreatHint and submission paths must be distinct"
            ))
        ));
    }

    #[test]
    fn unknown_fields_and_unsafe_config_modes_fail_closed() {
        let directory = secure_directory();
        let config = write_config(
            &directory,
            &format!(
                r#"role = "relay"
identity_path = "{}"
listen_addresses = ["/ip4/127.0.0.1/udp/0/quic-v1"]
wallet_private_key = "must-not-be-accepted"
"#,
                directory.path().join("identity").display(),
            ),
        );
        assert!(ServiceConfig::from_toml_file(&config).is_err());
        fs::set_permissions(&config, fs::Permissions::from_mode(0o640))
            .expect("unsafe config permissions");
        assert!(matches!(
            ServiceConfig::from_toml_file(&config),
            Err(ServiceError::UnsafeConfig)
        ));
    }

    #[test]
    fn role_specific_fields_and_unbounded_values_are_rejected() {
        let directory = secure_directory();
        let config = write_config(
            &directory,
            &format!(
                r#"role = "relay"
identity_path = "{}"
listen_addresses = ["/ip4/127.0.0.1/udp/0/quic-v1"]
collector_socket = "{}"
health_interval_secs = 3601
"#,
                directory.path().join("identity").display(),
                directory.path().join("collector.sock").display(),
            ),
        );
        assert!(ServiceConfig::from_toml_file(&config).is_err());

        let guardian_config = write_config(
            &directory,
            &format!(
                r#"role = "guardian"
identity_path = "{}"
collector_socket = "{}"
threat_hint_socket = "{}"
submission_socket = "{}"
listen_addresses = ["/ip4/127.0.0.1/udp/4101/quic-v1"]
advertise_addresses = ["/ip4/198.51.100.10/udp/4101/quic-v1"]
"#,
                directory.path().join("guardian.identity").display(),
                directory.path().join("collector.sock").display(),
                directory.path().join("threat-hint.sock").display(),
                directory.path().join("submit.sock").display(),
            ),
        );
        assert!(ServiceConfig::from_toml_file(&guardian_config).is_err());
    }

    #[test]
    fn relay_preflight_reports_canonical_advertised_routes() {
        let directory = secure_directory();
        let config = write_config(
            &directory,
            &format!(
                r#"role = "relay"
identity_path = "{}"
listen_addresses = ["/ip4/0.0.0.0/udp/4100/quic-v1"]
advertise_addresses = ["/ip4/198.51.100.10/udp/4100/quic-v1"]
"#,
                directory.path().join("identity").display(),
            ),
        );
        let prepared = ServiceConfig::from_toml_file(&config)
            .expect("parse relay config")
            .prepare()
            .expect("prepare relay config");
        let report = serde_json::to_value(prepared.preflight_report()).expect("preflight report");
        assert_eq!(report["schema_version"], 2);
        assert_eq!(report["listener_count"], 1);
        assert_eq!(report["advertise_address_count"], 1);
        assert_eq!(report["public_multi_host_evidence"], "not-proven");
        assert!(!report.to_string().contains("198.51.100.10"));
    }

    #[test]
    fn noncanonical_advertised_address_is_rejected() {
        let directory = secure_directory();
        let config = write_config(
            &directory,
            &format!(
                r#"role = "relay"
identity_path = "{}"
listen_addresses = ["/ip4/127.0.0.1/udp/4100/quic-v1"]
advertise_addresses = ["/ip6/2001:0db8::1/udp/4100/quic-v1"]
"#,
                directory.path().join("identity").display(),
            ),
        );
        assert!(ServiceConfig::from_toml_file(&config)
            .expect("parse relay config")
            .prepare()
            .is_err());
    }

    #[test]
    fn parent_directory_components_are_rejected() {
        assert!(matches!(
            validate_absolute_file_path(Path::new("/tmp/prometheus/../identity")),
            Err(ServiceError::InvalidConfig(_))
        ));
    }
}

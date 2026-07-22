#![deny(warnings)]
//! Opaque Guardian ballot transport over libp2p.
//!
//! This crate carries pre-validated ballot envelopes only. In particular, a
//! [`libp2p_identity::PeerId`] is connection metadata and is never a Guardian identity,
//! membership record, or signing-key assignment.

#[cfg(not(unix))]
compile_error!("prometheus-guardian-p2p requires Unix AF_UNIX and peer credentials");

pub mod ingress;
pub mod local_submit;
pub mod relay_service;
pub mod service;
pub mod threat_hint_ingress;
#[path = "identity.rs"]
pub mod transport_identity;

use std::{
    collections::{HashMap, HashSet},
    future::Future,
    io,
    pin::Pin,
    time::Duration,
};

use async_trait::async_trait;
use futures::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    stream::FuturesUnordered,
    StreamExt,
};
use libp2p_autonat as autonat;
use libp2p_connection_limits as connection_limits;
use libp2p_core::{
    multiaddr::Protocol, muxing::StreamMuxerBox, transport::ListenerId, upgrade, Multiaddr,
    Transport,
};
use libp2p_dcutr as dcutr;
use libp2p_identify as identify;
use libp2p_identity::{self as identity, PeerId};
use libp2p_ping as ping;
use libp2p_relay as relay;
use libp2p_request_response as request_response;
use libp2p_swarm::{NetworkBehaviour, StreamProtocol, Swarm, SwarmEvent};
pub use prometheus_threat_hint::{ThreatHintEnvelope, ThreatIndicatorType, ThreatProofSystem};
use thiserror::Error;

use crate::ingress::{IngressError, UnixBallotIngress};
use crate::threat_hint_ingress::{ThreatHintIngressError, UnixThreatHintIngress};

/// Direct request-response protocol for opaque Guardian ballot envelopes.
pub const BALLOT_PROTOCOL: &str = "/prometheus/guardian-ballot/1.0.0";
/// Direct request-response protocol for canonical Light Client threat hints.
pub const THREAT_HINT_PROTOCOL: &str = "/prometheus/threat-hint/1.0.0";
/// Maximum permitted ballot envelope size, matching the canonical verifier.
pub const MAX_BALLOT_BYTES: usize = 8_192;
/// Maximum permitted canonical threat-hint envelope size.
pub const MAX_THREAT_HINT_BYTES: usize = prometheus_threat_hint::MAX_CANONICAL_BYTES;
/// Maximum configured static transport routes.
pub const MAX_STATIC_PEERS: usize = 64;
/// Maximum configured direct or relay listeners.
pub const MAX_LISTEN_ADDRESSES: usize = 16;
/// Maximum encoded length accepted for an operator-supplied multiaddress.
pub const MAX_MULTIADDR_BYTES: usize = 512;
/// Maximum explicitly trusted AutoNAT probe servers.
pub const MAX_AUTONAT_SERVERS: usize = 8;
/// Maximum requests accepted from an operator configuration.
pub const MAX_CONCURRENT_REQUESTS: usize = 1_024;
/// Maximum concurrent streams accepted per connection.
pub const MAX_STREAMS_PER_CONNECTION: usize = 64;
/// Minimum global stream budget needed to reserve one stream per protocol.
pub const MIN_STREAMS_PER_CONNECTION: usize = 2;
/// Maximum value for any individual configured connection limit.
pub const MAX_CONNECTION_LIMIT: u32 = 4_096;
/// Maximum operator-configured transport duration.
pub const MAX_TRANSPORT_DURATION: Duration = Duration::from_secs(24 * 60 * 60);

const ACK_BYTES: usize = 1;
const BALLOT_LENGTH_BYTES: usize = 2;

/// A validated, unchanged ballot envelope for transport.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BallotBytes(Vec<u8>);

impl BallotBytes {
    /// Retains opaque bytes after enforcing the transport boundary.
    pub fn new(bytes: Vec<u8>) -> Result<Self, TransportError> {
        if bytes.is_empty() || bytes.len() > MAX_BALLOT_BYTES {
            return Err(TransportError::BallotSize(bytes.len()));
        }

        Ok(Self(bytes))
    }

    /// Returns the exact ballot bytes supplied to this transport.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Consumes the wrapper and returns the exact transported bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

/// A validated canonical ThreatHint envelope retained as exact wire bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ThreatHintBytes(Vec<u8>);

impl ThreatHintBytes {
    /// Parses one canonical schema-v1 envelope and retains its exact bytes.
    pub fn new(bytes: Vec<u8>) -> Result<Self, TransportError> {
        if bytes.is_empty() || bytes.len() > MAX_THREAT_HINT_BYTES {
            return Err(TransportError::ThreatHintSize(bytes.len()));
        }
        ThreatHintEnvelope::parse_canonical(&bytes)
            .map_err(|_| TransportError::InvalidThreatHint)?;
        Ok(Self(bytes))
    }

    /// Encodes a validated envelope into exact canonical transport bytes.
    pub fn from_envelope(envelope: &ThreatHintEnvelope) -> Result<Self, TransportError> {
        let bytes = envelope
            .to_canonical_bytes()
            .map_err(|_| TransportError::InvalidThreatHint)?;
        Self::new(bytes)
    }

    /// Returns the exact canonical bytes supplied to this transport.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Parses the retained bytes into the shared schema type.
    pub fn parse(&self) -> Result<ThreatHintEnvelope, TransportError> {
        ThreatHintEnvelope::parse_canonical(&self.0).map_err(|_| TransportError::InvalidThreatHint)
    }
}

/// The only response data emitted by the ballot carrier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum AckStatus {
    Accepted = 0,
    Duplicate = 1,
    Rejected = 2,
    Busy = 3,
}

impl AckStatus {
    fn from_wire(value: u8) -> io::Result<Self> {
        match value {
            0 => Ok(Self::Accepted),
            1 => Ok(Self::Duplicate),
            2 => Ok(Self::Rejected),
            3 => Ok(Self::Busy),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unknown Guardian ballot acknowledgement",
            )),
        }
    }

    /// Stable machine-readable acknowledgement name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Duplicate => "duplicate",
            Self::Rejected => "rejected",
            Self::Busy => "busy",
        }
    }
}

/// Data-minimal response for the independent ThreatHint channel.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ThreatHintAckStatus {
    Accepted = 0,
    Duplicate = 1,
    Rejected = 2,
    Busy = 3,
}

impl ThreatHintAckStatus {
    fn from_wire(value: u8) -> io::Result<Self> {
        match value {
            0 => Ok(Self::Accepted),
            1 => Ok(Self::Duplicate),
            2 => Ok(Self::Rejected),
            3 => Ok(Self::Busy),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unknown ThreatHint acknowledgement",
            )),
        }
    }

    /// Stable machine-readable acknowledgement name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Duplicate => "duplicate",
            Self::Rejected => "rejected",
            Self::Busy => "busy",
        }
    }
}

/// A configured transport peer. It intentionally has no Guardian identity fields.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct StaticPeer {
    pub peer_id: PeerId,
    pub address: Multiaddr,
}

/// Bounded transport settings for a Guardian sidecar.
#[derive(Clone, Debug)]
pub struct GuardianP2pConfig {
    pub listen_addresses: Vec<Multiaddr>,
    pub static_peers: Vec<StaticPeer>,
    pub autonat_servers: Vec<StaticPeer>,
    pub autonat_boot_delay: Duration,
    pub autonat_retry_interval: Duration,
    pub autonat_refresh_interval: Duration,
    pub autonat_confidence_max: usize,
    pub autonat_allow_private_addresses: bool,
    pub request_timeout: Duration,
    pub idle_connection_timeout: Duration,
    pub max_concurrent_requests: usize,
    pub max_concurrent_streams_per_connection: usize,
    pub max_pending_incoming_connections: u32,
    pub max_pending_outgoing_connections: u32,
    pub max_established_incoming_connections: u32,
    pub max_established_outgoing_connections: u32,
    pub max_established_connections_per_peer: u32,
}

impl Default for GuardianP2pConfig {
    fn default() -> Self {
        Self {
            listen_addresses: Vec::new(),
            static_peers: Vec::new(),
            autonat_servers: Vec::new(),
            autonat_boot_delay: Duration::from_secs(15),
            autonat_retry_interval: Duration::from_secs(90),
            autonat_refresh_interval: Duration::from_secs(15 * 60),
            autonat_confidence_max: 3,
            autonat_allow_private_addresses: false,
            request_timeout: Duration::from_secs(10),
            idle_connection_timeout: Duration::from_secs(30),
            max_concurrent_requests: 32,
            max_concurrent_streams_per_connection: MIN_STREAMS_PER_CONNECTION,
            max_pending_incoming_connections: 8,
            max_pending_outgoing_connections: 8,
            max_established_incoming_connections: 16,
            max_established_outgoing_connections: 16,
            max_established_connections_per_peer: 2,
        }
    }
}

impl GuardianP2pConfig {
    pub fn validate(&self) -> Result<(), TransportError> {
        if self.request_timeout.is_zero()
            || self.request_timeout > MAX_TRANSPORT_DURATION
            || self.idle_connection_timeout.is_zero()
            || self.idle_connection_timeout > MAX_TRANSPORT_DURATION
        {
            return Err(TransportError::InvalidConfig("timeouts must be non-zero"));
        }
        if self.autonat_retry_interval.is_zero()
            || self.autonat_retry_interval > MAX_TRANSPORT_DURATION
            || self.autonat_refresh_interval.is_zero()
            || self.autonat_refresh_interval > MAX_TRANSPORT_DURATION
            || self.autonat_boot_delay > MAX_TRANSPORT_DURATION
            || !(1..=10).contains(&self.autonat_confidence_max)
        {
            return Err(TransportError::InvalidConfig(
                "AutoNAT intervals and confidence must be bounded",
            ));
        }

        if !(1..=MAX_CONCURRENT_REQUESTS).contains(&self.max_concurrent_requests)
            || !(MIN_STREAMS_PER_CONNECTION..=MAX_STREAMS_PER_CONNECTION)
                .contains(&self.max_concurrent_streams_per_connection)
            || !(1..=MAX_CONNECTION_LIMIT).contains(&self.max_pending_incoming_connections)
            || !(1..=MAX_CONNECTION_LIMIT).contains(&self.max_pending_outgoing_connections)
            || !(1..=MAX_CONNECTION_LIMIT).contains(&self.max_established_incoming_connections)
            || !(1..=MAX_CONNECTION_LIMIT).contains(&self.max_established_outgoing_connections)
            || !(1..=MAX_CONNECTION_LIMIT).contains(&self.max_established_connections_per_peer)
        {
            return Err(TransportError::InvalidConfig(
                "request and connection limits are out of bounds",
            ));
        }

        if self.listen_addresses.len() > MAX_LISTEN_ADDRESSES {
            return Err(TransportError::InvalidConfig("too many listen addresses"));
        }
        if self.static_peers.len() > MAX_STATIC_PEERS {
            return Err(TransportError::InvalidConfig("too many static peers"));
        }
        if self.autonat_servers.len() > MAX_AUTONAT_SERVERS {
            return Err(TransportError::InvalidConfig("too many AutoNAT servers"));
        }

        let mut listen_addresses = HashSet::new();
        for address in &self.listen_addresses {
            validate_listen_address(address)?;
            if !listen_addresses.insert(address) {
                return Err(TransportError::InvalidConfig("duplicate listen address"));
            }
        }

        let mut static_peers = HashSet::new();
        for peer in &self.static_peers {
            validate_static_peer(peer)?;
            if !static_peers.insert(peer) {
                return Err(TransportError::InvalidConfig("duplicate static peer route"));
            }
        }

        let mut autonat_servers = HashSet::new();
        for server in &self.autonat_servers {
            validate_autonat_server(server)?;
            if !autonat_servers.insert(server) {
                return Err(TransportError::InvalidConfig(
                    "duplicate AutoNAT server route",
                ));
            }
        }

        Ok(())
    }

    fn connection_limits(&self) -> connection_limits::ConnectionLimits {
        connection_limits::ConnectionLimits::default()
            .with_max_pending_incoming(Some(self.max_pending_incoming_connections))
            .with_max_pending_outgoing(Some(self.max_pending_outgoing_connections))
            .with_max_established_incoming(Some(self.max_established_incoming_connections))
            .with_max_established_outgoing(Some(self.max_established_outgoing_connections))
            .with_max_established_per_peer(Some(self.max_established_connections_per_peer))
            .with_max_established(Some(
                self.max_established_incoming_connections
                    .saturating_add(self.max_established_outgoing_connections),
            ))
    }

    fn autonat_config(&self) -> autonat::Config {
        autonat::Config {
            boot_delay: self.autonat_boot_delay,
            retry_interval: self.autonat_retry_interval,
            refresh_interval: self.autonat_refresh_interval,
            confidence_max: self.autonat_confidence_max,
            only_global_ips: !self.autonat_allow_private_addresses,
            ..autonat::Config::default()
        }
    }
}

fn validate_listen_address(address: &Multiaddr) -> Result<(), TransportError> {
    validate_address_size(address)?;
    let protocols: Vec<_> = address.iter().collect();
    validate_quic_base(&protocols, true)?;

    match protocols.as_slice() {
        [_, _, Protocol::QuicV1] => Ok(()),
        [_, _, Protocol::QuicV1, Protocol::P2p(_), Protocol::P2pCircuit] => Ok(()),
        _ => Err(TransportError::InvalidConfig(
            "listen address must be an IP/UDP/QUIC-v1 address or relay reservation",
        )),
    }
}

fn validate_static_peer(peer: &StaticPeer) -> Result<(), TransportError> {
    validate_address_size(&peer.address)?;
    let protocols: Vec<_> = peer.address.iter().collect();
    validate_quic_base(&protocols, false)?;

    match protocols.as_slice() {
        [_, _, Protocol::QuicV1] => Ok(()),
        [_, _, Protocol::QuicV1, Protocol::P2p(target)] if target == &peer.peer_id => Ok(()),
        [_, _, Protocol::QuicV1, Protocol::P2p(relay_peer), Protocol::P2pCircuit, Protocol::P2p(target)]
            if target == &peer.peer_id && relay_peer != target =>
        {
            Ok(())
        }
        _ => Err(TransportError::InvalidConfig(
            "static peer address must be direct QUIC-v1 or an exact relay circuit route",
        )),
    }
}

fn validate_autonat_server(server: &StaticPeer) -> Result<(), TransportError> {
    validate_address_size(&server.address)?;
    let protocols: Vec<_> = server.address.iter().collect();
    validate_quic_base(&protocols, false)?;
    match protocols.as_slice() {
        [_, _, Protocol::QuicV1] => Ok(()),
        [_, _, Protocol::QuicV1, Protocol::P2p(target)] if target == &server.peer_id => Ok(()),
        _ => Err(TransportError::InvalidConfig(
            "AutoNAT server must use an exact direct QUIC-v1 route",
        )),
    }
}

fn validate_address_size(address: &Multiaddr) -> Result<(), TransportError> {
    if address.is_empty() || address.to_vec().len() > MAX_MULTIADDR_BYTES {
        return Err(TransportError::InvalidConfig(
            "multiaddress is empty or exceeds the configured limit",
        ));
    }
    Ok(())
}

fn validate_quic_base(protocols: &[Protocol<'_>], listener: bool) -> Result<(), TransportError> {
    let ip_is_valid = match protocols.first() {
        Some(Protocol::Ip4(address)) => {
            listener || (!address.is_unspecified() && !address.is_multicast())
        }
        Some(Protocol::Ip6(address)) => {
            listener || (!address.is_unspecified() && !address.is_multicast())
        }
        _ => false,
    };
    let port_is_valid = match protocols.get(1) {
        Some(Protocol::Udp(port)) => listener || *port != 0,
        _ => false,
    };
    if !ip_is_valid || !port_is_valid || !matches!(protocols.get(2), Some(Protocol::QuicV1)) {
        return Err(TransportError::InvalidConfig(
            "multiaddress must begin with a valid IP/UDP/QUIC-v1 route",
        ));
    }
    Ok(())
}

/// Events relevant to a sidecar's ballot processing loop.
#[derive(Debug)]
pub enum TransportEvent {
    Listening {
        address: Multiaddr,
    },
    ListenerClosed {
        address: Multiaddr,
        failed: bool,
    },
    ListenerFailed {
        address: Multiaddr,
    },
    InboundBallot {
        peer: PeerId,
        request_id: request_response::InboundRequestId,
        ballot: BallotBytes,
    },
    InboundProcessed {
        peer: PeerId,
        status: AckStatus,
    },
    InboundThreatHint {
        peer: PeerId,
        request_id: request_response::InboundRequestId,
        hint: ThreatHintBytes,
    },
    InboundThreatHintProcessed {
        peer: PeerId,
        status: ThreatHintAckStatus,
    },
    OutboundAck {
        peer: PeerId,
        request_id: request_response::OutboundRequestId,
        status: AckStatus,
    },
    OutboundFailure {
        peer: PeerId,
        request_id: request_response::OutboundRequestId,
        failure: RequestFailure,
    },
    OutboundThreatHintAck {
        peer: PeerId,
        request_id: request_response::OutboundRequestId,
        status: ThreatHintAckStatus,
    },
    OutboundThreatHintFailure {
        peer: PeerId,
        request_id: request_response::OutboundRequestId,
        failure: RequestFailure,
    },
    ConnectionEstablished {
        peer: PeerId,
        path: ConnectionPath,
    },
    ConnectionClosed {
        peer: PeerId,
        path: ConnectionPath,
        remaining: u32,
        failed: bool,
    },
    RelayReservationAccepted {
        relay_peer: PeerId,
        renewal: bool,
    },
    RelayOutboundCircuit {
        relay_peer: PeerId,
    },
    RelayInboundCircuit {
        source_peer: PeerId,
    },
    NatStatusChanged {
        old: NatReachability,
        new: NatReachability,
    },
    HolePunchFinished {
        peer: PeerId,
        outcome: HolePunchOutcome,
    },
    ExternalAddressConfirmed {
        path: ConnectionPath,
    },
}

/// Whether a connection or confirmed external route is direct or relayed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionPath {
    Direct,
    Relayed,
}

/// Data-minimal AutoNAT status for operator health reporting.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NatReachability {
    Unknown,
    Private,
    Public,
}

impl From<&autonat::NatStatus> for NatReachability {
    fn from(status: &autonat::NatStatus) -> Self {
        match status {
            autonat::NatStatus::Unknown => Self::Unknown,
            autonat::NatStatus::Private => Self::Private,
            autonat::NatStatus::Public(_) => Self::Public,
        }
    }
}

/// Stable outcome of a DCUtR direct-connection upgrade attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HolePunchOutcome {
    DirectEstablished,
    RelayFallback,
}

/// Stable classification of an outbound request-response failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestFailure {
    Dial,
    Timeout,
    ConnectionClosed,
    UnsupportedProtocol,
    Io,
}

impl From<&request_response::OutboundFailure> for RequestFailure {
    fn from(failure: &request_response::OutboundFailure) -> Self {
        match failure {
            request_response::OutboundFailure::DialFailure => Self::Dial,
            request_response::OutboundFailure::Timeout => Self::Timeout,
            request_response::OutboundFailure::ConnectionClosed => Self::ConnectionClosed,
            request_response::OutboundFailure::UnsupportedProtocols => Self::UnsupportedProtocol,
            request_response::OutboundFailure::Io(_) => Self::Io,
        }
    }
}

/// Errors raised before or while dispatching a ballot transport operation.
#[derive(Debug, Error)]
pub enum TransportError {
    #[error("ballot must contain between 1 and {MAX_BALLOT_BYTES} bytes; got {0}")]
    BallotSize(usize),
    #[error("ThreatHint must contain between 1 and {MAX_THREAT_HINT_BYTES} bytes; got {0}")]
    ThreatHintSize(usize),
    #[error("ThreatHint envelope is not canonical schema v1")]
    InvalidThreatHint,
    #[error("invalid Guardian P2P configuration: {0}")]
    InvalidConfig(&'static str),
    #[error("failed to initialize libp2p transport: {0}")]
    Initialization(String),
    #[error("failed to listen on configured address: {0}")]
    Listen(String),
    #[error("maximum {max} outbound requests are already in flight")]
    OutboundBusy { max: usize },
    #[error("inbound request is no longer awaiting an acknowledgement")]
    UnknownInboundRequest,
    #[error("the inbound ThreatHint is no longer awaiting an acknowledgement")]
    UnknownInboundThreatHint,
    #[error("the inbound response channel closed before the acknowledgement was sent")]
    ResponseChannelClosed,
}

#[derive(Clone, Debug, Default)]
struct BallotCodec;

#[async_trait]
impl request_response::Codec for BallotCodec {
    type Protocol = StreamProtocol;
    type Request = BallotBytes;
    type Response = AckStatus;

    async fn read_request<T>(&mut self, _: &Self::Protocol, io: &mut T) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        let ballot = BallotBytes::new(read_ballot_frame(io).await?).map_err(to_invalid_data)?;
        require_stream_end(io, "Guardian ballot frame contains trailing bytes").await?;
        Ok(ballot)
    }

    async fn read_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut encoded = [0_u8; ACK_BYTES];
        io.read_exact(&mut encoded).await?;
        require_stream_end(
            io,
            "Guardian ballot acknowledgement contains trailing bytes",
        )
        .await?;
        AckStatus::from_wire(encoded[0])
    }

    async fn write_request<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        request: Self::Request,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        write_ballot_frame(io, request.as_bytes()).await
    }

    async fn write_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        response: Self::Response,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        io.write_all(&[response as u8]).await?;
        io.close().await
    }
}

#[derive(Clone, Debug, Default)]
struct ThreatHintCodec;

#[async_trait]
impl request_response::Codec for ThreatHintCodec {
    type Protocol = StreamProtocol;
    type Request = ThreatHintBytes;
    type Response = ThreatHintAckStatus;

    async fn read_request<T>(&mut self, _: &Self::Protocol, io: &mut T) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        let hint =
            ThreatHintBytes::new(read_threat_hint_frame(io).await?).map_err(to_invalid_data)?;
        require_stream_end(io, "ThreatHint frame contains trailing bytes").await?;
        Ok(hint)
    }

    async fn read_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut encoded = [0_u8; ACK_BYTES];
        io.read_exact(&mut encoded).await?;
        require_stream_end(io, "ThreatHint acknowledgement contains trailing bytes").await?;
        ThreatHintAckStatus::from_wire(encoded[0])
    }

    async fn write_request<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        request: Self::Request,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        write_threat_hint_frame(io, request.as_bytes()).await
    }

    async fn write_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        response: Self::Response,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        io.write_all(&[response as u8]).await?;
        io.close().await
    }
}

async fn require_stream_end<T>(io: &mut T, message: &'static str) -> io::Result<()>
where
    T: AsyncRead + Unpin,
{
    let mut trailing = [0_u8; 1];
    if io.read(&mut trailing).await? != 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, message));
    }
    Ok(())
}

async fn read_threat_hint_frame<T>(io: &mut T) -> io::Result<Vec<u8>>
where
    T: AsyncRead + Unpin,
{
    let mut length = [0_u8; BALLOT_LENGTH_BYTES];
    io.read_exact(&mut length).await?;
    let length = usize::from(u16::from_be_bytes(length));
    if length == 0 || length > MAX_THREAT_HINT_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ThreatHint exceeds transport limit",
        ));
    }

    let mut hint = vec![0_u8; length];
    io.read_exact(&mut hint).await?;
    Ok(hint)
}

async fn write_threat_hint_frame<T>(io: &mut T, hint: &[u8]) -> io::Result<()>
where
    T: AsyncWrite + Unpin,
{
    if hint.is_empty() || hint.len() > MAX_THREAT_HINT_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "ThreatHint exceeds transport limit",
        ));
    }

    let length = u16::try_from(hint.len()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "ThreatHint length does not fit transport frame",
        )
    })?;
    io.write_all(&length.to_be_bytes()).await?;
    io.write_all(hint).await?;
    io.close().await
}

async fn read_ballot_frame<T>(io: &mut T) -> io::Result<Vec<u8>>
where
    T: AsyncRead + Unpin,
{
    let mut length = [0_u8; BALLOT_LENGTH_BYTES];
    io.read_exact(&mut length).await?;
    let length = usize::from(u16::from_be_bytes(length));
    if length == 0 || length > MAX_BALLOT_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Guardian ballot exceeds transport limit",
        ));
    }

    let mut ballot = vec![0_u8; length];
    io.read_exact(&mut ballot).await?;
    Ok(ballot)
}

async fn write_ballot_frame<T>(io: &mut T, ballot: &[u8]) -> io::Result<()>
where
    T: AsyncWrite + Unpin,
{
    if ballot.is_empty() || ballot.len() > MAX_BALLOT_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Guardian ballot exceeds transport limit",
        ));
    }

    let length = u16::try_from(ballot.len()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "Guardian ballot length does not fit transport frame",
        )
    })?;
    io.write_all(&length.to_be_bytes()).await?;
    io.write_all(ballot).await?;
    io.close().await
}

fn to_invalid_data(error: TransportError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "BehaviourEvent", prelude = "libp2p_swarm::derive_prelude")]
struct GuardianBehaviour {
    ballots: request_response::Behaviour<BallotCodec>,
    threat_hints: request_response::Behaviour<ThreatHintCodec>,
    identify: identify::Behaviour,
    ping: ping::Behaviour,
    autonat: autonat::Behaviour,
    relay: relay::client::Behaviour,
    dcutr: dcutr::Behaviour,
    limits: connection_limits::Behaviour,
}

impl GuardianBehaviour {
    fn new(
        keypair: &identity::Keypair,
        relay_client: relay::client::Behaviour,
        config: &GuardianP2pConfig,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let local_peer_id = keypair.public().to_peer_id();
        let (ballot_streams, threat_hint_streams) =
            protocol_stream_limits(config.max_concurrent_streams_per_connection);
        let ballots = request_response::Behaviour::with_codec(
            BallotCodec,
            [(
                StreamProtocol::new(BALLOT_PROTOCOL),
                request_response::ProtocolSupport::Full,
            )],
            request_response::Config::default()
                .with_request_timeout(config.request_timeout)
                .with_max_concurrent_streams(ballot_streams),
        );
        let threat_hints = request_response::Behaviour::with_codec(
            ThreatHintCodec,
            [(
                StreamProtocol::new(THREAT_HINT_PROTOCOL),
                request_response::ProtocolSupport::Full,
            )],
            request_response::Config::default()
                .with_request_timeout(config.request_timeout)
                .with_max_concurrent_streams(threat_hint_streams),
        );

        Ok(Self {
            ballots,
            threat_hints,
            identify: identify::Behaviour::new(identify::Config::new(
                "/prometheus/guardian/1.0.0".to_owned(),
                keypair.public(),
            )),
            ping: ping::Behaviour::new(ping::Config::new()),
            autonat: autonat::Behaviour::new(local_peer_id, config.autonat_config()),
            relay: relay_client,
            dcutr: dcutr::Behaviour::new(local_peer_id),
            limits: connection_limits::Behaviour::new(config.connection_limits()),
        })
    }
}

fn protocol_stream_limits(total: usize) -> (usize, usize) {
    let threat_hints = total / 2;
    (total - threat_hints, threat_hints)
}

#[derive(Debug)]
enum BehaviourEvent {
    Ballots(request_response::Event<BallotBytes, AckStatus>),
    ThreatHints(request_response::Event<ThreatHintBytes, ThreatHintAckStatus>),
    Identify(Box<identify::Event>),
    Ping(ping::Event),
    Autonat(autonat::Event),
    Relay(relay::client::Event),
    Dcutr(dcutr::Event),
}

impl From<std::convert::Infallible> for BehaviourEvent {
    fn from(never: std::convert::Infallible) -> Self {
        match never {}
    }
}

impl From<request_response::Event<BallotBytes, AckStatus>> for BehaviourEvent {
    fn from(event: request_response::Event<BallotBytes, AckStatus>) -> Self {
        Self::Ballots(event)
    }
}

impl From<request_response::Event<ThreatHintBytes, ThreatHintAckStatus>> for BehaviourEvent {
    fn from(event: request_response::Event<ThreatHintBytes, ThreatHintAckStatus>) -> Self {
        Self::ThreatHints(event)
    }
}

impl From<identify::Event> for BehaviourEvent {
    fn from(event: identify::Event) -> Self {
        Self::Identify(Box::new(event))
    }
}

impl From<ping::Event> for BehaviourEvent {
    fn from(event: ping::Event) -> Self {
        Self::Ping(event)
    }
}

impl From<autonat::Event> for BehaviourEvent {
    fn from(event: autonat::Event) -> Self {
        Self::Autonat(event)
    }
}

impl From<relay::client::Event> for BehaviourEvent {
    fn from(event: relay::client::Event) -> Self {
        Self::Relay(event)
    }
}

impl From<dcutr::Event> for BehaviourEvent {
    fn from(event: dcutr::Event) -> Self {
        Self::Dcutr(event)
    }
}

/// Event-driven libp2p carrier for a Guardian sidecar.
pub struct GuardianP2p {
    swarm: Swarm<GuardianBehaviour>,
    inbound_responses:
        HashMap<request_response::InboundRequestId, request_response::ResponseChannel<AckStatus>>,
    inbound_threat_hint_responses: HashMap<
        request_response::InboundRequestId,
        request_response::ResponseChannel<ThreatHintAckStatus>,
    >,
    inbound_work: HashSet<request_response::InboundRequestId>,
    inbound_threat_hint_work: HashSet<request_response::InboundRequestId>,
    ingress_request_ids: HashSet<request_response::InboundRequestId>,
    ingress_tasks: FuturesUnordered<IngressFuture>,
    threat_hint_ingress_request_ids: HashSet<request_response::InboundRequestId>,
    threat_hint_ingress_tasks: FuturesUnordered<ThreatHintIngressFuture>,
    outbound_requests: HashSet<request_response::OutboundRequestId>,
    outbound_threat_hint_requests: HashSet<request_response::OutboundRequestId>,
    max_outbound_requests: usize,
    max_inbound_requests: usize,
    configured_static_peers: HashSet<StaticPeer>,
    configured_listen_addresses: HashSet<Multiaddr>,
    listener_addresses: HashMap<ListenerId, Multiaddr>,
    active_listener_addresses: HashMap<ListenerId, HashSet<Multiaddr>>,
}

type IngressFuture = Pin<Box<dyn Future<Output = IngressCompletion> + Send>>;
type ThreatHintIngressFuture = Pin<Box<dyn Future<Output = ThreatHintIngressCompletion> + Send>>;

struct IngressCompletion {
    peer: PeerId,
    request_id: request_response::InboundRequestId,
    status: AckStatus,
}

struct ThreatHintIngressCompletion {
    peer: PeerId,
    request_id: request_response::InboundRequestId,
    status: ThreatHintAckStatus,
}

impl GuardianP2p {
    /// Builds a QUIC-only direct transport plus relay client transport.
    pub fn new(
        keypair: identity::Keypair,
        config: GuardianP2pConfig,
    ) -> Result<Self, TransportError> {
        config.validate()?;
        let static_peers = config.static_peers.clone();
        let listen_addresses = config.listen_addresses.clone();
        let autonat_servers = config.autonat_servers.clone();
        let idle_connection_timeout = config.idle_connection_timeout;
        let max_outbound_requests = config.max_concurrent_requests;
        let max_inbound_requests = config.max_concurrent_requests;
        let behaviour_config = config.clone();

        let local_peer_id = keypair.public().to_peer_id();
        let quic_transport = libp2p_quic::tokio::Transport::new(libp2p_quic::Config::new(&keypair))
            .map(|(peer_id, muxer), _| (peer_id, StreamMuxerBox::new(muxer)));
        let (relay_transport, relay_client) = relay::client::new(local_peer_id);
        let relay_transport = relay_transport
            .upgrade(upgrade::Version::V1Lazy)
            .authenticate(
                libp2p_tls::Config::new(&keypair)
                    .map_err(|error| TransportError::Initialization(error.to_string()))?,
            )
            .multiplex(libp2p_yamux::Config::default())
            .map(|(peer_id, muxer), _| (peer_id, StreamMuxerBox::new(muxer)));
        let transport = relay_transport
            .or_transport(quic_transport)
            .map(|either, _| either.into_inner())
            .boxed();
        let behaviour = GuardianBehaviour::new(&keypair, relay_client, &behaviour_config)
            .map_err(|error| TransportError::Initialization(error.to_string()))?;
        let swarm_config = libp2p_swarm::Config::with_tokio_executor()
            .with_idle_connection_timeout(idle_connection_timeout);
        let mut swarm = Swarm::new(transport, behaviour, local_peer_id, swarm_config);

        for server in autonat_servers {
            swarm
                .behaviour_mut()
                .autonat
                .add_server(server.peer_id, Some(server.address));
        }

        for peer in &static_peers {
            swarm.add_peer_address(peer.peer_id, peer.address.clone());
        }
        let mut listener_addresses = HashMap::new();
        for address in &listen_addresses {
            let listener_id = swarm
                .listen_on(address.clone())
                .map_err(|error| TransportError::Listen(error.to_string()))?;
            listener_addresses.insert(listener_id, address.clone());
        }

        Ok(Self {
            swarm,
            inbound_responses: HashMap::new(),
            inbound_threat_hint_responses: HashMap::new(),
            inbound_work: HashSet::new(),
            inbound_threat_hint_work: HashSet::new(),
            ingress_request_ids: HashSet::new(),
            ingress_tasks: FuturesUnordered::new(),
            threat_hint_ingress_request_ids: HashSet::new(),
            threat_hint_ingress_tasks: FuturesUnordered::new(),
            outbound_requests: HashSet::new(),
            outbound_threat_hint_requests: HashSet::new(),
            max_outbound_requests,
            max_inbound_requests,
            configured_static_peers: static_peers.into_iter().collect(),
            configured_listen_addresses: listen_addresses.into_iter().collect(),
            listener_addresses,
            active_listener_addresses: HashMap::new(),
        })
    }

    /// Returns the local libp2p peer identifier, which is transport metadata only.
    pub fn local_peer_id(&self) -> PeerId {
        *self.swarm.local_peer_id()
    }

    /// Adds a static dial address for a transport peer.
    pub fn add_static_peer(&mut self, peer: StaticPeer) -> Result<(), TransportError> {
        validate_static_peer(&peer)?;
        if self.configured_static_peers.contains(&peer) {
            return Ok(());
        }
        if self.configured_static_peers.len() >= MAX_STATIC_PEERS {
            return Err(TransportError::InvalidConfig("too many static peers"));
        }
        self.swarm
            .add_peer_address(peer.peer_id, peer.address.clone());
        self.configured_static_peers.insert(peer);
        Ok(())
    }

    /// Starts a listener, including an explicitly configured relay circuit address.
    pub fn listen_on(&mut self, address: Multiaddr) -> Result<(), TransportError> {
        validate_listen_address(&address)?;
        if self.configured_listen_addresses.contains(&address) {
            return Ok(());
        }
        if self.configured_listen_addresses.len() >= MAX_LISTEN_ADDRESSES {
            return Err(TransportError::InvalidConfig("too many listen addresses"));
        }
        let listener_id = self
            .swarm
            .listen_on(address.clone())
            .map_err(|error| TransportError::Listen(error.to_string()))?;
        self.configured_listen_addresses.insert(address.clone());
        self.listener_addresses.insert(listener_id, address);
        Ok(())
    }

    /// Returns true only after every configured listener has produced an active address.
    pub fn is_ready(&self) -> bool {
        !self.listener_addresses.is_empty()
            && self.listener_addresses.keys().all(|listener_id| {
                self.active_listener_addresses
                    .get(listener_id)
                    .is_some_and(|addresses| !addresses.is_empty())
            })
    }

    /// Returns admitted inbound collector work and outstanding outbound requests.
    pub fn pending_work(&self) -> (usize, usize) {
        (
            self.inbound_request_count(),
            self.outbound_requests.len() + self.outbound_threat_hint_requests.len(),
        )
    }

    fn inbound_request_count(&self) -> usize {
        self.inbound_work.len() + self.inbound_threat_hint_work.len()
    }

    /// Stops accepting new network traffic while retained work is drained by the owner loop.
    pub fn shutdown_listeners(&mut self) -> usize {
        let listener_ids: Vec<_> = self.listener_addresses.keys().copied().collect();
        let mut removed = 0;
        for listener_id in listener_ids {
            if self.swarm.remove_listener(listener_id) {
                removed += 1;
            }
        }
        removed
    }

    /// Sends exact opaque ballot bytes and returns the request correlation ID.
    pub fn send_ballot(
        &mut self,
        peer: PeerId,
        ballot: BallotBytes,
    ) -> Result<request_response::OutboundRequestId, TransportError> {
        if self.outbound_requests.len() + self.outbound_threat_hint_requests.len()
            >= self.max_outbound_requests
        {
            return Err(TransportError::OutboundBusy {
                max: self.max_outbound_requests,
            });
        }

        let request_id = self
            .swarm
            .behaviour_mut()
            .ballots
            .send_request(&peer, ballot);
        let inserted = self.outbound_requests.insert(request_id);
        debug_assert!(inserted, "libp2p request IDs must be unique");
        Ok(request_id)
    }

    /// Sends one canonical ThreatHint without assigning trust to the transport peer.
    pub fn send_threat_hint(
        &mut self,
        peer: PeerId,
        hint: ThreatHintBytes,
    ) -> Result<request_response::OutboundRequestId, TransportError> {
        if self.outbound_requests.len() + self.outbound_threat_hint_requests.len()
            >= self.max_outbound_requests
        {
            return Err(TransportError::OutboundBusy {
                max: self.max_outbound_requests,
            });
        }

        let request_id = self
            .swarm
            .behaviour_mut()
            .threat_hints
            .send_request(&peer, hint);
        let inserted = self.outbound_threat_hint_requests.insert(request_id);
        debug_assert!(inserted, "libp2p request IDs must be unique per behaviour");
        Ok(request_id)
    }

    /// Sends one bounded acknowledgement for a pending inbound ballot.
    pub fn respond(
        &mut self,
        request_id: request_response::InboundRequestId,
        status: AckStatus,
    ) -> Result<(), TransportError> {
        let channel = self
            .inbound_responses
            .remove(&request_id)
            .ok_or(TransportError::UnknownInboundRequest)?;
        self.inbound_work.remove(&request_id);
        self.swarm
            .behaviour_mut()
            .ballots
            .send_response(channel, status)
            .map_err(|_| TransportError::ResponseChannelClosed)
    }

    /// Sends one bounded response for a pending inbound ThreatHint.
    pub fn respond_threat_hint(
        &mut self,
        request_id: request_response::InboundRequestId,
        status: ThreatHintAckStatus,
    ) -> Result<(), TransportError> {
        let channel = self
            .inbound_threat_hint_responses
            .remove(&request_id)
            .ok_or(TransportError::UnknownInboundThreatHint)?;
        self.inbound_threat_hint_work.remove(&request_id);
        self.swarm
            .behaviour_mut()
            .threat_hints
            .send_response(channel, status)
            .map_err(|_| TransportError::ResponseChannelClosed)
    }

    /// Waits for the next application-relevant transport event.
    pub async fn next_event(&mut self) -> TransportEvent {
        loop {
            let event = self.swarm.select_next_some().await;
            if let Some(event) = self.handle_swarm_event(event) {
                return event;
            }
        }
    }

    /// Drives one event with ThreatHints rejected when no verifier boundary is configured.
    pub async fn next_sidecar_event(
        &mut self,
        ingress: &UnixBallotIngress,
    ) -> Result<TransportEvent, TransportError> {
        self.next_sidecar_event_inner(ingress, None).await
    }

    /// Drives one event through separate ballot and verified-ThreatHint boundaries.
    pub async fn next_verified_sidecar_event(
        &mut self,
        ingress: &UnixBallotIngress,
        threat_hint_ingress: &UnixThreatHintIngress,
    ) -> Result<TransportEvent, TransportError> {
        self.next_sidecar_event_inner(ingress, Some(threat_hint_ingress))
            .await
    }

    async fn next_sidecar_event_inner(
        &mut self,
        ingress: &UnixBallotIngress,
        threat_hint_ingress: Option<&UnixThreatHintIngress>,
    ) -> Result<TransportEvent, TransportError> {
        loop {
            enum Progress {
                Swarm(SwarmEvent<BehaviourEvent>),
                Ingress(IngressCompletion),
                ThreatHintIngress(ThreatHintIngressCompletion),
            }

            let progress = if self.ingress_tasks.is_empty()
                && self.threat_hint_ingress_tasks.is_empty()
            {
                Progress::Swarm(self.swarm.select_next_some().await)
            } else {
                let swarm = &mut self.swarm;
                let ingress_tasks = &mut self.ingress_tasks;
                let threat_hint_ingress_tasks = &mut self.threat_hint_ingress_tasks;
                tokio::select! {
                    event = swarm.select_next_some() => Progress::Swarm(event),
                    completion = ingress_tasks.select_next_some(), if !ingress_tasks.is_empty() => {
                        Progress::Ingress(completion)
                    }
                    completion = threat_hint_ingress_tasks.select_next_some(),
                        if !threat_hint_ingress_tasks.is_empty() => {
                            Progress::ThreatHintIngress(completion)
                    }
                }
            };

            match progress {
                Progress::Swarm(event) => {
                    let Some(event) = self.handle_swarm_event(event) else {
                        continue;
                    };
                    match event {
                        TransportEvent::InboundBallot {
                            peer,
                            request_id,
                            ballot,
                        } => {
                            let ingress = ingress.clone();
                            let inserted = self.ingress_request_ids.insert(request_id);
                            debug_assert!(inserted, "inbound request cannot start ingress twice");
                            self.ingress_tasks.push(Box::pin(async move {
                                let status = match ingress.forward(&ballot).await {
                                    Ok(status) => status,
                                    Err(
                                        IngressError::Io(_)
                                        | IngressError::Timeout
                                        | IngressError::Unavailable,
                                    ) => AckStatus::Busy,
                                    Err(_) => AckStatus::Rejected,
                                };
                                IngressCompletion {
                                    peer,
                                    request_id,
                                    status,
                                }
                            }));
                        }
                        TransportEvent::InboundThreatHint {
                            peer,
                            request_id,
                            hint,
                        } => {
                            let Some(threat_hint_ingress) = threat_hint_ingress else {
                                match self
                                    .respond_threat_hint(request_id, ThreatHintAckStatus::Rejected)
                                {
                                    Ok(()) => {
                                        return Ok(TransportEvent::InboundThreatHintProcessed {
                                            peer,
                                            status: ThreatHintAckStatus::Rejected,
                                        });
                                    }
                                    Err(TransportError::ResponseChannelClosed) => continue,
                                    Err(error) => return Err(error),
                                }
                            };
                            let ingress = threat_hint_ingress.clone();
                            let inserted = self.threat_hint_ingress_request_ids.insert(request_id);
                            debug_assert!(
                                inserted,
                                "inbound ThreatHint cannot start ingress twice"
                            );
                            self.threat_hint_ingress_tasks.push(Box::pin(async move {
                                let status = match ingress.forward(&hint).await {
                                    Ok(status) => status,
                                    Err(
                                        ThreatHintIngressError::Io(_)
                                        | ThreatHintIngressError::Timeout
                                        | ThreatHintIngressError::Unavailable,
                                    ) => ThreatHintAckStatus::Busy,
                                    Err(_) => ThreatHintAckStatus::Rejected,
                                };
                                ThreatHintIngressCompletion {
                                    peer,
                                    request_id,
                                    status,
                                }
                            }));
                        }
                        event => return Ok(event),
                    }
                }
                Progress::Ingress(completion) => {
                    if let Some(event) = self.complete_ingress(completion)? {
                        return Ok(event);
                    }
                }
                Progress::ThreatHintIngress(completion) => {
                    if let Some(event) = self.complete_threat_hint_ingress(completion)? {
                        return Ok(event);
                    }
                }
            }
        }
    }

    fn complete_threat_hint_ingress(
        &mut self,
        completion: ThreatHintIngressCompletion,
    ) -> Result<Option<TransportEvent>, TransportError> {
        self.threat_hint_ingress_request_ids
            .remove(&completion.request_id);
        if !self
            .inbound_threat_hint_responses
            .contains_key(&completion.request_id)
        {
            self.inbound_threat_hint_work.remove(&completion.request_id);
            return Ok(None);
        }

        match self.respond_threat_hint(completion.request_id, completion.status) {
            Ok(()) => Ok(Some(TransportEvent::InboundThreatHintProcessed {
                peer: completion.peer,
                status: completion.status,
            })),
            Err(TransportError::ResponseChannelClosed) => Ok(None),
            Err(error) => Err(error),
        }
    }

    fn complete_ingress(
        &mut self,
        completion: IngressCompletion,
    ) -> Result<Option<TransportEvent>, TransportError> {
        self.ingress_request_ids.remove(&completion.request_id);
        if !self.inbound_responses.contains_key(&completion.request_id) {
            self.inbound_work.remove(&completion.request_id);
            return Ok(None);
        }

        match self.respond(completion.request_id, completion.status) {
            Ok(()) => Ok(Some(TransportEvent::InboundProcessed {
                peer: completion.peer,
                status: completion.status,
            })),
            Err(TransportError::ResponseChannelClosed) => Ok(None),
            Err(error) => Err(error),
        }
    }

    fn handle_swarm_event(&mut self, event: SwarmEvent<BehaviourEvent>) -> Option<TransportEvent> {
        match event {
            SwarmEvent::NewListenAddr {
                listener_id,
                address,
            } => {
                self.active_listener_addresses
                    .entry(listener_id)
                    .or_default()
                    .insert(address.clone());
                Some(TransportEvent::Listening { address })
            }
            SwarmEvent::ExpiredListenAddr {
                listener_id,
                address,
            } => {
                if let Some(addresses) = self.active_listener_addresses.get_mut(&listener_id) {
                    addresses.remove(&address);
                }
                Some(TransportEvent::ListenerClosed {
                    address,
                    failed: false,
                })
            }
            SwarmEvent::ListenerClosed {
                listener_id,
                addresses,
                reason,
            } => {
                self.active_listener_addresses.remove(&listener_id);
                let address = addresses
                    .into_iter()
                    .next()
                    .or_else(|| self.listener_addresses.get(&listener_id).cloned())?;
                Some(TransportEvent::ListenerClosed {
                    address,
                    failed: reason.is_err(),
                })
            }
            SwarmEvent::ListenerError { listener_id, .. } => self
                .listener_addresses
                .get(&listener_id)
                .cloned()
                .map(|address| TransportEvent::ListenerFailed { address }),
            SwarmEvent::Behaviour(BehaviourEvent::Ballots(event)) => {
                self.handle_ballot_event(event)
            }
            SwarmEvent::Behaviour(BehaviourEvent::ThreatHints(event)) => {
                self.handle_threat_hint_event(event)
            }
            SwarmEvent::Behaviour(BehaviourEvent::Identify(event)) => {
                let _ = event;
                None
            }
            SwarmEvent::Behaviour(BehaviourEvent::Ping(event)) => {
                let _ = event;
                None
            }
            SwarmEvent::Behaviour(BehaviourEvent::Autonat(event)) => {
                if let autonat::Event::StatusChanged { old, new } = event {
                    Some(TransportEvent::NatStatusChanged {
                        old: NatReachability::from(&old),
                        new: NatReachability::from(&new),
                    })
                } else {
                    None
                }
            }
            SwarmEvent::Behaviour(BehaviourEvent::Relay(event)) => match event {
                relay::client::Event::ReservationReqAccepted {
                    relay_peer_id,
                    renewal,
                    ..
                } => Some(TransportEvent::RelayReservationAccepted {
                    relay_peer: relay_peer_id,
                    renewal,
                }),
                relay::client::Event::OutboundCircuitEstablished { relay_peer_id, .. } => {
                    Some(TransportEvent::RelayOutboundCircuit {
                        relay_peer: relay_peer_id,
                    })
                }
                relay::client::Event::InboundCircuitEstablished { src_peer_id, .. } => {
                    Some(TransportEvent::RelayInboundCircuit {
                        source_peer: src_peer_id,
                    })
                }
            },
            SwarmEvent::Behaviour(BehaviourEvent::Dcutr(event)) => {
                Some(TransportEvent::HolePunchFinished {
                    peer: event.remote_peer_id,
                    outcome: if event.result.is_ok() {
                        HolePunchOutcome::DirectEstablished
                    } else {
                        HolePunchOutcome::RelayFallback
                    },
                })
            }
            SwarmEvent::ConnectionEstablished {
                peer_id, endpoint, ..
            } => Some(TransportEvent::ConnectionEstablished {
                peer: peer_id,
                path: connection_path(endpoint.is_relayed()),
            }),
            SwarmEvent::ConnectionClosed {
                peer_id,
                endpoint,
                num_established,
                cause,
                ..
            } => Some(TransportEvent::ConnectionClosed {
                peer: peer_id,
                path: connection_path(endpoint.is_relayed()),
                remaining: num_established,
                failed: cause.is_some(),
            }),
            SwarmEvent::ExternalAddrConfirmed { address } => {
                Some(TransportEvent::ExternalAddressConfirmed {
                    path: connection_path(address.iter().any(|part| part == Protocol::P2pCircuit)),
                })
            }
            _ => None,
        }
    }

    fn handle_ballot_event(
        &mut self,
        event: request_response::Event<BallotBytes, AckStatus>,
    ) -> Option<TransportEvent> {
        match event {
            request_response::Event::Message {
                peer,
                message:
                    request_response::Message::Request {
                        request_id,
                        request: ballot,
                        channel,
                    },
                ..
            } => {
                if self.inbound_request_count() >= self.max_inbound_requests {
                    let _ = self
                        .swarm
                        .behaviour_mut()
                        .ballots
                        .send_response(channel, AckStatus::Busy);
                    return None;
                }
                let admitted = self.inbound_work.insert(request_id);
                debug_assert!(admitted, "libp2p request IDs must be unique");
                let previous = self.inbound_responses.insert(request_id, channel);
                debug_assert!(previous.is_none(), "libp2p request IDs must be unique");
                Some(TransportEvent::InboundBallot {
                    peer,
                    request_id,
                    ballot,
                })
            }
            request_response::Event::Message {
                peer,
                message:
                    request_response::Message::Response {
                        request_id,
                        response: status,
                    },
                ..
            } => {
                self.outbound_requests.remove(&request_id);
                Some(TransportEvent::OutboundAck {
                    peer,
                    request_id,
                    status,
                })
            }
            request_response::Event::OutboundFailure {
                peer,
                request_id,
                error,
                ..
            } => {
                self.outbound_requests.remove(&request_id);
                Some(TransportEvent::OutboundFailure {
                    peer,
                    request_id,
                    failure: RequestFailure::from(&error),
                })
            }
            request_response::Event::InboundFailure { request_id, .. } => {
                self.inbound_responses.remove(&request_id);
                if !self.ingress_request_ids.contains(&request_id) {
                    self.inbound_work.remove(&request_id);
                }
                None
            }
            request_response::Event::ResponseSent { request_id, .. } => {
                self.inbound_responses.remove(&request_id);
                self.inbound_work.remove(&request_id);
                None
            }
        }
    }

    fn handle_threat_hint_event(
        &mut self,
        event: request_response::Event<ThreatHintBytes, ThreatHintAckStatus>,
    ) -> Option<TransportEvent> {
        match event {
            request_response::Event::Message {
                peer,
                message:
                    request_response::Message::Request {
                        request_id,
                        request: hint,
                        channel,
                    },
                ..
            } => {
                if self.inbound_request_count() >= self.max_inbound_requests {
                    let _ = self
                        .swarm
                        .behaviour_mut()
                        .threat_hints
                        .send_response(channel, ThreatHintAckStatus::Busy);
                    return None;
                }
                let admitted = self.inbound_threat_hint_work.insert(request_id);
                debug_assert!(admitted, "libp2p request IDs must be unique per behaviour");
                let previous = self
                    .inbound_threat_hint_responses
                    .insert(request_id, channel);
                debug_assert!(
                    previous.is_none(),
                    "request IDs must be unique per behaviour"
                );
                Some(TransportEvent::InboundThreatHint {
                    peer,
                    request_id,
                    hint,
                })
            }
            request_response::Event::Message {
                peer,
                message:
                    request_response::Message::Response {
                        request_id,
                        response: status,
                    },
                ..
            } => {
                self.outbound_threat_hint_requests.remove(&request_id);
                Some(TransportEvent::OutboundThreatHintAck {
                    peer,
                    request_id,
                    status,
                })
            }
            request_response::Event::OutboundFailure {
                peer,
                request_id,
                error,
                ..
            } => {
                self.outbound_threat_hint_requests.remove(&request_id);
                Some(TransportEvent::OutboundThreatHintFailure {
                    peer,
                    request_id,
                    failure: RequestFailure::from(&error),
                })
            }
            request_response::Event::InboundFailure { request_id, .. } => {
                self.inbound_threat_hint_responses.remove(&request_id);
                if !self.threat_hint_ingress_request_ids.contains(&request_id) {
                    self.inbound_threat_hint_work.remove(&request_id);
                }
                None
            }
            request_response::Event::ResponseSent { request_id, .. } => {
                self.inbound_threat_hint_responses.remove(&request_id);
                self.inbound_threat_hint_work.remove(&request_id);
                None
            }
        }
    }
}

fn connection_path(relayed: bool) -> ConnectionPath {
    if relayed {
        ConnectionPath::Relayed
    } else {
        ConnectionPath::Direct
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf, sync::Arc, time::Duration};

    use super::*;
    use sha2::{Digest, Sha256};
    use tokio::{
        io::{AsyncReadExt as TokioAsyncReadExt, AsyncWriteExt},
        net::{UnixListener, UnixStream},
        sync::Notify,
    };

    fn test_config() -> GuardianP2pConfig {
        GuardianP2pConfig {
            request_timeout: Duration::from_secs(3),
            idle_connection_timeout: Duration::from_secs(3),
            ..GuardianP2pConfig::default()
        }
    }

    fn test_threat_hint() -> ThreatHintBytes {
        let envelope = ThreatHintEnvelope::new(
            "11".repeat(32),
            8_501,
            ThreatIndicatorType::Behavior,
            ThreatProofSystem::DevelopmentStubV1,
            vec![0x42; 48],
            "22".repeat(32),
            1_700_000_000,
        )
        .expect("valid test ThreatHint");
        ThreatHintBytes::from_envelope(&envelope).expect("canonical test ThreatHint")
    }

    async fn next_event_with_timeout(node: &mut GuardianP2p) -> TransportEvent {
        tokio::time::timeout(Duration::from_secs(10), node.next_event())
            .await
            .expect("two-node libp2p test timed out")
    }

    async fn next_sidecar_ballot_event(
        node: &mut GuardianP2p,
        ingress: &UnixBallotIngress,
    ) -> Result<TransportEvent, TransportError> {
        loop {
            let event = node.next_sidecar_event(ingress).await?;
            if matches!(
                event,
                TransportEvent::InboundBallot { .. }
                    | TransportEvent::InboundProcessed { .. }
                    | TransportEvent::OutboundAck { .. }
                    | TransportEvent::OutboundFailure { .. }
            ) {
                return Ok(event);
            }
        }
    }

    async fn serve_ingress_once(path: PathBuf, expected: Vec<u8>) {
        let listener = UnixListener::bind(&path).expect("bind collector ingress");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .expect("owner-only collector socket");
        let (mut stream, _) = listener.accept().await.expect("accept carrier");
        let received = read_ingress_ballot(&mut stream).await;
        assert_eq!(received, expected);
        write_ingress_ack(&mut stream, &received, "accepted").await;
    }

    async fn read_ingress_ballot(stream: &mut UnixStream) -> Vec<u8> {
        let length = stream.read_u32().await.expect("read ingress length") as usize;
        let mut received = vec![0_u8; length];
        stream
            .read_exact(&mut received)
            .await
            .expect("read exact ingress ballot");
        received
    }

    async fn write_ingress_ack(stream: &mut UnixStream, ballot: &[u8], status: &str) {
        let digest = format!("{:x}", Sha256::digest(ballot));
        let ack = format!(
            "{{\"payload_digest\":\"{digest}\",\"protocol_version\":1,\"session_id\":\"{}\",\"status\":\"{status}\"}}",
            "a".repeat(64),
        );
        stream
            .write_u32(u32::try_from(ack.len()).expect("bounded ack"))
            .await
            .expect("write ack length");
        stream.write_all(ack.as_bytes()).await.expect("write ack");
        stream.shutdown().await.expect("close acknowledgement");
    }

    async fn serve_threat_hint_ingress_once(path: PathBuf, expected: Vec<u8>, status: &str) {
        let listener = UnixListener::bind(&path).expect("bind ThreatHint ingress");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .expect("owner-only ThreatHint socket");
        let (mut stream, _) = listener.accept().await.expect("accept ThreatHint carrier");
        let received = read_ingress_ballot(&mut stream).await;
        assert_eq!(received, expected);
        let digest = format!("{:x}", Sha256::digest(&received));
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

    async fn serve_two_ingress_out_of_order(path: PathBuf) {
        let listener = UnixListener::bind(&path).expect("bind collector ingress");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .expect("owner-only collector socket");

        let (mut first_stream, _) = listener.accept().await.expect("accept first carrier");
        let first_ballot = read_ingress_ballot(&mut first_stream).await;
        let (mut second_stream, _) = listener.accept().await.expect("accept second carrier");
        let second_ballot = read_ingress_ballot(&mut second_stream).await;

        write_ingress_ack(&mut second_stream, &second_ballot, "accepted").await;
        tokio::time::sleep(Duration::from_millis(250)).await;
        write_ingress_ack(&mut first_stream, &first_ballot, "rejected").await;
    }

    async fn serve_delayed_ingress(path: PathBuf, started: Arc<Notify>, release: Arc<Notify>) {
        let listener = UnixListener::bind(&path).expect("bind collector ingress");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .expect("owner-only collector socket");
        let (mut stream, _) = listener.accept().await.expect("accept carrier");
        let ballot = read_ingress_ballot(&mut stream).await;
        started.notify_one();
        release.notified().await;
        write_ingress_ack(&mut stream, &ballot, "accepted").await;
    }

    #[test]
    fn ballot_size_is_bounded() {
        assert!(BallotBytes::new(vec![0_u8; MAX_BALLOT_BYTES]).is_ok());
        assert!(BallotBytes::new(Vec::new()).is_err());
        assert!(BallotBytes::new(vec![0_u8; MAX_BALLOT_BYTES + 1]).is_err());
    }

    #[test]
    fn threat_hint_requires_canonical_shared_schema() {
        let hint = test_threat_hint();
        assert_eq!(
            hint.parse().expect("retained hint parses").confidence_bps(),
            8_501
        );

        let mut noncanonical = hint.as_bytes().to_vec();
        noncanonical.push(b'\n');
        assert!(matches!(
            ThreatHintBytes::new(noncanonical),
            Err(TransportError::InvalidThreatHint)
        ));
        assert!(matches!(
            ThreatHintBytes::new(Vec::new()),
            Err(TransportError::ThreatHintSize(0))
        ));
        assert!(matches!(
            ThreatHintBytes::new(vec![b'x'; MAX_THREAT_HINT_BYTES + 1]),
            Err(TransportError::ThreatHintSize(_))
        ));
    }

    #[test]
    fn configuration_accepts_exact_direct_and_relay_routes() {
        let target = identity::Keypair::generate_ed25519().public().to_peer_id();
        let relay = identity::Keypair::generate_ed25519().public().to_peer_id();
        let direct = format!("/ip4/127.0.0.1/udp/4001/quic-v1/p2p/{target}")
            .parse()
            .expect("direct route");
        let relayed =
            format!("/ip4/127.0.0.1/udp/4002/quic-v1/p2p/{relay}/p2p-circuit/p2p/{target}")
                .parse()
                .expect("relay route");
        let reservation = format!("/ip4/127.0.0.1/udp/4002/quic-v1/p2p/{relay}/p2p-circuit")
            .parse()
            .expect("relay reservation");
        let config = GuardianP2pConfig {
            listen_addresses: vec![
                "/ip4/0.0.0.0/udp/0/quic-v1"
                    .parse()
                    .expect("direct listener"),
                reservation,
            ],
            static_peers: vec![
                StaticPeer {
                    peer_id: target,
                    address: direct,
                },
                StaticPeer {
                    peer_id: target,
                    address: relayed,
                },
            ],
            ..test_config()
        };

        config.validate().expect("strict routes are valid");
    }

    #[test]
    fn configuration_rejects_dns_mismatches_duplicates_and_unbounded_routes() {
        let target = identity::Keypair::generate_ed25519().public().to_peer_id();
        let other = identity::Keypair::generate_ed25519().public().to_peer_id();

        for address in [
            "/dns4/example.invalid/udp/4001/quic-v1".to_owned(),
            format!("/ip4/127.0.0.1/udp/0/quic-v1/p2p/{target}"),
            format!("/ip4/127.0.0.1/udp/4001/quic-v1/p2p/{other}"),
        ] {
            let config = GuardianP2pConfig {
                static_peers: vec![StaticPeer {
                    peer_id: target,
                    address: address.parse().expect("syntactically valid multiaddress"),
                }],
                ..test_config()
            };
            assert!(matches!(
                config.validate(),
                Err(TransportError::InvalidConfig(_))
            ));
        }

        let route = StaticPeer {
            peer_id: target,
            address: "/ip4/127.0.0.1/udp/4001/quic-v1"
                .parse()
                .expect("direct route"),
        };
        let duplicate = GuardianP2pConfig {
            static_peers: vec![route.clone(), route],
            ..test_config()
        };
        assert!(matches!(
            duplicate.validate(),
            Err(TransportError::InvalidConfig(_))
        ));

        let unbounded = GuardianP2pConfig {
            static_peers: (0..=MAX_STATIC_PEERS)
                .map(|port| StaticPeer {
                    peer_id: target,
                    address: format!("/ip4/127.0.0.1/udp/{}/quic-v1", 4000 + port)
                        .parse()
                        .expect("bounded direct route"),
                })
                .collect(),
            ..test_config()
        };
        assert!(matches!(
            unbounded.validate(),
            Err(TransportError::InvalidConfig(_))
        ));
    }

    #[test]
    fn stream_budget_is_split_without_multiplying_per_connection_capacity() {
        assert_eq!(protocol_stream_limits(2), (1, 1));
        assert_eq!(protocol_stream_limits(3), (2, 1));
        assert_eq!(protocol_stream_limits(MAX_STREAMS_PER_CONNECTION), (32, 32));

        let mut config = test_config();
        config.max_concurrent_streams_per_connection = 1;
        assert!(matches!(
            config.validate(),
            Err(TransportError::InvalidConfig(_))
        ));
    }

    #[tokio::test]
    async fn request_codec_rejects_trailing_bytes() {
        let mut frame = vec![0, 1, 7, 9];
        let mut cursor = futures::io::Cursor::new(&mut frame);
        let mut codec = BallotCodec;
        let protocol = StreamProtocol::new(BALLOT_PROTOCOL);
        let error = request_response::Codec::read_request(&mut codec, &protocol, &mut cursor)
            .await
            .expect_err("trailing bytes must fail closed");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn threat_hint_codec_rejects_trailing_bytes() {
        let hint = test_threat_hint();
        let length = u16::try_from(hint.as_bytes().len()).expect("bounded hint length");
        let mut frame = length.to_be_bytes().to_vec();
        frame.extend_from_slice(hint.as_bytes());
        frame.push(0);
        let mut cursor = futures::io::Cursor::new(&mut frame);
        let mut codec = ThreatHintCodec;
        let protocol = StreamProtocol::new(THREAT_HINT_PROTOCOL);
        let error = request_response::Codec::read_request(&mut codec, &protocol, &mut cursor)
            .await
            .expect_err("trailing bytes must fail closed");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn two_nodes_exchange_opaque_ballot_and_bounded_ack() {
        let receiver_identity = identity::Keypair::generate_ed25519();
        let receiver_peer = receiver_identity.public().to_peer_id();
        let mut receiver_config = test_config();
        receiver_config.listen_addresses.push(
            "/ip4/127.0.0.1/udp/0/quic-v1"
                .parse()
                .expect("valid test address"),
        );
        let mut receiver = GuardianP2p::new(receiver_identity, receiver_config)
            .expect("ephemeral receiver should initialize");

        let receiver_address = match next_event_with_timeout(&mut receiver).await {
            TransportEvent::Listening { address } => address,
            event => panic!("expected listener address, got {event:?}"),
        };

        let sender_identity = identity::Keypair::generate_ed25519();
        let sender_peer = sender_identity.public().to_peer_id();
        let mut sender_config = test_config();
        sender_config.static_peers.push(StaticPeer {
            peer_id: receiver_peer,
            address: receiver_address,
        });
        let mut sender = GuardianP2p::new(sender_identity, sender_config)
            .expect("ephemeral sender should initialize");

        let ballot = BallotBytes::new(b"canonical ballot bytes stay opaque".to_vec())
            .expect("bounded ballot");
        let request_id = sender
            .send_ballot(receiver_peer, ballot.clone())
            .expect("request capacity available");

        let inbound_request = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                tokio::select! {
                    event = receiver.next_event() => if let TransportEvent::InboundBallot {
                            peer,
                            request_id,
                            ballot: received,
                        } = event {
                        assert_eq!(peer, sender_peer);
                        assert_eq!(received, ballot);
                        break request_id;
                    },
                    event = sender.next_event() => {
                        if let TransportEvent::OutboundFailure { failure, .. } = event {
                            panic!("ballot request failed before delivery: {failure:?}");
                        }
                    }
                }
            }
        })
        .await
        .expect("two-node ballot delivery timed out");
        receiver
            .respond(inbound_request, AckStatus::Duplicate)
            .expect("acknowledgement channel remains open");

        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                tokio::select! {
                    event = sender.next_event() => match event {
                        TransportEvent::OutboundAck {
                            peer,
                            request_id: received_request_id,
                            status,
                        } => {
                            assert_eq!(peer, receiver_peer);
                            assert_eq!(received_request_id, request_id);
                            assert_eq!(status, AckStatus::Duplicate);
                            break;
                        }
                        TransportEvent::OutboundFailure { failure, .. } => {
                            panic!("ballot acknowledgement failed: {failure:?}");
                        }
                        _ => {}
                    },
                    _ = receiver.next_event() => {}
                }
            }
        })
        .await
        .expect("two-node acknowledgement timed out");
    }

    #[tokio::test]
    async fn two_nodes_exchange_canonical_threat_hint_on_independent_protocol() {
        let receiver_identity = identity::Keypair::generate_ed25519();
        let receiver_peer = receiver_identity.public().to_peer_id();
        let mut receiver_config = test_config();
        receiver_config.listen_addresses.push(
            "/ip4/127.0.0.1/udp/0/quic-v1"
                .parse()
                .expect("valid test address"),
        );
        let mut receiver = GuardianP2p::new(receiver_identity, receiver_config)
            .expect("ephemeral receiver should initialize");
        let receiver_address = match next_event_with_timeout(&mut receiver).await {
            TransportEvent::Listening { address } => address,
            event => panic!("expected listener address, got {event:?}"),
        };

        let sender_identity = identity::Keypair::generate_ed25519();
        let sender_peer = sender_identity.public().to_peer_id();
        let mut sender_config = test_config();
        sender_config.static_peers.push(StaticPeer {
            peer_id: receiver_peer,
            address: receiver_address,
        });
        let mut sender = GuardianP2p::new(sender_identity, sender_config)
            .expect("ephemeral sender should initialize");
        let hint = test_threat_hint();
        let request_id = sender
            .send_threat_hint(receiver_peer, hint.clone())
            .expect("ThreatHint request capacity available");

        let inbound_request = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                tokio::select! {
                    event = receiver.next_event() => if let TransportEvent::InboundThreatHint {
                        peer,
                        request_id,
                        hint: received,
                    } = event {
                        assert_eq!(peer, sender_peer);
                        assert_eq!(received, hint);
                        break request_id;
                    },
                    event = sender.next_event() => {
                        if let TransportEvent::OutboundThreatHintFailure { failure, .. } = event {
                            panic!("ThreatHint request failed before delivery: {failure:?}");
                        }
                    }
                }
            }
        })
        .await
        .expect("two-node ThreatHint delivery timed out");
        receiver
            .respond_threat_hint(inbound_request, ThreatHintAckStatus::Accepted)
            .expect("ThreatHint acknowledgement channel remains open");

        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                tokio::select! {
                    event = sender.next_event() => match event {
                        TransportEvent::OutboundThreatHintAck {
                            peer,
                            request_id: received_request_id,
                            status,
                        } => {
                            assert_eq!(peer, receiver_peer);
                            assert_eq!(received_request_id, request_id);
                            assert_eq!(status, ThreatHintAckStatus::Accepted);
                            break;
                        }
                        TransportEvent::OutboundThreatHintFailure { failure, .. } => {
                            panic!("ThreatHint acknowledgement failed: {failure:?}");
                        }
                        _ => {}
                    },
                    _ = receiver.next_event() => {}
                }
            }
        })
        .await
        .expect("two-node ThreatHint acknowledgement timed out");
    }

    #[tokio::test]
    async fn mixed_protocol_inbound_work_shares_one_admission_cap() {
        let receiver_identity = identity::Keypair::generate_ed25519();
        let receiver_peer = receiver_identity.public().to_peer_id();
        let mut receiver_config = test_config();
        receiver_config.max_concurrent_requests = 1;
        receiver_config.listen_addresses.push(
            "/ip4/127.0.0.1/udp/0/quic-v1"
                .parse()
                .expect("valid test address"),
        );
        let mut receiver = GuardianP2p::new(receiver_identity, receiver_config)
            .expect("ephemeral receiver should initialize");
        let receiver_address = match next_event_with_timeout(&mut receiver).await {
            TransportEvent::Listening { address } => address,
            event => panic!("expected listener address, got {event:?}"),
        };

        let mut sender_config = test_config();
        sender_config.static_peers.push(StaticPeer {
            peer_id: receiver_peer,
            address: receiver_address,
        });
        let mut sender = GuardianP2p::new(identity::Keypair::generate_ed25519(), sender_config)
            .expect("ephemeral sender should initialize");
        sender
            .send_threat_hint(receiver_peer, test_threat_hint())
            .expect("ThreatHint request capacity available");

        let inbound_hint = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                tokio::select! {
                    event = receiver.next_event() => {
                        if let TransportEvent::InboundThreatHint { request_id, .. } = event {
                            break request_id;
                        }
                    },
                    event = sender.next_event() => {
                        if let TransportEvent::OutboundThreatHintFailure { failure, .. } = event {
                            panic!("ThreatHint request failed before admission: {failure:?}");
                        }
                    }
                }
            }
        })
        .await
        .expect("ThreatHint did not occupy the shared inbound slot");
        assert_eq!(receiver.pending_work(), (1, 0));

        let ballot_request = sender
            .send_ballot(
                receiver_peer,
                BallotBytes::new(b"mixed-protocol overflow ballot".to_vec())
                    .expect("bounded ballot"),
            )
            .expect("ballot request capacity available");
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                tokio::select! {
                    event = receiver.next_event() => {
                        if matches!(event, TransportEvent::InboundBallot { .. }) {
                            panic!("ballot bypassed the shared inbound admission cap");
                        }
                    },
                    event = sender.next_event() => match event {
                        TransportEvent::OutboundAck { request_id, status, .. }
                            if request_id == ballot_request =>
                        {
                            assert_eq!(status, AckStatus::Busy);
                            break;
                        }
                        TransportEvent::OutboundFailure { request_id, failure, .. }
                            if request_id == ballot_request =>
                        {
                            panic!("overflow ballot failed before busy ACK: {failure:?}");
                        }
                        _ => {}
                    }
                }
            }
        })
        .await
        .expect("mixed-protocol busy acknowledgement timed out");

        assert_eq!(receiver.pending_work(), (1, 0));
        receiver
            .respond_threat_hint(inbound_hint, ThreatHintAckStatus::Rejected)
            .expect("held ThreatHint response channel remains open");
        assert_eq!(receiver.pending_work(), (0, 0));
    }

    #[tokio::test]
    async fn operated_sidecar_rejects_threat_hint_without_dedicated_verifier() {
        let directory = tempfile::tempdir().expect("temporary ingress directory");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("owner-only ingress directory");
        let ingress = UnixBallotIngress::configured(
            directory.path().join("unused-ballot.sock"),
            Duration::from_secs(2),
        )
        .expect("safe configured ballot ingress");

        let receiver_identity = identity::Keypair::generate_ed25519();
        let receiver_peer = receiver_identity.public().to_peer_id();
        let mut receiver_config = test_config();
        receiver_config.listen_addresses.push(
            "/ip4/127.0.0.1/udp/0/quic-v1"
                .parse()
                .expect("valid test address"),
        );
        let mut receiver =
            GuardianP2p::new(receiver_identity, receiver_config).expect("receiver initializes");
        let receiver_address = match next_event_with_timeout(&mut receiver).await {
            TransportEvent::Listening { address } => address,
            event => panic!("expected listener address, got {event:?}"),
        };

        let mut sender_config = test_config();
        sender_config.static_peers.push(StaticPeer {
            peer_id: receiver_peer,
            address: receiver_address,
        });
        let mut sender = GuardianP2p::new(identity::Keypair::generate_ed25519(), sender_config)
            .expect("sender initializes");
        let request_id = sender
            .send_threat_hint(receiver_peer, test_threat_hint())
            .expect("send canonical ThreatHint");

        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                tokio::select! {
                    event = receiver.next_sidecar_event(&ingress) => {
                        if let TransportEvent::InboundThreatHintProcessed { status, .. } =
                            event.expect("sidecar event")
                        {
                            assert_eq!(status, ThreatHintAckStatus::Rejected);
                            break;
                        }
                    },
                    event = sender.next_event() => {
                        if let TransportEvent::OutboundThreatHintFailure { failure, .. } = event {
                            panic!("ThreatHint request failed: {failure:?}");
                        }
                    }
                }
            }
        })
        .await
        .expect("sidecar fail-closed response timed out");

        match next_event_with_timeout(&mut sender).await {
            TransportEvent::OutboundThreatHintAck {
                request_id: received,
                status,
                ..
            } => {
                assert_eq!(received, request_id);
                assert_eq!(status, ThreatHintAckStatus::Rejected);
            }
            event => panic!("expected rejected ThreatHint acknowledgement, got {event:?}"),
        }
        assert_eq!(receiver.pending_work(), (0, 0));
    }

    #[tokio::test]
    async fn operated_sidecar_forwards_threat_hint_to_dedicated_verifier() {
        let directory = tempfile::tempdir().expect("temporary ingress directory");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("owner-only ingress directory");
        let ballot_ingress = UnixBallotIngress::configured(
            directory.path().join("unused-ballot.sock"),
            Duration::from_secs(2),
        )
        .expect("safe configured ballot ingress");
        let threat_hint = test_threat_hint();
        let threat_hint_path = directory.path().join("threat-hint.sock");
        let verifier_task = tokio::spawn(serve_threat_hint_ingress_once(
            threat_hint_path.clone(),
            threat_hint.as_bytes().to_vec(),
            "accepted",
        ));
        tokio::task::yield_now().await;
        let threat_hint_ingress =
            UnixThreatHintIngress::new(threat_hint_path, Duration::from_secs(2))
                .expect("owner-only ThreatHint ingress");

        let receiver_identity = identity::Keypair::generate_ed25519();
        let receiver_peer = receiver_identity.public().to_peer_id();
        let mut receiver_config = test_config();
        receiver_config.listen_addresses.push(
            "/ip4/127.0.0.1/udp/0/quic-v1"
                .parse()
                .expect("valid test address"),
        );
        let mut receiver =
            GuardianP2p::new(receiver_identity, receiver_config).expect("receiver initializes");
        let receiver_address = match next_event_with_timeout(&mut receiver).await {
            TransportEvent::Listening { address } => address,
            event => panic!("expected listener address, got {event:?}"),
        };

        let mut sender_config = test_config();
        sender_config.static_peers.push(StaticPeer {
            peer_id: receiver_peer,
            address: receiver_address,
        });
        let mut sender = GuardianP2p::new(identity::Keypair::generate_ed25519(), sender_config)
            .expect("sender initializes");
        let request_id = sender
            .send_threat_hint(receiver_peer, threat_hint)
            .expect("send canonical ThreatHint");

        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                tokio::select! {
                    event = receiver.next_verified_sidecar_event(
                        &ballot_ingress,
                        &threat_hint_ingress,
                    ) => {
                        if let TransportEvent::InboundThreatHintProcessed { status, .. } =
                            event.expect("sidecar event")
                        {
                            assert_eq!(status, ThreatHintAckStatus::Accepted);
                            break;
                        }
                    },
                    event = sender.next_event() => {
                        if let TransportEvent::OutboundThreatHintFailure { failure, .. } = event {
                            panic!("ThreatHint request failed: {failure:?}");
                        }
                    }
                }
            }
        })
        .await
        .expect("verified sidecar response timed out");
        verifier_task.await.expect("verifier task");

        match next_event_with_timeout(&mut sender).await {
            TransportEvent::OutboundThreatHintAck {
                request_id: received,
                status,
                ..
            } => {
                assert_eq!(received, request_id);
                assert_eq!(status, ThreatHintAckStatus::Accepted);
            }
            event => panic!("expected accepted ThreatHint acknowledgement, got {event:?}"),
        }
        assert_eq!(receiver.pending_work(), (0, 0));
    }

    #[tokio::test]
    async fn canceled_threat_hint_releases_its_independent_work_slot() {
        let receiver_identity = identity::Keypair::generate_ed25519();
        let receiver_peer = receiver_identity.public().to_peer_id();
        let mut receiver_config = test_config();
        receiver_config.request_timeout = Duration::from_millis(150);
        receiver_config.listen_addresses.push(
            "/ip4/127.0.0.1/udp/0/quic-v1"
                .parse()
                .expect("valid test address"),
        );
        let mut receiver =
            GuardianP2p::new(receiver_identity, receiver_config).expect("receiver initializes");
        let receiver_address = match next_event_with_timeout(&mut receiver).await {
            TransportEvent::Listening { address } => address,
            event => panic!("expected listener address, got {event:?}"),
        };

        let mut sender_config = test_config();
        sender_config.request_timeout = Duration::from_millis(150);
        sender_config.static_peers.push(StaticPeer {
            peer_id: receiver_peer,
            address: receiver_address,
        });
        let mut sender = GuardianP2p::new(identity::Keypair::generate_ed25519(), sender_config)
            .expect("sender initializes");
        sender
            .send_threat_hint(receiver_peer, test_threat_hint())
            .expect("send canonical ThreatHint");

        let inbound_request = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                tokio::select! {
                    event = receiver.next_event() => {
                        if let TransportEvent::InboundThreatHint { request_id, .. } = event {
                            break request_id;
                        }
                    },
                    event = sender.next_event() => {
                        if let TransportEvent::OutboundThreatHintFailure { failure, .. } = event {
                            panic!("ThreatHint failed before inbound delivery: {failure:?}");
                        }
                    }
                }
            }
        })
        .await
        .expect("ThreatHint did not reach receiver");
        assert!(receiver
            .inbound_threat_hint_responses
            .contains_key(&inbound_request));
        assert!(receiver.inbound_threat_hint_work.contains(&inbound_request));

        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                tokio::select! {
                    event = sender.next_event() => {
                        if let TransportEvent::OutboundThreatHintFailure { failure, .. } = event {
                            assert!(matches!(
                                failure,
                                RequestFailure::Timeout
                                    | RequestFailure::ConnectionClosed
                                    | RequestFailure::Io
                            ));
                            break;
                        }
                    },
                    _ = receiver.next_event() => {}
                }
            }
        })
        .await
        .expect("ThreatHint request did not time out");

        let cleanup_deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        while receiver
            .inbound_threat_hint_responses
            .contains_key(&inbound_request)
            && tokio::time::Instant::now() < cleanup_deadline
        {
            let _ = tokio::time::timeout_at(cleanup_deadline, receiver.next_event()).await;
        }
        assert!(!receiver
            .inbound_threat_hint_responses
            .contains_key(&inbound_request));
        assert!(!receiver.inbound_threat_hint_work.contains(&inbound_request));
        assert_eq!(receiver.pending_work(), (0, 0));
    }

    #[tokio::test]
    async fn network_ballot_is_processed_by_owner_only_ingress_before_ack() {
        let directory = tempfile::tempdir().expect("temporary ingress directory");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("owner-only ingress directory");
        let socket_path = directory.path().join("guardian.sock");
        let ballot =
            BallotBytes::new(b"network to collector exact bytes".to_vec()).expect("bounded ballot");
        let ingress_server = tokio::spawn(serve_ingress_once(
            socket_path.clone(),
            ballot.as_bytes().to_vec(),
        ));
        tokio::task::yield_now().await;
        let ingress = UnixBallotIngress::new(&socket_path, Duration::from_secs(2))
            .expect("validated ingress");

        let receiver_identity = identity::Keypair::generate_ed25519();
        let receiver_peer = receiver_identity.public().to_peer_id();
        let mut receiver_config = test_config();
        receiver_config.listen_addresses.push(
            "/ip4/127.0.0.1/udp/0/quic-v1"
                .parse()
                .expect("valid test address"),
        );
        let mut receiver =
            GuardianP2p::new(receiver_identity, receiver_config).expect("receiver initializes");
        let receiver_address = match next_event_with_timeout(&mut receiver).await {
            TransportEvent::Listening { address } => address,
            event => panic!("expected listener address, got {event:?}"),
        };

        let sender_identity = identity::Keypair::generate_ed25519();
        let mut sender_config = test_config();
        sender_config.static_peers.push(StaticPeer {
            peer_id: receiver_peer,
            address: receiver_address,
        });
        let mut sender =
            GuardianP2p::new(sender_identity, sender_config).expect("sender initializes");
        let request_id = sender
            .send_ballot(receiver_peer, ballot)
            .expect("send bounded ballot");

        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                tokio::select! {
                    event = receiver.next_sidecar_event(&ingress) => {
                        if let TransportEvent::InboundProcessed { peer, status } =
                            event.expect("sidecar event")
                        {
                            assert_eq!(peer, sender.local_peer_id());
                            assert_eq!(status, AckStatus::Accepted);
                            break;
                        }
                    },
                    event = sender.next_event() => {
                        if let TransportEvent::OutboundFailure { failure, .. } = event {
                            panic!("ballot request failed: {failure:?}");
                        }
                    }
                }
            }
        })
        .await
        .expect("sidecar processing timed out");

        match next_event_with_timeout(&mut sender).await {
            TransportEvent::OutboundAck {
                request_id: received,
                status,
                ..
            } => {
                assert_eq!(received, request_id);
                assert_eq!(status, AckStatus::Accepted);
            }
            event => panic!("expected accepted acknowledgement, got {event:?}"),
        }
        ingress_server.await.expect("collector ingress task");
    }

    #[tokio::test]
    async fn slow_ingress_does_not_stop_swarm_progress() {
        let directory = tempfile::tempdir().expect("temporary ingress directory");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("owner-only ingress directory");
        let socket_path = directory.path().join("guardian.sock");
        let ingress_server = tokio::spawn(serve_two_ingress_out_of_order(socket_path.clone()));
        tokio::task::yield_now().await;
        let ingress = UnixBallotIngress::new(&socket_path, Duration::from_secs(2))
            .expect("validated ingress");

        let receiver_identity = identity::Keypair::generate_ed25519();
        let receiver_peer = receiver_identity.public().to_peer_id();
        let mut receiver_config = test_config();
        receiver_config.listen_addresses.push(
            "/ip4/127.0.0.1/udp/0/quic-v1"
                .parse()
                .expect("valid test address"),
        );
        let mut receiver =
            GuardianP2p::new(receiver_identity, receiver_config).expect("receiver initializes");
        let receiver_address = match next_event_with_timeout(&mut receiver).await {
            TransportEvent::Listening { address } => address,
            event => panic!("expected listener address, got {event:?}"),
        };

        let mut sender_one_config = test_config();
        sender_one_config.static_peers.push(StaticPeer {
            peer_id: receiver_peer,
            address: receiver_address.clone(),
        });
        let mut sender_one =
            GuardianP2p::new(identity::Keypair::generate_ed25519(), sender_one_config)
                .expect("first sender initializes");

        let mut sender_two_config = test_config();
        sender_two_config.static_peers.push(StaticPeer {
            peer_id: receiver_peer,
            address: receiver_address,
        });
        let mut sender_two =
            GuardianP2p::new(identity::Keypair::generate_ed25519(), sender_two_config)
                .expect("second sender initializes");

        sender_one
            .send_ballot(
                receiver_peer,
                BallotBytes::new(b"first slow ballot".to_vec()).expect("bounded ballot"),
            )
            .expect("send first ballot");
        sender_two
            .send_ballot(
                receiver_peer,
                BallotBytes::new(b"second fast ballot".to_vec()).expect("bounded ballot"),
            )
            .expect("send second ballot");

        let first_status = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                tokio::select! {
                    event = receiver.next_sidecar_event(&ingress) => {
                        if let TransportEvent::InboundProcessed { status, .. } =
                            event.expect("sidecar event")
                        {
                            break status;
                        }
                    },
                    event = sender_one.next_event() => {
                        if let TransportEvent::OutboundFailure { failure, .. } = event {
                            panic!("first ballot request failed: {failure:?}");
                        }
                    },
                    event = sender_two.next_event() => {
                        if let TransportEvent::OutboundFailure { failure, .. } = event {
                            panic!("second ballot request failed: {failure:?}");
                        }
                    }
                }
            }
        })
        .await
        .expect("concurrent sidecar processing timed out");
        assert_eq!(first_status, AckStatus::Accepted);

        let second_status = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                tokio::select! {
                    event = receiver.next_sidecar_event(&ingress) => {
                        if let TransportEvent::InboundProcessed { status, .. } =
                            event.expect("sidecar event")
                        {
                            break status;
                        }
                    },
                    _ = sender_one.next_event() => {},
                    _ = sender_two.next_event() => {}
                }
            }
        })
        .await
        .expect("delayed sidecar processing timed out");
        assert_eq!(second_status, AckStatus::Rejected);
        ingress_server.await.expect("collector ingress task");
    }

    #[tokio::test]
    async fn canceled_peer_keeps_capacity_until_ingress_finishes() {
        let directory = tempfile::tempdir().expect("temporary ingress directory");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("owner-only ingress directory");
        let socket_path = directory.path().join("guardian.sock");
        let started = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let ingress_server = tokio::spawn(serve_delayed_ingress(
            socket_path.clone(),
            Arc::clone(&started),
            Arc::clone(&release),
        ));
        tokio::task::yield_now().await;
        let ingress = UnixBallotIngress::new(&socket_path, Duration::from_secs(2))
            .expect("validated ingress");

        let receiver_identity = identity::Keypair::generate_ed25519();
        let receiver_peer = receiver_identity.public().to_peer_id();
        let mut receiver_config = test_config();
        receiver_config.request_timeout = Duration::from_millis(200);
        receiver_config.max_concurrent_requests = 1;
        receiver_config.listen_addresses.push(
            "/ip4/127.0.0.1/udp/0/quic-v1"
                .parse()
                .expect("valid test address"),
        );
        let mut receiver =
            GuardianP2p::new(receiver_identity, receiver_config).expect("receiver initializes");
        let receiver_address = match next_event_with_timeout(&mut receiver).await {
            TransportEvent::Listening { address } => address,
            event => panic!("expected listener address, got {event:?}"),
        };

        let mut sender_config = test_config();
        sender_config.request_timeout = Duration::from_millis(200);
        sender_config.static_peers.push(StaticPeer {
            peer_id: receiver_peer,
            address: receiver_address,
        });
        let mut sender = GuardianP2p::new(identity::Keypair::generate_ed25519(), sender_config)
            .expect("sender initializes");
        sender
            .send_ballot(
                receiver_peer,
                BallotBytes::new(b"peer cancels before collector".to_vec())
                    .expect("bounded ballot"),
            )
            .expect("send ballot");

        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                tokio::select! {
                    _ = started.notified() => break,
                    event = next_sidecar_ballot_event(&mut receiver, &ingress) => {
                        panic!("sidecar unexpectedly completed before release: {event:?}");
                    },
                    event = sender.next_event() => {
                        if let TransportEvent::OutboundFailure { failure, .. } = event {
                            panic!("request failed before reaching ingress: {failure:?}");
                        }
                    }
                }
            }
        })
        .await
        .expect("collector did not receive ballot");

        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                tokio::select! {
                    event = next_sidecar_ballot_event(&mut receiver, &ingress) => {
                        panic!("sidecar unexpectedly completed while ingress blocked: {event:?}");
                    },
                    event = sender.next_event() => {
                        if let TransportEvent::OutboundFailure { failure, .. } = event {
                            assert!(matches!(
                                failure,
                                RequestFailure::Timeout
                                    | RequestFailure::ConnectionClosed
                                    | RequestFailure::Io
                            ));
                            break;
                        }
                    }
                }
            }
        })
        .await
        .expect("peer request did not time out");

        assert!(
            tokio::time::timeout(
                Duration::from_millis(100),
                next_sidecar_ballot_event(&mut receiver, &ingress),
            )
            .await
            .is_err(),
            "canceled peer must not create an application event"
        );
        assert!(receiver.inbound_responses.is_empty());
        assert_eq!(receiver.inbound_work.len(), 1);
        assert_eq!(receiver.ingress_request_ids.len(), 1);

        release.notify_one();
        ingress_server.await.expect("collector ingress task");
        assert!(
            tokio::time::timeout(
                Duration::from_millis(100),
                next_sidecar_ballot_event(&mut receiver, &ingress),
            )
            .await
            .is_err(),
            "orphaned ingress completion must be discarded without an error"
        );
        assert!(receiver.inbound_work.is_empty());
        assert!(receiver.ingress_request_ids.is_empty());
    }

    #[tokio::test]
    async fn closed_response_channel_race_is_nonfatal() {
        let directory = tempfile::tempdir().expect("temporary ingress directory");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("owner-only ingress directory");
        let socket_path = directory.path().join("guardian.sock");
        let started = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let ingress_server = tokio::spawn(serve_delayed_ingress(
            socket_path.clone(),
            Arc::clone(&started),
            Arc::clone(&release),
        ));
        tokio::task::yield_now().await;
        let ingress = UnixBallotIngress::new(&socket_path, Duration::from_secs(2))
            .expect("validated ingress");

        let receiver_identity = identity::Keypair::generate_ed25519();
        let receiver_peer = receiver_identity.public().to_peer_id();
        let mut receiver_config = test_config();
        receiver_config.request_timeout = Duration::from_millis(200);
        receiver_config.listen_addresses.push(
            "/ip4/127.0.0.1/udp/0/quic-v1"
                .parse()
                .expect("valid test address"),
        );
        let mut receiver =
            GuardianP2p::new(receiver_identity, receiver_config).expect("receiver initializes");
        let receiver_address = match next_event_with_timeout(&mut receiver).await {
            TransportEvent::Listening { address } => address,
            event => panic!("expected listener address, got {event:?}"),
        };

        let mut sender_config = test_config();
        sender_config.request_timeout = Duration::from_millis(200);
        sender_config.static_peers.push(StaticPeer {
            peer_id: receiver_peer,
            address: receiver_address,
        });
        let mut sender = GuardianP2p::new(identity::Keypair::generate_ed25519(), sender_config)
            .expect("sender initializes");
        sender
            .send_ballot(
                receiver_peer,
                BallotBytes::new(b"closed response channel race".to_vec()).expect("bounded ballot"),
            )
            .expect("send ballot");

        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                tokio::select! {
                    _ = started.notified() => break,
                    event = next_sidecar_ballot_event(&mut receiver, &ingress) => {
                        panic!("sidecar unexpectedly completed before release: {event:?}");
                    },
                    _ = sender.next_event() => {}
                }
            }
        })
        .await
        .expect("collector did not receive ballot");

        let failed_request = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                tokio::select! {
                    event = receiver.swarm.select_next_some() => {
                        if let SwarmEvent::Behaviour(BehaviourEvent::Ballots(
                            request_response::Event::InboundFailure { request_id, .. },
                        )) = event
                        {
                            break request_id;
                        }
                    },
                    _ = sender.next_event() => {}
                }
            }
        })
        .await
        .expect("receiver did not close the response channel");
        assert!(receiver.inbound_responses.contains_key(&failed_request));

        release.notify_one();
        ingress_server.await.expect("collector ingress task");
        let completion = tokio::time::timeout(
            Duration::from_secs(1),
            receiver.ingress_tasks.select_next_some(),
        )
        .await
        .expect("ingress completion timed out");
        assert_eq!(completion.request_id, failed_request);
        assert!(receiver
            .complete_ingress(completion)
            .expect("closed automatic response channel is nonfatal")
            .is_none());
        assert!(receiver.inbound_responses.is_empty());
        assert!(receiver.inbound_work.is_empty());
        assert!(receiver.ingress_request_ids.is_empty());
    }

    #[test]
    fn outbound_requests_are_bounded_before_dialing() {
        let mut config = test_config();
        config.max_concurrent_requests = 1;
        let identity = identity::Keypair::generate_ed25519();
        let peer = identity::Keypair::generate_ed25519().public().to_peer_id();
        let mut node = GuardianP2p::new(identity, config).expect("ephemeral node initializes");
        let ballot = BallotBytes::new(vec![1]).expect("bounded ballot");

        node.send_ballot(peer, ballot.clone())
            .expect("first request is admitted");
        assert!(matches!(
            node.send_ballot(peer, ballot),
            Err(TransportError::OutboundBusy { max: 1 })
        ));
        assert!(matches!(
            node.send_threat_hint(peer, test_threat_hint()),
            Err(TransportError::OutboundBusy { max: 1 })
        ));
    }
}

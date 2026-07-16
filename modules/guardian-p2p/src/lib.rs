#![deny(warnings)]
//! Opaque Guardian ballot transport over libp2p.
//!
//! This crate carries pre-validated ballot envelopes only. In particular, a
//! [`libp2p_identity::PeerId`] is connection metadata and is never a Guardian identity,
//! membership record, or signing-key assignment.

pub mod ingress;

use std::{
    collections::{HashMap, HashSet},
    io,
    time::Duration,
};

use async_trait::async_trait;
use futures::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    StreamExt,
};
use libp2p_autonat as autonat;
use libp2p_connection_limits as connection_limits;
use libp2p_core::{muxing::StreamMuxerBox, upgrade, Multiaddr, Transport};
use libp2p_dcutr as dcutr;
use libp2p_identify as identify;
use libp2p_identity::{self as identity, PeerId};
use libp2p_ping as ping;
use libp2p_relay as relay;
use libp2p_request_response as request_response;
use libp2p_swarm::{NetworkBehaviour, StreamProtocol, Swarm, SwarmEvent};
use thiserror::Error;

use crate::ingress::{IngressError, UnixBallotIngress};

/// Direct request-response protocol for opaque Guardian ballot envelopes.
pub const BALLOT_PROTOCOL: &str = "/prometheus/guardian-ballot/1.0.0";
/// Maximum permitted ballot envelope size, matching the canonical verifier.
pub const MAX_BALLOT_BYTES: usize = 8_192;

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
}

/// A configured transport peer. It intentionally has no Guardian identity fields.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StaticPeer {
    pub peer_id: PeerId,
    pub address: Multiaddr,
}

/// Bounded transport settings for a Guardian sidecar.
#[derive(Clone, Debug)]
pub struct GuardianP2pConfig {
    pub listen_addresses: Vec<Multiaddr>,
    pub static_peers: Vec<StaticPeer>,
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
            request_timeout: Duration::from_secs(10),
            idle_connection_timeout: Duration::from_secs(30),
            max_concurrent_requests: 32,
            max_concurrent_streams_per_connection: 1,
            max_pending_incoming_connections: 8,
            max_pending_outgoing_connections: 8,
            max_established_incoming_connections: 16,
            max_established_outgoing_connections: 16,
            max_established_connections_per_peer: 2,
        }
    }
}

impl GuardianP2pConfig {
    fn validate(&self) -> Result<(), TransportError> {
        if self.request_timeout.is_zero() || self.idle_connection_timeout.is_zero() {
            return Err(TransportError::InvalidConfig("timeouts must be non-zero"));
        }

        if self.max_concurrent_requests == 0
            || self.max_concurrent_streams_per_connection == 0
            || self.max_pending_incoming_connections == 0
            || self.max_pending_outgoing_connections == 0
            || self.max_established_incoming_connections == 0
            || self.max_established_outgoing_connections == 0
            || self.max_established_connections_per_peer == 0
        {
            return Err(TransportError::InvalidConfig(
                "connection limits must be non-zero",
            ));
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
}

/// Events relevant to a sidecar's ballot processing loop.
#[derive(Debug)]
pub enum TransportEvent {
    Listening {
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
        require_stream_end(io).await?;
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
        require_stream_end(io).await?;
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

async fn require_stream_end<T>(io: &mut T) -> io::Result<()>
where
    T: AsyncRead + Unpin,
{
    let mut trailing = [0_u8; 1];
    if io.read(&mut trailing).await? != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Guardian ballot frame contains trailing bytes",
        ));
    }
    Ok(())
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
        let ballots = request_response::Behaviour::with_codec(
            BallotCodec,
            [(
                StreamProtocol::new(BALLOT_PROTOCOL),
                request_response::ProtocolSupport::Full,
            )],
            request_response::Config::default()
                .with_request_timeout(config.request_timeout)
                .with_max_concurrent_streams(config.max_concurrent_streams_per_connection),
        );

        Ok(Self {
            ballots,
            identify: identify::Behaviour::new(identify::Config::new(
                "/prometheus/guardian/1.0.0".to_owned(),
                keypair.public(),
            )),
            ping: ping::Behaviour::new(ping::Config::new()),
            autonat: autonat::Behaviour::new(local_peer_id, autonat::Config::default()),
            relay: relay_client,
            dcutr: dcutr::Behaviour::new(local_peer_id),
            limits: connection_limits::Behaviour::new(config.connection_limits()),
        })
    }
}

#[derive(Debug)]
enum BehaviourEvent {
    Ballots(request_response::Event<BallotBytes, AckStatus>),
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
    outbound_requests: HashSet<request_response::OutboundRequestId>,
    max_outbound_requests: usize,
    max_inbound_requests: usize,
}

impl GuardianP2p {
    /// Builds a QUIC-only direct transport plus relay client transport.
    pub fn new(
        keypair: identity::Keypair,
        config: GuardianP2pConfig,
    ) -> Result<Self, TransportError> {
        config.validate()?;
        let static_peers = config.static_peers.clone();
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

        for peer in static_peers {
            swarm.add_peer_address(peer.peer_id, peer.address);
        }
        for address in config.listen_addresses {
            swarm
                .listen_on(address)
                .map_err(|error| TransportError::Listen(error.to_string()))?;
        }

        Ok(Self {
            swarm,
            inbound_responses: HashMap::new(),
            outbound_requests: HashSet::new(),
            max_outbound_requests,
            max_inbound_requests,
        })
    }

    /// Returns the local libp2p peer identifier, which is transport metadata only.
    pub fn local_peer_id(&self) -> PeerId {
        *self.swarm.local_peer_id()
    }

    /// Adds a static dial address for a transport peer.
    pub fn add_static_peer(&mut self, peer: StaticPeer) {
        self.swarm.add_peer_address(peer.peer_id, peer.address);
    }

    /// Starts a listener, including an explicitly configured relay circuit address.
    pub fn listen_on(&mut self, address: Multiaddr) -> Result<(), TransportError> {
        self.swarm
            .listen_on(address)
            .map(|_| ())
            .map_err(|error| TransportError::Listen(error.to_string()))
    }

    /// Sends exact opaque ballot bytes and returns the request correlation ID.
    pub fn send_ballot(
        &mut self,
        peer: PeerId,
        ballot: BallotBytes,
    ) -> Result<request_response::OutboundRequestId, TransportError> {
        if self.outbound_requests.len() >= self.max_outbound_requests {
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
        self.swarm
            .behaviour_mut()
            .ballots
            .send_response(channel, status)
            .map_err(|_| TransportError::ResponseChannelClosed)
    }

    /// Waits for the next application-relevant transport event.
    pub async fn next_event(&mut self) -> TransportEvent {
        loop {
            match self.swarm.select_next_some().await {
                SwarmEvent::NewListenAddr { address, .. } => {
                    return TransportEvent::Listening { address };
                }
                SwarmEvent::Behaviour(BehaviourEvent::Ballots(event)) => {
                    if let Some(event) = self.handle_ballot_event(event) {
                        return event;
                    }
                }
                SwarmEvent::Behaviour(BehaviourEvent::Identify(event)) => {
                    let _ = event;
                }
                SwarmEvent::Behaviour(BehaviourEvent::Ping(event)) => {
                    let _ = event;
                }
                SwarmEvent::Behaviour(BehaviourEvent::Autonat(event)) => {
                    let _ = event;
                }
                SwarmEvent::Behaviour(BehaviourEvent::Relay(event)) => {
                    let _ = event;
                }
                SwarmEvent::Behaviour(BehaviourEvent::Dcutr(event)) => {
                    let _ = event;
                }
                _ => {}
            }
        }
    }

    /// Drives one event and completes inbound ballots through the local collector.
    pub async fn next_sidecar_event(
        &mut self,
        ingress: &UnixBallotIngress,
    ) -> Result<TransportEvent, TransportError> {
        match self.next_event().await {
            TransportEvent::InboundBallot {
                peer,
                request_id,
                ballot,
            } => {
                let status = match ingress.forward(&ballot).await {
                    Ok(status) => status,
                    Err(IngressError::Io(_) | IngressError::Timeout) => AckStatus::Busy,
                    Err(_) => AckStatus::Rejected,
                };
                self.respond(request_id, status)?;
                Ok(TransportEvent::InboundProcessed { peer, status })
            }
            event => Ok(event),
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
                if self.inbound_responses.len() >= self.max_inbound_requests {
                    let _ = self
                        .swarm
                        .behaviour_mut()
                        .ballots
                        .send_response(channel, AckStatus::Busy);
                    return None;
                }
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
            request_response::Event::InboundFailure { request_id, .. }
            | request_response::Event::ResponseSent { request_id, .. } => {
                self.inbound_responses.remove(&request_id);
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf, time::Duration};

    use super::*;
    use sha2::{Digest, Sha256};
    use tokio::{
        io::{AsyncReadExt as TokioAsyncReadExt, AsyncWriteExt},
        net::UnixListener,
    };

    fn test_config() -> GuardianP2pConfig {
        GuardianP2pConfig {
            request_timeout: Duration::from_secs(3),
            idle_connection_timeout: Duration::from_secs(3),
            ..GuardianP2pConfig::default()
        }
    }

    async fn next_event_with_timeout(node: &mut GuardianP2p) -> TransportEvent {
        tokio::time::timeout(Duration::from_secs(10), node.next_event())
            .await
            .expect("two-node libp2p test timed out")
    }

    async fn serve_ingress_once(path: PathBuf, expected: Vec<u8>) {
        let listener = UnixListener::bind(&path).expect("bind collector ingress");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .expect("owner-only collector socket");
        let (mut stream, _) = listener.accept().await.expect("accept carrier");
        let length = stream.read_u32().await.expect("read ingress length") as usize;
        let mut received = vec![0_u8; length];
        stream
            .read_exact(&mut received)
            .await
            .expect("read exact ingress ballot");
        assert_eq!(received, expected);
        let digest = format!("{:x}", Sha256::digest(&received));
        let ack = format!(
            "{{\"payload_digest\":\"{digest}\",\"protocol_version\":1,\"session_id\":\"{}\",\"status\":\"accepted\"}}",
            "a".repeat(64)
        );
        stream
            .write_u32(u32::try_from(ack.len()).expect("bounded ack"))
            .await
            .expect("write ack length");
        stream.write_all(ack.as_bytes()).await.expect("write ack");
    }

    #[test]
    fn ballot_size_is_bounded() {
        assert!(BallotBytes::new(vec![0_u8; MAX_BALLOT_BYTES]).is_ok());
        assert!(BallotBytes::new(Vec::new()).is_err());
        assert!(BallotBytes::new(vec![0_u8; MAX_BALLOT_BYTES + 1]).is_err());
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
    }
}

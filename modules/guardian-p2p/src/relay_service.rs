//! Bounded QUIC relay and AutoNAT service for operated Guardian networks.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    net::Ipv4Addr,
    time::Duration,
};

use futures::StreamExt;
use libp2p_autonat as autonat;
use libp2p_connection_limits as connection_limits;
use libp2p_core::{
    multiaddr::Protocol, muxing::StreamMuxerBox, transport::ListenerId, Multiaddr, Transport,
};
use libp2p_identity::{Keypair, PeerId};
use libp2p_ping as ping;
use libp2p_relay as relay;
use libp2p_swarm::{NetworkBehaviour, Swarm, SwarmEvent};

use crate::{
    connection_path, validate_listen_address, ConnectionPath, TransportError, MAX_LISTEN_ADDRESSES,
    MAX_TRANSPORT_DURATION,
};

/// Bounded relay service settings.
#[derive(Clone, Debug)]
pub struct RelayServiceConfig {
    pub listen_addresses: Vec<Multiaddr>,
    pub advertise_addresses: Vec<Multiaddr>,
    pub idle_connection_timeout: Duration,
    pub allow_private_autonat_addresses: bool,
}

impl Default for RelayServiceConfig {
    fn default() -> Self {
        Self {
            listen_addresses: Vec::new(),
            advertise_addresses: Vec::new(),
            idle_connection_timeout: Duration::from_secs(60),
            allow_private_autonat_addresses: false,
        }
    }
}

impl RelayServiceConfig {
    pub fn validate(&self) -> Result<(), TransportError> {
        if self.listen_addresses.is_empty()
            || self.listen_addresses.len() > MAX_LISTEN_ADDRESSES
            || self.idle_connection_timeout.is_zero()
            || self.idle_connection_timeout > MAX_TRANSPORT_DURATION
        {
            return Err(TransportError::InvalidConfig(
                "relay listeners and idle timeout must be bounded",
            ));
        }

        let mut listen_addresses = HashSet::new();
        for address in &self.listen_addresses {
            validate_listen_address(address)?;
            let protocols: Vec<_> = address.iter().collect();
            if !matches!(protocols.as_slice(), [_, _, Protocol::QuicV1]) {
                return Err(TransportError::InvalidConfig(
                    "relay service listener must be a direct QUIC-v1 route",
                ));
            }
            if !listen_addresses.insert(address) {
                return Err(TransportError::InvalidConfig("duplicate relay listener"));
            }
        }

        if self.advertise_addresses.len() > MAX_LISTEN_ADDRESSES {
            return Err(TransportError::InvalidConfig(
                "too many relay advertised addresses",
            ));
        }
        let mut advertise_addresses = HashSet::new();
        for address in &self.advertise_addresses {
            validate_advertise_address(address)?;
            if !advertise_addresses.insert(address) {
                return Err(TransportError::InvalidConfig(
                    "duplicate relay advertised address",
                ));
            }
        }
        Ok(())
    }
}

fn validate_advertise_address(address: &Multiaddr) -> Result<(), TransportError> {
    crate::validate_address_size(address)?;
    let protocols: Vec<_> = address.iter().collect();
    crate::validate_quic_base(&protocols, false)?;
    if matches!(protocols.first(), Some(Protocol::Ip4(ip)) if *ip == Ipv4Addr::BROADCAST) {
        return Err(TransportError::InvalidConfig(
            "relay advertised address must not use IPv4 broadcast",
        ));
    }
    if !matches!(protocols.as_slice(), [_, _, Protocol::QuicV1]) {
        return Err(TransportError::InvalidConfig(
            "relay advertised address must be an exact IP/UDP/QUIC-v1 route",
        ));
    }
    Ok(())
}

/// Data-minimal events emitted by the operated relay service.
#[derive(Debug)]
pub enum RelayServiceEvent {
    BootstrapRoute {
        address: Multiaddr,
    },
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
    ReservationAccepted {
        peer: PeerId,
        renewed: bool,
    },
    ReservationClosed {
        peer: PeerId,
    },
    CircuitAccepted {
        source: PeerId,
        destination: PeerId,
    },
    CircuitClosed {
        source: PeerId,
        destination: PeerId,
        failed: bool,
    },
}

#[derive(NetworkBehaviour)]
#[behaviour(
    to_swarm = "RelayBehaviourEvent",
    prelude = "libp2p_swarm::derive_prelude"
)]
struct RelayBehaviour {
    relay: relay::Behaviour,
    autonat: autonat::Behaviour,
    ping: ping::Behaviour,
    limits: connection_limits::Behaviour,
}

#[derive(Debug)]
enum RelayBehaviourEvent {
    Relay(relay::Event),
    Autonat(autonat::Event),
    Ping(ping::Event),
}

impl From<relay::Event> for RelayBehaviourEvent {
    fn from(event: relay::Event) -> Self {
        Self::Relay(event)
    }
}

impl From<autonat::Event> for RelayBehaviourEvent {
    fn from(event: autonat::Event) -> Self {
        Self::Autonat(event)
    }
}

impl From<ping::Event> for RelayBehaviourEvent {
    fn from(event: ping::Event) -> Self {
        Self::Ping(event)
    }
}

impl From<std::convert::Infallible> for RelayBehaviourEvent {
    fn from(never: std::convert::Infallible) -> Self {
        match never {}
    }
}

/// Operated relay node with fixed resource caps and no Guardian authorization role.
pub struct RelayService {
    swarm: Swarm<RelayBehaviour>,
    listener_addresses: HashMap<ListenerId, Multiaddr>,
    active_listener_addresses: HashMap<ListenerId, HashSet<Multiaddr>>,
    pending_events: VecDeque<RelayServiceEvent>,
}

impl RelayService {
    /// Builds a QUIC relay and AutoNAT probe service.
    pub fn new(keypair: Keypair, config: RelayServiceConfig) -> Result<Self, TransportError> {
        config.validate()?;
        let local_peer_id = keypair.public().to_peer_id();
        let transport = libp2p_quic::tokio::Transport::new(libp2p_quic::Config::new(&keypair))
            .map(|(peer_id, muxer), _| (peer_id, StreamMuxerBox::new(muxer)))
            .boxed();
        let relay_config = relay::Config {
            max_reservations: 64,
            max_reservations_per_peer: 2,
            reservation_duration: Duration::from_secs(15 * 60),
            max_circuits: 32,
            max_circuits_per_peer: 4,
            max_circuit_duration: Duration::from_secs(2 * 60),
            max_circuit_bytes: 1 << 17,
            ..relay::Config::default()
        };
        let autonat_config = autonat::Config {
            only_global_ips: !config.allow_private_autonat_addresses,
            ..autonat::Config::default()
        };
        let limits = connection_limits::ConnectionLimits::default()
            .with_max_pending_incoming(Some(32))
            .with_max_pending_outgoing(Some(32))
            .with_max_established_incoming(Some(128))
            .with_max_established_outgoing(Some(32))
            .with_max_established_per_peer(Some(4))
            .with_max_established(Some(160));
        let behaviour = RelayBehaviour {
            relay: relay::Behaviour::new(local_peer_id, relay_config),
            autonat: autonat::Behaviour::new(local_peer_id, autonat_config),
            ping: ping::Behaviour::new(ping::Config::new()),
            limits: connection_limits::Behaviour::new(limits),
        };
        let swarm_config = libp2p_swarm::Config::with_tokio_executor()
            .with_idle_connection_timeout(config.idle_connection_timeout);
        let mut swarm = Swarm::new(transport, behaviour, local_peer_id, swarm_config);
        let mut pending_events = VecDeque::new();
        for address in config.advertise_addresses {
            swarm.add_external_address(address.clone());
            pending_events.push_back(RelayServiceEvent::BootstrapRoute {
                address: address.with(Protocol::P2p(local_peer_id)),
            });
        }
        let mut listener_addresses = HashMap::new();
        for address in config.listen_addresses {
            let listener_id = swarm
                .listen_on(address.clone())
                .map_err(|error| TransportError::Listen(error.to_string()))?;
            listener_addresses.insert(listener_id, address);
        }
        Ok(Self {
            swarm,
            listener_addresses,
            active_listener_addresses: HashMap::new(),
            pending_events,
        })
    }

    /// Returns transport metadata only; it grants no Guardian role.
    pub fn local_peer_id(&self) -> PeerId {
        *self.swarm.local_peer_id()
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

    /// Stops relay listeners before the owner loop drains and exits.
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

    /// Drives the relay until an operator-relevant event is available.
    pub async fn next_event(&mut self) -> RelayServiceEvent {
        if let Some(event) = self.pending_events.pop_front() {
            return event;
        }
        loop {
            let event = self.swarm.select_next_some().await;
            if let Some(event) = self.handle_event(event) {
                return event;
            }
        }
    }

    fn handle_event(
        &mut self,
        event: SwarmEvent<RelayBehaviourEvent>,
    ) -> Option<RelayServiceEvent> {
        match event {
            SwarmEvent::NewListenAddr {
                listener_id,
                address,
            } => {
                self.active_listener_addresses
                    .entry(listener_id)
                    .or_default()
                    .insert(address.clone());
                Some(RelayServiceEvent::Listening { address })
            }
            SwarmEvent::ExpiredListenAddr {
                listener_id,
                address,
            } => {
                if let Some(addresses) = self.active_listener_addresses.get_mut(&listener_id) {
                    addresses.remove(&address);
                }
                Some(RelayServiceEvent::ListenerClosed {
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
                Some(RelayServiceEvent::ListenerClosed {
                    address,
                    failed: reason.is_err(),
                })
            }
            SwarmEvent::ListenerError { listener_id, .. } => self
                .listener_addresses
                .get(&listener_id)
                .cloned()
                .map(|address| RelayServiceEvent::ListenerFailed { address }),
            SwarmEvent::ConnectionEstablished {
                peer_id, endpoint, ..
            } => Some(RelayServiceEvent::ConnectionEstablished {
                peer: peer_id,
                path: connection_path(endpoint.is_relayed()),
            }),
            SwarmEvent::ConnectionClosed {
                peer_id,
                endpoint,
                num_established,
                cause,
                ..
            } => Some(RelayServiceEvent::ConnectionClosed {
                peer: peer_id,
                path: connection_path(endpoint.is_relayed()),
                remaining: num_established,
                failed: cause.is_some(),
            }),
            SwarmEvent::Behaviour(RelayBehaviourEvent::Relay(event)) => match event {
                relay::Event::ReservationReqAccepted {
                    src_peer_id,
                    renewed,
                } => Some(RelayServiceEvent::ReservationAccepted {
                    peer: src_peer_id,
                    renewed,
                }),
                relay::Event::ReservationClosed { src_peer_id }
                | relay::Event::ReservationTimedOut { src_peer_id } => {
                    Some(RelayServiceEvent::ReservationClosed { peer: src_peer_id })
                }
                relay::Event::CircuitReqAccepted {
                    src_peer_id,
                    dst_peer_id,
                } => Some(RelayServiceEvent::CircuitAccepted {
                    source: src_peer_id,
                    destination: dst_peer_id,
                }),
                relay::Event::CircuitClosed {
                    src_peer_id,
                    dst_peer_id,
                    error,
                } => Some(RelayServiceEvent::CircuitClosed {
                    source: src_peer_id,
                    destination: dst_peer_id,
                    failed: error.is_some(),
                }),
                _ => None,
            },
            SwarmEvent::Behaviour(RelayBehaviourEvent::Autonat(event)) => {
                let _ = event;
                None
            }
            SwarmEvent::Behaviour(RelayBehaviourEvent::Ping(event)) => {
                let _ = event;
                None
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{net::UdpSocket, time::Duration};

    use libp2p_core::multiaddr::Protocol;
    use libp2p_identity::Keypair;

    use super::*;
    use crate::{
        AckStatus, BallotBytes, ConnectionPath, GuardianP2p, GuardianP2pConfig, HolePunchOutcome,
        NatReachability, StaticPeer, TransportEvent,
    };

    fn guardian_config(autonat_server: StaticPeer) -> GuardianP2pConfig {
        GuardianP2pConfig {
            autonat_servers: vec![autonat_server],
            autonat_boot_delay: Duration::ZERO,
            autonat_retry_interval: Duration::from_millis(200),
            autonat_refresh_interval: Duration::from_secs(2),
            autonat_confidence_max: 1,
            autonat_allow_private_addresses: true,
            request_timeout: Duration::from_secs(3),
            idle_connection_timeout: Duration::from_secs(10),
            ..GuardianP2pConfig::default()
        }
    }

    fn available_udp_port() -> u16 {
        UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .expect("reserve local UDP port")
            .local_addr()
            .expect("read local UDP address")
            .port()
    }

    #[tokio::test]
    async fn advertised_address_emits_canonical_bootstrap_route() {
        let relay_identity = Keypair::generate_ed25519();
        let relay_peer = relay_identity.public().to_peer_id();
        let advertise_address: Multiaddr = "/ip4/198.51.100.10/udp/4100/quic-v1"
            .parse()
            .expect("advertised relay address");
        let mut relay = RelayService::new(
            relay_identity,
            RelayServiceConfig {
                listen_addresses: vec!["/ip4/127.0.0.1/udp/0/quic-v1"
                    .parse()
                    .expect("relay listen route")],
                advertise_addresses: vec![advertise_address.clone()],
                idle_connection_timeout: Duration::from_secs(10),
                allow_private_autonat_addresses: true,
            },
        )
        .expect("relay service initializes");

        match relay.next_event().await {
            RelayServiceEvent::BootstrapRoute { address } => {
                assert_eq!(address, advertise_address.with(Protocol::P2p(relay_peer)))
            }
            event => panic!("expected bootstrap route, got {event:?}"),
        }
    }

    #[test]
    fn invalid_advertised_addresses_fail_closed() {
        let invalid = [
            "/ip4/0.0.0.0/udp/4100/quic-v1",
            "/ip4/224.0.0.1/udp/4100/quic-v1",
            "/ip4/255.255.255.255/udp/4100/quic-v1",
            "/ip6/::/udp/4100/quic-v1",
            "/dns4/relay.example/udp/4100/quic-v1",
            "/ip4/198.51.100.10/udp/0/quic-v1",
            "/ip4/198.51.100.10/tcp/4100",
        ];
        for address in invalid {
            let config = RelayServiceConfig {
                listen_addresses: vec!["/ip4/127.0.0.1/udp/0/quic-v1"
                    .parse()
                    .expect("relay listen route")],
                advertise_addresses: vec![address.parse().expect("parse invalid test route")],
                ..RelayServiceConfig::default()
            };
            assert!(config.validate().is_err(), "accepted {address}");
        }

        let duplicate: Multiaddr = "/ip4/198.51.100.10/udp/4100/quic-v1"
            .parse()
            .expect("duplicate advertised route");
        let duplicate_config = RelayServiceConfig {
            listen_addresses: vec!["/ip4/127.0.0.1/udp/0/quic-v1"
                .parse()
                .expect("relay listen route")],
            advertise_addresses: vec![duplicate.clone(), duplicate],
            ..RelayServiceConfig::default()
        };
        assert!(duplicate_config.validate().is_err());

        let too_many = (1..=MAX_LISTEN_ADDRESSES + 1)
            .map(|index| {
                format!("/ip4/198.51.100.{index}/udp/4100/quic-v1")
                    .parse()
                    .expect("bounded advertised route")
            })
            .collect();
        let too_many_config = RelayServiceConfig {
            listen_addresses: vec!["/ip4/127.0.0.1/udp/0/quic-v1"
                .parse()
                .expect("relay listen route")],
            advertise_addresses: too_many,
            ..RelayServiceConfig::default()
        };
        assert!(too_many_config.validate().is_err());

        let mut oversized = Multiaddr::empty();
        for _ in 0..=crate::MAX_MULTIADDR_BYTES {
            oversized.push(Protocol::P2pCircuit);
        }
        let oversized_config = RelayServiceConfig {
            listen_addresses: vec!["/ip4/127.0.0.1/udp/0/quic-v1"
                .parse()
                .expect("relay listen route")],
            advertise_addresses: vec![oversized],
            ..RelayServiceConfig::default()
        };
        assert!(oversized_config.validate().is_err());
    }

    #[tokio::test]
    async fn listener_is_not_implicitly_advertised() {
        let mut relay = RelayService::new(
            Keypair::generate_ed25519(),
            RelayServiceConfig {
                listen_addresses: vec!["/ip4/127.0.0.1/udp/0/quic-v1"
                    .parse()
                    .expect("relay listen route")],
                advertise_addresses: Vec::new(),
                ..RelayServiceConfig::default()
            },
        )
        .expect("relay service initializes");

        assert!(matches!(
            relay.next_event().await,
            RelayServiceEvent::Listening { .. }
        ));
        assert_eq!(relay.swarm.external_addresses().count(), 0);
    }

    #[tokio::test]
    async fn operated_relay_delivers_ballot_and_preserves_fallback() {
        let relay_identity = Keypair::generate_ed25519();
        let relay_peer = relay_identity.public().to_peer_id();
        let relay_port = available_udp_port();
        let relay_address: Multiaddr = format!("/ip4/127.0.0.1/udp/{relay_port}/quic-v1")
            .parse()
            .expect("relay advertised route");
        let mut relay = RelayService::new(
            relay_identity,
            RelayServiceConfig {
                listen_addresses: vec![format!("/ip4/0.0.0.0/udp/{relay_port}/quic-v1")
                    .parse()
                    .expect("relay wildcard listener")],
                advertise_addresses: vec![relay_address.clone()],
                idle_connection_timeout: Duration::from_secs(10),
                allow_private_autonat_addresses: true,
            },
        )
        .expect("relay service initializes");
        match relay.next_event().await {
            RelayServiceEvent::BootstrapRoute { address } => {
                assert_eq!(
                    address,
                    relay_address.clone().with(Protocol::P2p(relay_peer))
                )
            }
            event => panic!("expected bootstrap route, got {event:?}"),
        }
        match tokio::time::timeout(Duration::from_secs(5), relay.next_event())
            .await
            .expect("relay listener timed out")
        {
            RelayServiceEvent::Listening { .. } => {}
            event => panic!("expected relay listener, got {event:?}"),
        }
        let autonat_server = StaticPeer {
            peer_id: relay_peer,
            address: relay_address.clone(),
        };

        let receiver_identity = Keypair::generate_ed25519();
        let receiver_peer = receiver_identity.public().to_peer_id();
        let reservation_address = relay_address
            .clone()
            .with(Protocol::P2p(relay_peer))
            .with(Protocol::P2pCircuit);
        let mut receiver_config = guardian_config(autonat_server.clone());
        receiver_config
            .listen_addresses
            .push(reservation_address.clone());
        let mut receiver =
            GuardianP2p::new(receiver_identity, receiver_config).expect("receiver initializes");

        let mut relay_saw_reservation = false;
        let mut receiver_saw_reservation = false;
        tokio::time::timeout(Duration::from_secs(10), async {
            while !(relay_saw_reservation && receiver_saw_reservation) {
                tokio::select! {
                    event = relay.next_event() => {
                        if let RelayServiceEvent::ReservationAccepted { peer, renewed: false } = event {
                            assert_eq!(peer, receiver_peer);
                            relay_saw_reservation = true;
                        }
                    }
                    event = receiver.next_event() => {
                        if let TransportEvent::RelayReservationAccepted { relay_peer: peer, renewal: false } = event {
                            assert_eq!(peer, relay_peer);
                            receiver_saw_reservation = true;
                        }
                    }
                }
            }
        })
        .await
        .expect("relay reservation timed out");

        let sender_identity = Keypair::generate_ed25519();
        let sender_peer = sender_identity.public().to_peer_id();
        let receiver_route = reservation_address
            .clone()
            .with(Protocol::P2p(receiver_peer));
        let mut sender_config = guardian_config(autonat_server);
        sender_config.listen_addresses.push(
            "/ip4/127.0.0.1/udp/0/quic-v1"
                .parse()
                .expect("sender direct listener"),
        );
        sender_config.static_peers.push(StaticPeer {
            peer_id: receiver_peer,
            address: receiver_route,
        });
        let mut sender =
            GuardianP2p::new(sender_identity, sender_config).expect("sender initializes");
        let request_id = sender
            .send_ballot(
                receiver_peer,
                BallotBytes::new(b"operated-relay-ballot".to_vec()).expect("bounded ballot"),
            )
            .expect("relay ballot dispatch");

        let mut relay_saw_circuit = false;
        let mut sender_saw_relayed_connection = false;
        let mut receiver_saw_relayed_connection = false;
        let mut sender_saw_public_autonat = false;
        let mut fallback_observed = false;
        let mut ack_received = false;
        tokio::time::timeout(Duration::from_secs(15), async {
            while !(relay_saw_circuit
                && sender_saw_relayed_connection
                && receiver_saw_relayed_connection
                && sender_saw_public_autonat
                && fallback_observed
                && ack_received)
            {
                tokio::select! {
                    event = relay.next_event() => {
                        if let RelayServiceEvent::CircuitAccepted { source, destination } = event {
                            assert_eq!(source, sender_peer);
                            assert_eq!(destination, receiver_peer);
                            relay_saw_circuit = true;
                        }
                    }
                    event = receiver.next_event() => match event {
                        TransportEvent::ConnectionEstablished { peer, path: ConnectionPath::Relayed } => {
                            assert_eq!(peer, sender_peer);
                            receiver_saw_relayed_connection = true;
                        }
                        TransportEvent::InboundBallot { peer, request_id, ballot } => {
                            assert_eq!(peer, sender_peer);
                            assert_eq!(ballot.as_bytes(), b"operated-relay-ballot");
                            receiver.respond(request_id, AckStatus::Accepted).expect("relay response");
                        }
                        TransportEvent::HolePunchFinished { peer, outcome: HolePunchOutcome::RelayFallback } => {
                            assert_eq!(peer, sender_peer);
                            fallback_observed = true;
                        }
                        _ => {}
                    },
                    event = sender.next_event() => match event {
                        TransportEvent::ConnectionEstablished { peer, path: ConnectionPath::Relayed } => {
                            assert_eq!(peer, receiver_peer);
                            sender_saw_relayed_connection = true;
                        }
                        TransportEvent::NatStatusChanged { new: NatReachability::Public, .. } => {
                            sender_saw_public_autonat = true;
                        }
                        TransportEvent::HolePunchFinished { peer, outcome: HolePunchOutcome::RelayFallback } => {
                            assert_eq!(peer, receiver_peer);
                            fallback_observed = true;
                        }
                        TransportEvent::OutboundAck { request_id: received, status, .. } => {
                            assert_eq!(received, request_id);
                            assert_eq!(status, AckStatus::Accepted);
                            ack_received = true;
                        }
                        TransportEvent::OutboundFailure { failure, .. } => {
                            panic!("relay ballot failed: {failure:?}");
                        }
                        _ => {}
                    }
                }
            }
        })
        .await
        .expect("operated relay evidence timed out");

        drop(receiver);
        let mut relay_saw_circuit_close = false;
        let mut sender_saw_relayed_disconnect = false;
        tokio::time::timeout(Duration::from_secs(10), async {
            while !(relay_saw_circuit_close && sender_saw_relayed_disconnect) {
                tokio::select! {
                    event = relay.next_event() => {
                        if let RelayServiceEvent::CircuitClosed { source, destination, .. } = event {
                            assert_eq!(source, sender_peer);
                            assert_eq!(destination, receiver_peer);
                            relay_saw_circuit_close = true;
                        }
                    }
                    event = sender.next_event() => {
                        if let TransportEvent::ConnectionClosed {
                            peer,
                            path: ConnectionPath::Relayed,
                            ..
                        } = event
                        {
                            assert_eq!(peer, receiver_peer);
                            sender_saw_relayed_disconnect = true;
                        }
                    }
                }
            }
        })
        .await
        .expect("relayed disconnect evidence timed out");
    }
}

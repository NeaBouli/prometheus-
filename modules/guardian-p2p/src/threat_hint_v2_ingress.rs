//! Owner-only AF_UNIX bridge to the Python ThreatHint-v2 promotion ingress.
//!
//! The client forwards exactly one canonical [`ThreatHintV2TransportPayload`]
//! frame to the local Guardian ingress and validates a strict protocol-v2
//! acknowledgement bound to the SHA-256 payload digest. The payload nonce,
//! nested wires, and approval material never appear in acknowledgements or
//! errors.

use std::{
    os::unix::fs::{FileTypeExt, MetadataExt},
    path::{Path, PathBuf},
    time::Duration,
};

use prometheus_threat_hint::ThreatHintV2TransportPayload;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
    time,
};

const PROTOCOL_VERSION: u8 = 2;
const MAX_ACK_BYTES: usize = 384;
const FRAME_PREFIX_BYTES: usize = 4;

/// Data-minimal response of the ThreatHint-v2 ingress boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ThreatHintV2AckStatus {
    Accepted,
    Rejected,
    Busy,
}

impl ThreatHintV2AckStatus {
    /// Stable machine-readable acknowledgement name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Busy => "busy",
        }
    }
}

/// Strict local client for the Guardian ingress's owner-only Unix socket.
#[derive(Clone, Debug)]
pub struct UnixThreatHintV2Ingress {
    path: PathBuf,
    timeout: Duration,
}

impl UnixThreatHintV2Ingress {
    /// Validates the local socket path and constructs a bounded ingress client.
    pub fn new(
        path: impl Into<PathBuf>,
        timeout: Duration,
    ) -> Result<Self, ThreatHintV2IngressError> {
        let ingress = Self::configured(path, timeout)?;
        validate_socket(&ingress.path, effective_uid())?;
        Ok(ingress)
    }

    /// Constructs a bounded ingress client before the ingress socket exists.
    pub fn configured(
        path: impl Into<PathBuf>,
        timeout: Duration,
    ) -> Result<Self, ThreatHintV2IngressError> {
        if timeout.is_zero() || timeout > Duration::from_secs(60) {
            return Err(ThreatHintV2IngressError::InvalidTimeout);
        }
        let path = path.into();
        validate_socket_parent(&path, effective_uid())?;
        Ok(Self { path, timeout })
    }

    /// Forwards exact canonical payload bytes and validates the ingress result.
    pub async fn forward(
        &self,
        payload: &ThreatHintV2TransportPayload,
    ) -> Result<ThreatHintV2AckStatus, ThreatHintV2IngressError> {
        time::timeout(self.timeout, self.forward_inner(payload))
            .await
            .map_err(|_| ThreatHintV2IngressError::Timeout)?
    }

    async fn forward_inner(
        &self,
        payload: &ThreatHintV2TransportPayload,
    ) -> Result<ThreatHintV2AckStatus, ThreatHintV2IngressError> {
        let expected_uid = effective_uid();
        validate_socket(&self.path, expected_uid)?;
        let mut stream = UnixStream::connect(&self.path)
            .await
            .map_err(map_connect_error)?;
        if stream.peer_cred()?.uid() != expected_uid {
            return Err(ThreatHintV2IngressError::UnsafeSocket);
        }

        let payload_bytes = payload.to_canonical_bytes();
        let payload_len = u32::try_from(payload_bytes.len())
            .map_err(|_| ThreatHintV2IngressError::InvalidAcknowledgement)?;
        stream.write_all(&payload_len.to_be_bytes()).await?;
        stream.write_all(&payload_bytes).await?;
        stream.shutdown().await?;

        let mut prefix = [0_u8; FRAME_PREFIX_BYTES];
        stream.read_exact(&mut prefix).await?;
        let ack_len = usize::try_from(u32::from_be_bytes(prefix))
            .map_err(|_| ThreatHintV2IngressError::InvalidAcknowledgement)?;
        if ack_len == 0 || ack_len > MAX_ACK_BYTES {
            return Err(ThreatHintV2IngressError::InvalidAcknowledgement);
        }
        let mut ack_bytes = vec![0_u8; ack_len];
        stream.read_exact(&mut ack_bytes).await?;
        let mut trailing = [0_u8; 1];
        if stream.read(&mut trailing).await? != 0 {
            return Err(ThreatHintV2IngressError::InvalidAcknowledgement);
        }

        let ack: ThreatHintV2IngressAck = serde_json::from_slice(&ack_bytes)
            .map_err(|_| ThreatHintV2IngressError::InvalidAcknowledgement)?;
        let canonical = serde_json::to_vec(&ack)
            .map_err(|_| ThreatHintV2IngressError::InvalidAcknowledgement)?;
        if canonical != ack_bytes || !ack.has_valid_identifiers(&payload_bytes) {
            return Err(ThreatHintV2IngressError::InvalidAcknowledgement);
        }
        Ok(ack.status.into())
    }
}

/// Failure at the local ThreatHint-v2 ingress boundary.
#[derive(Debug, Error)]
pub enum ThreatHintV2IngressError {
    #[error("ThreatHint-v2 ingress timeout must be in (0, 60] seconds")]
    InvalidTimeout,
    #[error("ThreatHint-v2 ingress path must be an owner-only Unix socket")]
    UnsafeSocket,
    #[error("ThreatHint-v2 ingress operation timed out")]
    Timeout,
    #[error("ThreatHint-v2 ingress acknowledgement is invalid")]
    InvalidAcknowledgement,
    #[error("ThreatHint-v2 ingress is temporarily unavailable")]
    Unavailable,
    #[error("ThreatHint-v2 ingress I/O failed")]
    Io(#[from] std::io::Error),
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
enum IngressStatus {
    Accepted,
    Rejected,
    Busy,
}

impl From<IngressStatus> for ThreatHintV2AckStatus {
    fn from(status: IngressStatus) -> Self {
        match status {
            IngressStatus::Accepted => Self::Accepted,
            IngressStatus::Rejected => Self::Rejected,
            IngressStatus::Busy => Self::Busy,
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ThreatHintV2IngressAck {
    payload_digest: String,
    protocol_version: u8,
    status: IngressStatus,
}

impl ThreatHintV2IngressAck {
    fn has_valid_identifiers(&self, payload: &[u8]) -> bool {
        if self.protocol_version != PROTOCOL_VERSION {
            return false;
        }
        match self.status {
            IngressStatus::Busy => self.payload_digest.is_empty(),
            _ => self.payload_digest == format!("{:x}", Sha256::digest(payload)),
        }
    }
}

fn effective_uid() -> u32 {
    rustix::process::geteuid().as_raw()
}

fn validate_socket(path: &Path, expected_uid: u32) -> Result<(), ThreatHintV2IngressError> {
    validate_socket_parent(path, expected_uid)?;
    let socket_metadata = path
        .symlink_metadata()
        .map_err(|error| match error.kind() {
            std::io::ErrorKind::NotFound => ThreatHintV2IngressError::Unavailable,
            _ => ThreatHintV2IngressError::Io(error),
        })?;
    if !socket_metadata.file_type().is_socket()
        || socket_metadata.mode() & 0o777 != 0o600
        || socket_metadata.uid() != expected_uid
    {
        return Err(ThreatHintV2IngressError::UnsafeSocket);
    }
    Ok(())
}

fn validate_socket_parent(path: &Path, expected_uid: u32) -> Result<(), ThreatHintV2IngressError> {
    if !path.is_absolute() || path.file_name().is_none() {
        return Err(ThreatHintV2IngressError::UnsafeSocket);
    }
    let parent = path
        .parent()
        .ok_or(ThreatHintV2IngressError::UnsafeSocket)?;
    let parent_metadata = parent
        .symlink_metadata()
        .map_err(|_| ThreatHintV2IngressError::UnsafeSocket)?;
    if parent_metadata.file_type().is_symlink()
        || !parent_metadata.is_dir()
        || parent_metadata.mode() & 0o777 != 0o700
        || parent_metadata.uid() != expected_uid
    {
        return Err(ThreatHintV2IngressError::UnsafeSocket);
    }
    Ok(())
}

fn map_connect_error(error: std::io::Error) -> ThreatHintV2IngressError {
    match error.kind() {
        std::io::ErrorKind::NotFound
        | std::io::ErrorKind::ConnectionRefused
        | std::io::ErrorKind::ConnectionReset => ThreatHintV2IngressError::Unavailable,
        _ => ThreatHintV2IngressError::Io(error),
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::PermissionsExt};

    use tempfile::TempDir;
    use tokio::net::UnixListener;

    use super::*;

    fn owner_only_dir() -> TempDir {
        let directory = tempfile::tempdir().expect("temporary ingress directory");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("owner-only ingress directory");
        directory
    }

    fn hex_decode(encoded: &str) -> Vec<u8> {
        assert!(encoded.len().is_multiple_of(2), "even-length hex");
        (0..encoded.len())
            .step_by(2)
            .map(|offset| u8::from_str_radix(&encoded[offset..offset + 2], 16).expect("hex pair"))
            .collect()
    }

    fn payload() -> ThreatHintV2TransportPayload {
        let corpus: serde_json::Value = serde_json::from_str(include_str!(
            "../../threat-hint/tests/vectors/threat-hint-v2-transport-v1.json"
        ))
        .expect("transport vector corpus");
        let case = corpus["valid_cases"]
            .as_array()
            .expect("valid cases")
            .iter()
            .find(|case| case["name"] == "base_review_required")
            .expect("base case");
        let wire = hex_decode(case["wire_hex"].as_str().expect("wire hex"));
        let network = case["trusted_network_id"].as_str().expect("network id");
        ThreatHintV2TransportPayload::parse_canonical(&wire, network).expect("valid vector payload")
    }

    async fn serve_ack(path: PathBuf, expected: Vec<u8>, ack: Vec<u8>) {
        let listener = UnixListener::bind(&path).expect("bind test ingress");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .expect("owner-only ingress socket");
        let (mut stream, _) = listener.accept().await.expect("accept ingress client");
        let length = stream.read_u32().await.expect("read payload length") as usize;
        let mut received = vec![0_u8; length];
        stream
            .read_exact(&mut received)
            .await
            .expect("read exact payload");
        assert_eq!(received, expected);
        stream
            .write_u32(u32::try_from(ack.len()).expect("bounded test ack"))
            .await
            .expect("write ack length");
        stream.write_all(&ack).await.expect("write ack");
    }

    fn canonical_ack(payload: &[u8], status: IngressStatus) -> Vec<u8> {
        let payload_digest = if status == IngressStatus::Busy {
            String::new()
        } else {
            format!("{:x}", Sha256::digest(payload))
        };
        serde_json::to_vec(&ThreatHintV2IngressAck {
            payload_digest,
            protocol_version: PROTOCOL_VERSION,
            status,
        })
        .expect("canonical ack")
    }

    #[tokio::test]
    async fn forwards_exact_payload_and_accepts_digest_bound_ack() {
        let directory = owner_only_dir();
        let path = directory.path().join("threat-hint-v2.sock");
        let payload = payload();
        let server = tokio::spawn(serve_ack(
            path.clone(),
            payload.to_canonical_bytes(),
            canonical_ack(&payload.to_canonical_bytes(), IngressStatus::Accepted),
        ));
        tokio::task::yield_now().await;

        let ingress =
            UnixThreatHintV2Ingress::new(path, Duration::from_secs(1)).expect("configured ingress");
        assert_eq!(
            ingress.forward(&payload).await.expect("accepted response"),
            ThreatHintV2AckStatus::Accepted
        );
        server.await.expect("server task");
    }

    #[tokio::test]
    async fn busy_ack_is_unbound_and_canonical() {
        let directory = owner_only_dir();
        let path = directory.path().join("threat-hint-v2.sock");
        let payload = payload();
        let server = tokio::spawn(serve_ack(
            path.clone(),
            payload.to_canonical_bytes(),
            canonical_ack(&payload.to_canonical_bytes(), IngressStatus::Busy),
        ));
        tokio::task::yield_now().await;

        let ingress =
            UnixThreatHintV2Ingress::new(path, Duration::from_secs(1)).expect("configured ingress");
        assert_eq!(
            ingress.forward(&payload).await.expect("busy response"),
            ThreatHintV2AckStatus::Busy
        );
        server.await.expect("server task");
    }

    #[tokio::test]
    async fn rejects_ack_with_wrong_digest() {
        let directory = owner_only_dir();
        let path = directory.path().join("threat-hint-v2.sock");
        let payload = payload();
        let ack = serde_json::to_vec(&ThreatHintV2IngressAck {
            payload_digest: "0".repeat(64),
            protocol_version: PROTOCOL_VERSION,
            status: IngressStatus::Rejected,
        })
        .expect("ack");
        let server = tokio::spawn(serve_ack(path.clone(), payload.to_canonical_bytes(), ack));
        tokio::task::yield_now().await;

        let ingress =
            UnixThreatHintV2Ingress::new(path, Duration::from_secs(1)).expect("configured ingress");
        assert!(matches!(
            ingress.forward(&payload).await,
            Err(ThreatHintV2IngressError::InvalidAcknowledgement)
        ));
        server.await.expect("server task");
    }

    #[tokio::test]
    async fn rejects_ack_with_legacy_protocol_version() {
        let directory = owner_only_dir();
        let path = directory.path().join("threat-hint-v2.sock");
        let payload = payload();
        let ack = serde_json::to_vec(&ThreatHintV2IngressAck {
            payload_digest: format!("{:x}", Sha256::digest(payload.to_canonical_bytes())),
            protocol_version: 1,
            status: IngressStatus::Accepted,
        })
        .expect("ack");
        let server = tokio::spawn(serve_ack(path.clone(), payload.to_canonical_bytes(), ack));
        tokio::task::yield_now().await;

        let ingress =
            UnixThreatHintV2Ingress::new(path, Duration::from_secs(1)).expect("configured ingress");
        assert!(matches!(
            ingress.forward(&payload).await,
            Err(ThreatHintV2IngressError::InvalidAcknowledgement)
        ));
        server.await.expect("server task");
    }

    #[tokio::test]
    async fn rejects_ack_leaking_nested_material_or_unknown_fields() {
        for ack in [
            serde_json::json!({
                "payload_digest": "",
                "protocol_version": PROTOCOL_VERSION,
                "status": "busy",
                "report_nonce": "ab".repeat(32),
            }),
            serde_json::json!({
                "payload_digest": "",
                "protocol_version": PROTOCOL_VERSION,
                "status": "busy",
                "approval_wire": "deadbeef",
            }),
            serde_json::json!({
                "payload_digest": "",
                "protocol_version": PROTOCOL_VERSION,
                "status": "duplicate",
            }),
            serde_json::json!({
                "payload_digest": "cd".repeat(32),
                "protocol_version": PROTOCOL_VERSION,
                "status": "busy",
            }),
            serde_json::json!({
                "payload_digest": "",
                "protocol_version": PROTOCOL_VERSION,
                "status": "accepted",
            }),
        ] {
            let directory = owner_only_dir();
            let path = directory.path().join("threat-hint-v2.sock");
            let payload = payload();
            let ack = serde_json::to_vec(&ack).expect("ack");
            let server = tokio::spawn(serve_ack(path.clone(), payload.to_canonical_bytes(), ack));
            tokio::task::yield_now().await;

            let ingress = UnixThreatHintV2Ingress::new(path, Duration::from_secs(1))
                .expect("configured ingress");
            assert!(
                matches!(
                    ingress.forward(&payload).await,
                    Err(ThreatHintV2IngressError::InvalidAcknowledgement)
                ),
                "adversarial ack must fail closed"
            );
            server.await.expect("server task");
        }
    }

    #[tokio::test]
    async fn acknowledgement_with_trailing_bytes_fails_closed() {
        let directory = owner_only_dir();
        let path = directory.path().join("threat-hint-v2.sock");
        let payload = payload();
        let expected = payload.to_canonical_bytes();
        let ack = canonical_ack(&expected, IngressStatus::Rejected);
        let server_path = path.clone();
        let server = tokio::spawn(async move {
            let listener = UnixListener::bind(&server_path).expect("bind test ingress");
            fs::set_permissions(&server_path, fs::Permissions::from_mode(0o600))
                .expect("owner-only ingress socket");
            let (mut stream, _) = listener.accept().await.expect("accept ingress client");
            let length = stream.read_u32().await.expect("read payload length") as usize;
            let mut received = vec![0_u8; length];
            stream
                .read_exact(&mut received)
                .await
                .expect("read payload");
            assert_eq!(received, expected);
            stream
                .write_u32(u32::try_from(ack.len()).expect("bounded ack"))
                .await
                .expect("write ack length");
            stream.write_all(&ack).await.expect("write ack");
            stream.write_all(b"x").await.expect("write trailing byte");
        });
        tokio::task::yield_now().await;

        let ingress =
            UnixThreatHintV2Ingress::new(path, Duration::from_secs(1)).expect("configured ingress");
        assert!(matches!(
            ingress.forward(&payload).await,
            Err(ThreatHintV2IngressError::InvalidAcknowledgement)
        ));
        server.await.expect("server task");
    }

    #[tokio::test]
    async fn oversized_ack_frame_fails_closed() {
        let directory = owner_only_dir();
        let path = directory.path().join("threat-hint-v2.sock");
        let payload = payload();
        let expected = payload.to_canonical_bytes();
        let server_path = path.clone();
        let server = tokio::spawn(async move {
            let listener = UnixListener::bind(&server_path).expect("bind test ingress");
            fs::set_permissions(&server_path, fs::Permissions::from_mode(0o600))
                .expect("owner-only ingress socket");
            let (mut stream, _) = listener.accept().await.expect("accept ingress client");
            let length = stream.read_u32().await.expect("read payload length") as usize;
            let mut received = vec![0_u8; length];
            stream
                .read_exact(&mut received)
                .await
                .expect("read payload");
            assert_eq!(received, expected);
            let oversized = u32::try_from(MAX_ACK_BYTES + 1).expect("bounded test value");
            let _ = stream.write_u32(oversized).await;
        });
        tokio::task::yield_now().await;

        let ingress =
            UnixThreatHintV2Ingress::new(path, Duration::from_secs(1)).expect("configured ingress");
        assert!(matches!(
            ingress.forward(&payload).await,
            Err(ThreatHintV2IngressError::InvalidAcknowledgement)
        ));
        server.await.expect("server task");
    }

    #[tokio::test]
    async fn missing_socket_is_unavailable() {
        let directory = owner_only_dir();
        let ingress = UnixThreatHintV2Ingress::configured(
            directory.path().join("missing.sock"),
            Duration::from_secs(1),
        )
        .expect("configured ingress");
        assert!(matches!(
            ingress.forward(&payload()).await,
            Err(ThreatHintV2IngressError::Unavailable)
        ));
    }

    #[tokio::test]
    async fn regular_file_is_not_an_ingress_socket() {
        let directory = owner_only_dir();
        let path = directory.path().join("threat-hint-v2.sock");
        fs::write(&path, b"not a socket").expect("write regular file");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .expect("owner-only regular file");
        assert!(matches!(
            UnixThreatHintV2Ingress::new(path, Duration::from_secs(1)),
            Err(ThreatHintV2IngressError::UnsafeSocket)
        ));
    }

    #[test]
    fn world_readable_parent_is_rejected() {
        let directory = tempfile::tempdir().expect("temporary ingress directory");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o755))
            .expect("world-readable directory");
        assert!(matches!(
            UnixThreatHintV2Ingress::configured(
                directory.path().join("threat-hint-v2.sock"),
                Duration::from_secs(1),
            ),
            Err(ThreatHintV2IngressError::UnsafeSocket)
        ));
    }

    #[test]
    fn invalid_timeouts_are_rejected() {
        let directory = owner_only_dir();
        for timeout in [Duration::ZERO, Duration::from_secs(61)] {
            assert!(matches!(
                UnixThreatHintV2Ingress::configured(
                    directory.path().join("threat-hint-v2.sock"),
                    timeout,
                ),
                Err(ThreatHintV2IngressError::InvalidTimeout)
            ));
        }
    }

    #[test]
    fn ack_status_names_are_stable() {
        assert_eq!(ThreatHintV2AckStatus::Accepted.as_str(), "accepted");
        assert_eq!(ThreatHintV2AckStatus::Rejected.as_str(), "rejected");
        assert_eq!(ThreatHintV2AckStatus::Busy.as_str(), "busy");
    }

    #[test]
    fn error_messages_carry_no_candidate_material() {
        for message in [
            ThreatHintV2IngressError::InvalidTimeout.to_string(),
            ThreatHintV2IngressError::UnsafeSocket.to_string(),
            ThreatHintV2IngressError::Timeout.to_string(),
            ThreatHintV2IngressError::InvalidAcknowledgement.to_string(),
            ThreatHintV2IngressError::Unavailable.to_string(),
        ] {
            assert!(!message.contains("nonce"));
            assert!(!message.contains("approval"));
            assert!(!message.contains("0x"));
        }
    }
}

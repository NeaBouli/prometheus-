//! Owner-only AF_UNIX bridge to the Python ThreatHint verifier.

use std::{
    os::unix::fs::{FileTypeExt, MetadataExt},
    path::{Path, PathBuf},
    time::Duration,
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
    time,
};

use crate::{ThreatHintAckStatus, ThreatHintBytes};

const PROTOCOL_VERSION: u8 = 1;
const MAX_ACK_BYTES: usize = 384;
const FRAME_PREFIX_BYTES: usize = 4;

/// Strict local client for the Guardian verifier's owner-only Unix socket.
#[derive(Clone, Debug)]
pub struct UnixThreatHintIngress {
    path: PathBuf,
    timeout: Duration,
}

impl UnixThreatHintIngress {
    /// Validates the local socket path and constructs a bounded ingress client.
    pub fn new(
        path: impl Into<PathBuf>,
        timeout: Duration,
    ) -> Result<Self, ThreatHintIngressError> {
        let ingress = Self::configured(path, timeout)?;
        validate_socket(&ingress.path, effective_uid())?;
        Ok(ingress)
    }

    /// Constructs a bounded ingress client before the verifier socket exists.
    pub fn configured(
        path: impl Into<PathBuf>,
        timeout: Duration,
    ) -> Result<Self, ThreatHintIngressError> {
        if timeout.is_zero() || timeout > Duration::from_secs(60) {
            return Err(ThreatHintIngressError::InvalidTimeout);
        }
        let path = path.into();
        validate_socket_parent(&path, effective_uid())?;
        Ok(Self { path, timeout })
    }

    /// Forwards exact canonical bytes and validates the verifier result.
    pub async fn forward(
        &self,
        hint: &ThreatHintBytes,
    ) -> Result<ThreatHintAckStatus, ThreatHintIngressError> {
        time::timeout(self.timeout, self.forward_inner(hint))
            .await
            .map_err(|_| ThreatHintIngressError::Timeout)?
    }

    async fn forward_inner(
        &self,
        hint: &ThreatHintBytes,
    ) -> Result<ThreatHintAckStatus, ThreatHintIngressError> {
        let expected_uid = effective_uid();
        validate_socket(&self.path, expected_uid)?;
        let mut stream = UnixStream::connect(&self.path)
            .await
            .map_err(map_connect_error)?;
        if stream.peer_cred()?.uid() != expected_uid {
            return Err(ThreatHintIngressError::UnsafeSocket);
        }

        let hint_len = u32::try_from(hint.as_bytes().len())
            .map_err(|_| ThreatHintIngressError::InvalidAcknowledgement)?;
        stream.write_all(&hint_len.to_be_bytes()).await?;
        stream.write_all(hint.as_bytes()).await?;
        stream.shutdown().await?;

        let mut prefix = [0_u8; FRAME_PREFIX_BYTES];
        stream.read_exact(&mut prefix).await?;
        let ack_len = usize::try_from(u32::from_be_bytes(prefix))
            .map_err(|_| ThreatHintIngressError::InvalidAcknowledgement)?;
        if ack_len == 0 || ack_len > MAX_ACK_BYTES {
            return Err(ThreatHintIngressError::InvalidAcknowledgement);
        }
        let mut ack_bytes = vec![0_u8; ack_len];
        stream.read_exact(&mut ack_bytes).await?;
        let mut trailing = [0_u8; 1];
        if stream.read(&mut trailing).await? != 0 {
            return Err(ThreatHintIngressError::InvalidAcknowledgement);
        }

        let ack: ThreatHintIngressAck = serde_json::from_slice(&ack_bytes)
            .map_err(|_| ThreatHintIngressError::InvalidAcknowledgement)?;
        let canonical =
            serde_json::to_vec(&ack).map_err(|_| ThreatHintIngressError::InvalidAcknowledgement)?;
        if canonical != ack_bytes || !ack.has_valid_identifiers(hint.as_bytes()) {
            return Err(ThreatHintIngressError::InvalidAcknowledgement);
        }
        Ok(ack.status.into())
    }
}

/// Failure at the local ThreatHint verifier boundary.
#[derive(Debug, Error)]
pub enum ThreatHintIngressError {
    #[error("ThreatHint ingress timeout must be in (0, 60] seconds")]
    InvalidTimeout,
    #[error("ThreatHint ingress path must be an owner-only Unix socket")]
    UnsafeSocket,
    #[error("ThreatHint ingress operation timed out")]
    Timeout,
    #[error("ThreatHint ingress acknowledgement is invalid")]
    InvalidAcknowledgement,
    #[error("ThreatHint ingress is temporarily unavailable")]
    Unavailable,
    #[error("ThreatHint ingress I/O failed")]
    Io(#[from] std::io::Error),
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
enum IngressStatus {
    Accepted,
    Duplicate,
    Rejected,
    Busy,
}

impl From<IngressStatus> for ThreatHintAckStatus {
    fn from(status: IngressStatus) -> Self {
        match status {
            IngressStatus::Accepted => Self::Accepted,
            IngressStatus::Duplicate => Self::Duplicate,
            IngressStatus::Rejected => Self::Rejected,
            IngressStatus::Busy => Self::Busy,
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ThreatHintIngressAck {
    payload_digest: String,
    protocol_version: u8,
    status: IngressStatus,
}

impl ThreatHintIngressAck {
    fn has_valid_identifiers(&self, hint: &[u8]) -> bool {
        if self.protocol_version != PROTOCOL_VERSION {
            return false;
        }
        match self.status {
            IngressStatus::Busy => self.payload_digest.is_empty(),
            _ => self.payload_digest == format!("{:x}", Sha256::digest(hint)),
        }
    }
}

fn effective_uid() -> u32 {
    rustix::process::geteuid().as_raw()
}

fn validate_socket(path: &Path, expected_uid: u32) -> Result<(), ThreatHintIngressError> {
    validate_socket_parent(path, expected_uid)?;
    let socket_metadata = path
        .symlink_metadata()
        .map_err(|error| match error.kind() {
            std::io::ErrorKind::NotFound => ThreatHintIngressError::Unavailable,
            _ => ThreatHintIngressError::Io(error),
        })?;
    if !socket_metadata.file_type().is_socket()
        || socket_metadata.mode() & 0o777 != 0o600
        || socket_metadata.uid() != expected_uid
    {
        return Err(ThreatHintIngressError::UnsafeSocket);
    }
    Ok(())
}

fn validate_socket_parent(path: &Path, expected_uid: u32) -> Result<(), ThreatHintIngressError> {
    if !path.is_absolute() || path.file_name().is_none() {
        return Err(ThreatHintIngressError::UnsafeSocket);
    }
    let parent = path.parent().ok_or(ThreatHintIngressError::UnsafeSocket)?;
    let parent_metadata = parent
        .symlink_metadata()
        .map_err(|_| ThreatHintIngressError::UnsafeSocket)?;
    if parent_metadata.file_type().is_symlink()
        || !parent_metadata.is_dir()
        || parent_metadata.mode() & 0o777 != 0o700
        || parent_metadata.uid() != expected_uid
    {
        return Err(ThreatHintIngressError::UnsafeSocket);
    }
    Ok(())
}

fn map_connect_error(error: std::io::Error) -> ThreatHintIngressError {
    match error.kind() {
        std::io::ErrorKind::NotFound
        | std::io::ErrorKind::ConnectionRefused
        | std::io::ErrorKind::ConnectionReset => ThreatHintIngressError::Unavailable,
        _ => ThreatHintIngressError::Io(error),
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

    fn hint() -> ThreatHintBytes {
        ThreatHintBytes::new(
            br#"{"schema_version":1,"threat_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","confidence_bps":9000,"indicator_type":"file_hash","proof_system":"groth16_kip16_v1","proof":"010203","report_nonce":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","observed_at":1}"#.to_vec(),
        )
        .expect("canonical hint")
    }

    async fn serve_ack(path: PathBuf, expected: Vec<u8>, ack: Vec<u8>) {
        let listener = UnixListener::bind(&path).expect("bind test ingress");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .expect("owner-only ingress socket");
        let (mut stream, _) = listener.accept().await.expect("accept ingress client");
        let length = stream.read_u32().await.expect("read hint length") as usize;
        let mut received = vec![0_u8; length];
        stream
            .read_exact(&mut received)
            .await
            .expect("read exact hint");
        assert_eq!(received, expected);
        stream
            .write_u32(u32::try_from(ack.len()).expect("bounded test ack"))
            .await
            .expect("write ack length");
        stream.write_all(&ack).await.expect("write ack");
    }

    fn canonical_ack(hint: &[u8], status: IngressStatus) -> Vec<u8> {
        let payload_digest = if status == IngressStatus::Busy {
            String::new()
        } else {
            format!("{:x}", Sha256::digest(hint))
        };
        serde_json::to_vec(&ThreatHintIngressAck {
            payload_digest,
            protocol_version: PROTOCOL_VERSION,
            status,
        })
        .expect("canonical ack")
    }

    #[tokio::test]
    async fn forwards_exact_hint_and_accepts_digest_bound_ack() {
        let directory = owner_only_dir();
        let path = directory.path().join("threat-hint.sock");
        let hint = hint();
        let server = tokio::spawn(serve_ack(
            path.clone(),
            hint.as_bytes().to_vec(),
            canonical_ack(hint.as_bytes(), IngressStatus::Accepted),
        ));
        tokio::task::yield_now().await;

        let ingress =
            UnixThreatHintIngress::new(path, Duration::from_secs(1)).expect("configured ingress");
        assert_eq!(
            ingress.forward(&hint).await.expect("accepted response"),
            ThreatHintAckStatus::Accepted
        );
        server.await.expect("server task");
    }

    #[tokio::test]
    async fn rejects_ack_with_wrong_digest() {
        let directory = owner_only_dir();
        let path = directory.path().join("threat-hint.sock");
        let hint = hint();
        let ack = serde_json::to_vec(&ThreatHintIngressAck {
            payload_digest: "0".repeat(64),
            protocol_version: PROTOCOL_VERSION,
            status: IngressStatus::Rejected,
        })
        .expect("ack");
        let server = tokio::spawn(serve_ack(path.clone(), hint.as_bytes().to_vec(), ack));
        tokio::task::yield_now().await;

        let ingress =
            UnixThreatHintIngress::new(path, Duration::from_secs(1)).expect("configured ingress");
        assert!(matches!(
            ingress.forward(&hint).await,
            Err(ThreatHintIngressError::InvalidAcknowledgement)
        ));
        server.await.expect("server task");
    }

    #[tokio::test]
    async fn missing_socket_is_unavailable() {
        let directory = owner_only_dir();
        let ingress = UnixThreatHintIngress::configured(
            directory.path().join("missing.sock"),
            Duration::from_secs(1),
        )
        .expect("configured ingress");
        assert!(matches!(
            ingress.forward(&hint()).await,
            Err(ThreatHintIngressError::Unavailable)
        ));
    }

    #[tokio::test]
    async fn busy_ack_is_unbound_and_canonical() {
        let directory = owner_only_dir();
        let path = directory.path().join("threat-hint.sock");
        let hint = hint();
        let server = tokio::spawn(serve_ack(
            path.clone(),
            hint.as_bytes().to_vec(),
            canonical_ack(hint.as_bytes(), IngressStatus::Busy),
        ));
        tokio::task::yield_now().await;

        let ingress =
            UnixThreatHintIngress::new(path, Duration::from_secs(1)).expect("configured ingress");
        assert_eq!(
            ingress.forward(&hint).await.expect("busy response"),
            ThreatHintAckStatus::Busy
        );
        server.await.expect("server task");
    }

    #[tokio::test]
    async fn acknowledgement_with_trailing_bytes_fails_closed() {
        let directory = owner_only_dir();
        let path = directory.path().join("threat-hint.sock");
        let hint = hint();
        let expected = hint.as_bytes().to_vec();
        let ack = canonical_ack(hint.as_bytes(), IngressStatus::Rejected);
        let server_path = path.clone();
        let server = tokio::spawn(async move {
            let listener = UnixListener::bind(&server_path).expect("bind test ingress");
            fs::set_permissions(&server_path, fs::Permissions::from_mode(0o600))
                .expect("owner-only ingress socket");
            let (mut stream, _) = listener.accept().await.expect("accept ingress client");
            let length = stream.read_u32().await.expect("read hint length") as usize;
            let mut received = vec![0_u8; length];
            stream.read_exact(&mut received).await.expect("read hint");
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
            UnixThreatHintIngress::new(path, Duration::from_secs(1)).expect("configured ingress");
        assert!(matches!(
            ingress.forward(&hint).await,
            Err(ThreatHintIngressError::InvalidAcknowledgement)
        ));
        server.await.expect("server task");
    }

    #[tokio::test]
    async fn regular_file_is_not_an_ingress_socket() {
        let directory = owner_only_dir();
        let path = directory.path().join("threat-hint.sock");
        fs::write(&path, b"not a socket").expect("write regular file");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .expect("owner-only regular file");
        assert!(matches!(
            UnixThreatHintIngress::new(path, Duration::from_secs(1)),
            Err(ThreatHintIngressError::UnsafeSocket)
        ));
    }
}

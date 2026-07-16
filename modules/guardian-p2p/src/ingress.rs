//! Owner-only AF_UNIX bridge to the Python authenticated-ballot collector.

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

use crate::{AckStatus, BallotBytes};

const INGRESS_PROTOCOL_VERSION: u8 = 1;
const MAX_INGRESS_ACK_BYTES: usize = 512;
const FRAME_PREFIX_BYTES: usize = 4;

/// Strict local client for the Guardian collector's owner-only Unix socket.
#[derive(Clone, Debug)]
pub struct UnixBallotIngress {
    path: PathBuf,
    timeout: Duration,
}

impl UnixBallotIngress {
    /// Validates the local socket path and constructs a bounded ingress client.
    pub fn new(path: impl Into<PathBuf>, timeout: Duration) -> Result<Self, IngressError> {
        let ingress = Self::configured(path, timeout)?;
        validate_socket(&ingress.path, effective_uid())?;
        Ok(ingress)
    }

    /// Constructs a bounded ingress client before the collector socket exists.
    pub fn configured(path: impl Into<PathBuf>, timeout: Duration) -> Result<Self, IngressError> {
        if timeout.is_zero() || timeout > Duration::from_secs(60) {
            return Err(IngressError::InvalidTimeout);
        }
        let path = path.into();
        validate_socket_parent(&path, effective_uid())?;
        Ok(Self { path, timeout })
    }

    /// Waits for the owner-only collector socket without weakening unsafe-path failures.
    pub async fn wait_ready(
        &self,
        wait_timeout: Duration,
        retry_interval: Duration,
    ) -> Result<(), IngressError> {
        if wait_timeout.is_zero()
            || wait_timeout > Duration::from_secs(5 * 60)
            || retry_interval < Duration::from_millis(10)
            || retry_interval > Duration::from_secs(5)
        {
            return Err(IngressError::InvalidTimeout);
        }
        let deadline = time::Instant::now() + wait_timeout;
        loop {
            match validate_socket(&self.path, effective_uid()) {
                Ok(()) => return Ok(()),
                Err(IngressError::Unavailable) if time::Instant::now() < deadline => {
                    time::sleep(retry_interval).await;
                }
                Err(IngressError::Unavailable) => return Err(IngressError::Timeout),
                Err(error) => return Err(error),
            }
        }
    }

    /// Forwards exact bytes and validates the canonical collector result.
    pub async fn forward(&self, ballot: &BallotBytes) -> Result<AckStatus, IngressError> {
        time::timeout(self.timeout, self.forward_inner(ballot))
            .await
            .map_err(|_| IngressError::Timeout)?
    }

    async fn forward_inner(&self, ballot: &BallotBytes) -> Result<AckStatus, IngressError> {
        let expected_uid = effective_uid();
        validate_socket(&self.path, expected_uid)?;
        let mut stream = UnixStream::connect(&self.path)
            .await
            .map_err(map_connect_error)?;
        if stream.peer_cred()?.uid() != expected_uid {
            return Err(IngressError::UnsafeSocket);
        }
        let ballot_len = u32::try_from(ballot.as_bytes().len())
            .map_err(|_| IngressError::InvalidAcknowledgement)?;
        stream.write_all(&ballot_len.to_be_bytes()).await?;
        stream.write_all(ballot.as_bytes()).await?;
        stream.shutdown().await?;

        let mut prefix = [0_u8; FRAME_PREFIX_BYTES];
        stream.read_exact(&mut prefix).await?;
        let ack_len = usize::try_from(u32::from_be_bytes(prefix))
            .map_err(|_| IngressError::InvalidAcknowledgement)?;
        if ack_len == 0 || ack_len > MAX_INGRESS_ACK_BYTES {
            return Err(IngressError::InvalidAcknowledgement);
        }
        let mut ack_bytes = vec![0_u8; ack_len];
        stream.read_exact(&mut ack_bytes).await?;
        let mut trailing = [0_u8; 1];
        if stream.read(&mut trailing).await? != 0 {
            return Err(IngressError::InvalidAcknowledgement);
        }

        let ack: IngressAck =
            serde_json::from_slice(&ack_bytes).map_err(|_| IngressError::InvalidAcknowledgement)?;
        let canonical =
            serde_json::to_vec(&ack).map_err(|_| IngressError::InvalidAcknowledgement)?;
        if canonical != ack_bytes || !ack.has_valid_identifiers(ballot.as_bytes()) {
            return Err(IngressError::InvalidAcknowledgement);
        }
        Ok(ack.status.into())
    }
}

/// Failure at the local process boundary. Details are not protocol responses.
#[derive(Debug, Error)]
pub enum IngressError {
    #[error("Guardian ingress timeout must be in (0, 60] seconds")]
    InvalidTimeout,
    #[error("Guardian ingress path must be an owner-only Unix socket")]
    UnsafeSocket,
    #[error("Guardian ingress operation timed out")]
    Timeout,
    #[error("Guardian ingress acknowledgement is invalid")]
    InvalidAcknowledgement,
    #[error("Guardian ingress is temporarily unavailable")]
    Unavailable,
    #[error("Guardian ingress I/O failed")]
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

impl From<IngressStatus> for AckStatus {
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
struct IngressAck {
    payload_digest: String,
    protocol_version: u8,
    session_id: String,
    status: IngressStatus,
}

impl IngressAck {
    fn has_valid_identifiers(&self, ballot: &[u8]) -> bool {
        if self.protocol_version != INGRESS_PROTOCOL_VERSION {
            return false;
        }
        let expected_digest = format!("{:x}", Sha256::digest(ballot));
        match self.status {
            IngressStatus::Accepted | IngressStatus::Duplicate => {
                is_lower_hex_32(&self.session_id) && self.payload_digest == expected_digest
            }
            IngressStatus::Rejected => {
                (self.session_id.is_empty() || is_lower_hex_32(&self.session_id))
                    && self.payload_digest == expected_digest
            }
            IngressStatus::Busy => self.session_id.is_empty() && self.payload_digest.is_empty(),
        }
    }
}

fn effective_uid() -> u32 {
    rustix::process::geteuid().as_raw()
}

fn validate_socket(path: &Path, expected_uid: u32) -> Result<(), IngressError> {
    validate_socket_parent(path, expected_uid)?;
    let socket_metadata = path
        .symlink_metadata()
        .map_err(|error| match error.kind() {
            std::io::ErrorKind::NotFound => IngressError::Unavailable,
            _ => IngressError::Io(error),
        })?;
    if !socket_metadata.file_type().is_socket()
        || socket_metadata.mode() & 0o777 != 0o600
        || socket_metadata.uid() != expected_uid
    {
        return Err(IngressError::UnsafeSocket);
    }
    Ok(())
}

fn validate_socket_parent(path: &Path, expected_uid: u32) -> Result<(), IngressError> {
    if !path.is_absolute() || path.file_name().is_none() {
        return Err(IngressError::UnsafeSocket);
    }
    let parent = path.parent().ok_or(IngressError::UnsafeSocket)?;
    let parent_metadata = parent
        .symlink_metadata()
        .map_err(|_| IngressError::UnsafeSocket)?;
    if parent_metadata.file_type().is_symlink()
        || !parent_metadata.is_dir()
        || parent_metadata.mode() & 0o777 != 0o700
        || parent_metadata.uid() != expected_uid
    {
        return Err(IngressError::UnsafeSocket);
    }
    Ok(())
}

fn map_connect_error(error: std::io::Error) -> IngressError {
    match error.kind() {
        std::io::ErrorKind::NotFound
        | std::io::ErrorKind::ConnectionRefused
        | std::io::ErrorKind::ConnectionReset => IngressError::Unavailable,
        _ => IngressError::Io(error),
    }
}

fn is_lower_hex_32(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
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

    async fn serve_ack(path: PathBuf, expected: Vec<u8>, ack: Vec<u8>) {
        let listener = UnixListener::bind(&path).expect("bind test ingress");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .expect("owner-only ingress socket");
        let (mut stream, _) = listener.accept().await.expect("accept ingress client");
        let length = stream.read_u32().await.expect("read ballot length") as usize;
        let mut received = vec![0_u8; length];
        stream
            .read_exact(&mut received)
            .await
            .expect("read exact ballot");
        assert_eq!(received, expected);
        stream
            .write_u32(u32::try_from(ack.len()).expect("bounded test ack"))
            .await
            .expect("write ack length");
        stream.write_all(&ack).await.expect("write ack");
    }

    fn canonical_ack(ballot: &[u8], status: IngressStatus) -> Vec<u8> {
        serde_json::to_vec(&IngressAck {
            payload_digest: format!("{:x}", Sha256::digest(ballot)),
            protocol_version: INGRESS_PROTOCOL_VERSION,
            session_id: "a".repeat(64),
            status,
        })
        .expect("serialize canonical test acknowledgement")
    }

    #[tokio::test]
    async fn exact_ballot_reaches_owner_only_ingress() {
        let directory = owner_only_dir();
        let path = directory.path().join("guardian.sock");
        let ballot = BallotBytes::new(b"exact canonical ballot".to_vec()).expect("ballot");
        let ack = canonical_ack(ballot.as_bytes(), IngressStatus::Accepted);
        let server = tokio::spawn(serve_ack(path.clone(), ballot.as_bytes().to_vec(), ack));
        tokio::task::yield_now().await;
        let ingress = UnixBallotIngress::new(&path, Duration::from_secs(2)).expect("ingress");
        assert_eq!(
            ingress.forward(&ballot).await.expect("accepted ack"),
            AckStatus::Accepted
        );
        server.await.expect("test ingress task");
    }

    #[tokio::test]
    async fn mismatched_payload_digest_fails_closed() {
        let directory = owner_only_dir();
        let path = directory.path().join("guardian.sock");
        let ballot = BallotBytes::new(b"exact canonical ballot".to_vec()).expect("ballot");
        let ack = serde_json::to_vec(&IngressAck {
            payload_digest: "0".repeat(64),
            protocol_version: INGRESS_PROTOCOL_VERSION,
            session_id: "a".repeat(64),
            status: IngressStatus::Accepted,
        })
        .expect("serialize bad ack");
        let server = tokio::spawn(serve_ack(path.clone(), ballot.as_bytes().to_vec(), ack));
        tokio::task::yield_now().await;
        let ingress = UnixBallotIngress::new(&path, Duration::from_secs(2)).expect("ingress");
        assert!(matches!(
            ingress.forward(&ballot).await,
            Err(IngressError::InvalidAcknowledgement)
        ));
        server.await.expect("test ingress task");
    }

    #[tokio::test]
    async fn missing_collector_is_temporarily_unavailable() {
        let directory = owner_only_dir();
        let path = directory.path().join("missing.sock");
        let ingress =
            UnixBallotIngress::configured(&path, Duration::from_secs(1)).expect("ingress config");
        let ballot = BallotBytes::new(b"bounded ballot".to_vec()).expect("ballot");

        assert!(matches!(
            ingress.forward(&ballot).await,
            Err(IngressError::Unavailable)
        ));
    }

    #[tokio::test]
    async fn acknowledgement_with_trailing_bytes_fails_closed() {
        let directory = owner_only_dir();
        let path = directory.path().join("guardian.sock");
        let ballot = BallotBytes::new(b"exact canonical ballot".to_vec()).expect("ballot");
        let ack = canonical_ack(ballot.as_bytes(), IngressStatus::Accepted);
        let expected = ballot.as_bytes().to_vec();
        let server_path = path.clone();
        let server = tokio::spawn(async move {
            let listener = UnixListener::bind(&server_path).expect("bind test ingress");
            fs::set_permissions(&server_path, fs::Permissions::from_mode(0o600))
                .expect("owner-only ingress socket");
            let (mut stream, _) = listener.accept().await.expect("accept ingress client");
            let length = stream.read_u32().await.expect("read ballot length") as usize;
            let mut received = vec![0_u8; length];
            stream
                .read_exact(&mut received)
                .await
                .expect("read exact ballot");
            assert_eq!(received, expected);
            stream
                .write_u32(u32::try_from(ack.len()).expect("bounded test ack"))
                .await
                .expect("write ack length");
            stream.write_all(&ack).await.expect("write ack");
            stream.write_all(b"trailing").await.expect("write trailing");
        });
        tokio::task::yield_now().await;
        let ingress = UnixBallotIngress::new(&path, Duration::from_secs(2)).expect("ingress");

        assert!(matches!(
            ingress.forward(&ballot).await,
            Err(IngressError::InvalidAcknowledgement)
        ));
        server.await.expect("test ingress task");
    }

    #[test]
    fn regular_file_is_not_an_ingress_socket() {
        let directory = owner_only_dir();
        let path = directory.path().join("guardian.sock");
        fs::write(&path, b"not a socket").expect("write fixture");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("owner-only fixture");
        assert!(matches!(
            UnixBallotIngress::new(path, Duration::from_secs(1)),
            Err(IngressError::UnsafeSocket)
        ));
    }
}

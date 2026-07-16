use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use libp2p_identity::PeerId;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{mpsc, oneshot, OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinSet;
use tokio::time;

use crate::BallotBytes;
use crate::MAX_BALLOT_BYTES;

const PROTOCOL_VERSION: u8 = 1;
const MAX_PEER_ID_BYTES: usize = 128;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
const DEFAULT_REQUEST_QUEUE: usize = 64;
pub const MAX_CONCURRENT_SUBMISSIONS: usize = 64;

/// Validates a not-yet-bound owner-only submission socket path.
pub fn validate_submission_path(path: &Path) -> Result<(), LocalSubmissionError> {
    if !path.is_absolute() {
        return Err(LocalSubmissionError::UnsafeSocket);
    }
    let expected_uid = effective_uid();
    validate_parent_directory(path, expected_uid)?;
    match path.symlink_metadata() {
        Ok(_) => Err(LocalSubmissionError::UnsafeSocket),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(LocalSubmissionError::Io(error)),
    }
}

/// Request sent from the local submit server into service logic.
#[derive(Debug)]
pub struct LocalSubmission {
    pub peer: PeerId,
    pub ballot: BallotBytes,
    pub response: oneshot::Sender<LocalSubmissionResult>,
}

/// Response delivered by service logic to local clients.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum LocalSubmissionResult {
    Accepted = 0,
    Duplicate = 1,
    Rejected = 2,
    Busy = 3,
    TransportFailure = 4,
}

impl LocalSubmissionResult {
    fn as_u8(self) -> u8 {
        self as u8
    }

    fn from_u8(raw: u8) -> Result<Self, LocalSubmissionError> {
        match raw {
            0 => Ok(Self::Accepted),
            1 => Ok(Self::Duplicate),
            2 => Ok(Self::Rejected),
            3 => Ok(Self::Busy),
            4 => Ok(Self::TransportFailure),
            _ => Err(LocalSubmissionError::InvalidResponse),
        }
    }

    /// Stable machine-readable result name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Duplicate => "duplicate",
            Self::Rejected => "rejected",
            Self::Busy => "busy",
            Self::TransportFailure => "transport-failure",
        }
    }
}

/// Listener for the owner-only local submission socket.
pub struct SubmissionServer {
    path: PathBuf,
    listener: UnixListener,
    admission: Arc<Semaphore>,
    request_tx: mpsc::Sender<LocalSubmission>,
    expected_uid: u32,
    request_timeout: Duration,
}

impl SubmissionServer {
    /// Build a server for a secure path and an owned request channel.
    ///
    /// - Path must be absolute.
    /// - Parent must be owned by effective UID and mode 0700.
    /// - Existing socket path is rejected.
    /// - Concurrency must be in 1..=64.
    pub fn bind(
        path: impl Into<PathBuf>,
        max_concurrent_submissions: usize,
        request_timeout: Duration,
    ) -> Result<(Self, mpsc::Receiver<LocalSubmission>), LocalSubmissionError> {
        if max_concurrent_submissions == 0
            || max_concurrent_submissions > MAX_CONCURRENT_SUBMISSIONS
        {
            return Err(LocalSubmissionError::InvalidConfig);
        }
        if request_timeout.is_zero() || request_timeout > REQUEST_TIMEOUT {
            return Err(LocalSubmissionError::InvalidTimeout);
        }

        let path = path.into();
        validate_submission_path(&path)?;
        let expected_uid = effective_uid();
        let listener = UnixListener::bind(&path).map_err(LocalSubmissionError::from)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .map_err(LocalSubmissionError::from)?;
        validate_existing_socket(&path, expected_uid)?;

        let (request_tx, request_rx) = mpsc::channel(DEFAULT_REQUEST_QUEUE);

        Ok((
            Self {
                path,
                listener,
                admission: Arc::new(Semaphore::new(max_concurrent_submissions)),
                request_tx,
                expected_uid,
                request_timeout,
            },
            request_rx,
        ))
    }

    /// Run until shutdown signal is received, then remove only the bound socket path.
    pub async fn run(
        self,
        mut shutdown: oneshot::Receiver<()>,
    ) -> Result<(), LocalSubmissionError> {
        let server = Arc::new(self);
        let mut tasks = JoinSet::new();

        loop {
            tokio::select! {
                _ = &mut shutdown => {
                    break;
                }
                completed = tasks.join_next(), if !tasks.is_empty() => {
                    let _ = completed;
                }
                accept_result = server.listener.accept() => {
                    let (stream, _) = accept_result.map_err(LocalSubmissionError::from)?;
                    if stream
                        .peer_cred()
                        .map(|credentials| credentials.uid() != server.expected_uid)
                        .unwrap_or(true)
                    {
                        continue;
                    }
                    let server = Arc::clone(&server);
                    match server.admission.clone().try_acquire_owned() {
                        Ok(permit) => {
                            tasks.spawn(async move {
                                server.handle_connection(stream, permit).await;
                            });
                        }
                        Err(_) => {
                            tasks.spawn(async move {
                                let mut stream = stream;
                                let _ = write_response(&mut stream, LocalSubmissionResult::Busy).await;
                            });
                        }
                    }
                }
            }
        }

        while let Some(completed) = tasks.join_next().await {
            let _ = completed;
        }

        cleanup_owned_socket(&server.path, server.expected_uid)
    }

    async fn handle_connection(
        self: Arc<Self>,
        mut stream: UnixStream,
        _permit: OwnedSemaphorePermit,
    ) {
        let response = match time::timeout(self.request_timeout, self.process(&mut stream)).await {
            Ok(Ok(result)) => result,
            Ok(Err(LocalSubmissionError::Busy)) => LocalSubmissionResult::Busy,
            _ => LocalSubmissionResult::TransportFailure,
        };

        let _ = write_response(&mut stream, response).await;
    }

    async fn process(
        self: Arc<Self>,
        stream: &mut UnixStream,
    ) -> Result<LocalSubmissionResult, LocalSubmissionError> {
        let client_uid = stream.peer_cred()?.uid();
        if client_uid != self.expected_uid {
            return Err(LocalSubmissionError::UnsafeSocket);
        }

        let submission = read_submission_request(stream).await?;
        let (response_tx, response_rx) = oneshot::channel();
        self.request_tx
            .send(LocalSubmission {
                peer: submission.peer,
                ballot: submission.ballot,
                response: response_tx,
            })
            .await
            .map_err(|_| LocalSubmissionError::TransportFailure)?;

        match time::timeout(self.request_timeout, response_rx).await {
            Ok(Ok(result)) => Ok(result),
            Ok(Err(_)) => Err(LocalSubmissionError::TransportFailure),
            Err(_) => Err(LocalSubmissionError::Timeout),
        }
    }
}

#[derive(Debug)]
struct ParsedSubmission {
    peer: PeerId,
    ballot: BallotBytes,
}

async fn read_submission_request(
    stream: &mut UnixStream,
) -> Result<ParsedSubmission, LocalSubmissionError> {
    let mut version = [0_u8; 1];
    stream.read_exact(&mut version).await?;
    if version[0] != PROTOCOL_VERSION {
        return Err(LocalSubmissionError::InvalidProtocolVersion);
    }

    let mut peer_len_buf = [0_u8; 2];
    stream.read_exact(&mut peer_len_buf).await?;
    let peer_len = usize::from(u16::from_be_bytes(peer_len_buf));
    if peer_len == 0 || peer_len > MAX_PEER_ID_BYTES {
        return Err(LocalSubmissionError::InvalidFrame);
    }

    let mut peer_bytes = vec![0_u8; peer_len];
    stream.read_exact(&mut peer_bytes).await?;
    let peer_text =
        std::str::from_utf8(&peer_bytes).map_err(|_| LocalSubmissionError::InvalidFrame)?;
    let peer = PeerId::from_str(peer_text).map_err(|_| LocalSubmissionError::InvalidPeerId)?;
    if peer_text != peer.to_string() {
        return Err(LocalSubmissionError::InvalidPeerId);
    }

    let mut ballot_len_buf = [0_u8; 4];
    stream.read_exact(&mut ballot_len_buf).await?;
    let ballot_len_u32 = u32::from_be_bytes(ballot_len_buf);
    let ballot_len =
        usize::try_from(ballot_len_u32).map_err(|_| LocalSubmissionError::InvalidFrame)?;
    if ballot_len == 0 || ballot_len > MAX_BALLOT_BYTES {
        return Err(LocalSubmissionError::InvalidFrame);
    }

    let mut ballot = vec![0_u8; ballot_len];
    stream.read_exact(&mut ballot).await?;
    let mut trailing = [0_u8; 1];
    if stream.read(&mut trailing).await? != 0 {
        return Err(LocalSubmissionError::InvalidFrame);
    }

    Ok(ParsedSubmission {
        peer,
        ballot: BallotBytes::new(ballot).map_err(|_| LocalSubmissionError::InvalidFrame)?,
    })
}

async fn write_response(
    stream: &mut UnixStream,
    status: LocalSubmissionResult,
) -> Result<(), LocalSubmissionError> {
    let payload = [PROTOCOL_VERSION, status.as_u8()];
    stream.write_all(&payload).await?;
    stream.shutdown().await?;
    Ok(())
}

/// Submit one ballot to the local collector over AF_UNIX.
pub async fn submit_ballot(
    socket_path: impl AsRef<Path>,
    peer: &PeerId,
    ballot: &BallotBytes,
    timeout: Duration,
) -> Result<LocalSubmissionResult, LocalSubmissionError> {
    if timeout.is_zero() || timeout > REQUEST_TIMEOUT {
        return Err(LocalSubmissionError::InvalidTimeout);
    }

    let socket_path = socket_path.as_ref();
    if !socket_path.is_absolute() {
        return Err(LocalSubmissionError::UnsafeSocket);
    }

    let expected_uid = effective_uid();
    validate_parent_directory(socket_path, expected_uid)?;
    validate_existing_socket(socket_path, expected_uid)?;

    let peer_text = peer.to_string();
    if peer_text.is_empty() || peer_text.len() > MAX_PEER_ID_BYTES {
        return Err(LocalSubmissionError::InvalidPeerId);
    }
    let canonical =
        PeerId::from_str(&peer_text).map_err(|_| LocalSubmissionError::InvalidPeerId)?;
    if canonical.to_string() != peer_text || canonical != *peer {
        return Err(LocalSubmissionError::InvalidPeerId);
    }

    let mut frame = Vec::with_capacity(1 + 2 + peer_text.len() + 4 + ballot.as_bytes().len());
    frame.push(PROTOCOL_VERSION);
    frame.extend_from_slice(
        &u16::try_from(peer_text.len())
            .map_err(|_| LocalSubmissionError::InvalidPeerId)?
            .to_be_bytes(),
    );
    frame.extend_from_slice(peer_text.as_bytes());
    let ballot_len =
        u32::try_from(ballot.as_bytes().len()).map_err(|_| LocalSubmissionError::InvalidFrame)?;
    frame.extend_from_slice(&ballot_len.to_be_bytes());
    frame.extend_from_slice(ballot.as_bytes());

    let mut stream = time::timeout(timeout, UnixStream::connect(socket_path))
        .await
        .map_err(|_| LocalSubmissionError::Timeout)?
        .map_err(LocalSubmissionError::from)?;

    let server_uid = stream.peer_cred()?.uid();
    if server_uid != expected_uid {
        return Err(LocalSubmissionError::UnsafeSocket);
    }

    time::timeout(timeout, stream.write_all(&frame))
        .await
        .map_err(|_| LocalSubmissionError::Timeout)?
        .map_err(LocalSubmissionError::from)?;
    time::timeout(timeout, stream.shutdown())
        .await
        .map_err(|_| LocalSubmissionError::Timeout)?
        .map_err(LocalSubmissionError::from)?;

    let mut response = [0_u8; 2];
    time::timeout(timeout, stream.read_exact(&mut response))
        .await
        .map_err(|_| LocalSubmissionError::Timeout)?
        .map_err(LocalSubmissionError::from)?;

    if response[0] != PROTOCOL_VERSION {
        return Err(LocalSubmissionError::InvalidResponse);
    }
    let mut trailing = [0_u8; 1];
    if time::timeout(timeout, stream.read(&mut trailing))
        .await
        .map_err(|_| LocalSubmissionError::Timeout)?
        .map_err(LocalSubmissionError::from)?
        != 0
    {
        return Err(LocalSubmissionError::InvalidResponse);
    }

    LocalSubmissionResult::from_u8(response[1])
}

fn validate_parent_directory(path: &Path, expected_uid: u32) -> Result<(), LocalSubmissionError> {
    let parent = path.parent().ok_or(LocalSubmissionError::UnsafeSocket)?;
    let metadata = parent
        .symlink_metadata()
        .map_err(|_| LocalSubmissionError::UnsafeSocket)?;

    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_dir()
        || metadata.uid() != expected_uid
        || metadata.mode() & 0o777 != 0o700
    {
        return Err(LocalSubmissionError::UnsafeSocket);
    }

    Ok(())
}

fn validate_existing_socket(path: &Path, expected_uid: u32) -> Result<(), LocalSubmissionError> {
    let metadata = path
        .symlink_metadata()
        .map_err(|_| LocalSubmissionError::UnsafeSocket)?;
    if !metadata.file_type().is_socket()
        || metadata.uid() != expected_uid
        || metadata.mode() & 0o777 != 0o600
    {
        return Err(LocalSubmissionError::UnsafeSocket);
    }

    Ok(())
}

fn cleanup_owned_socket(path: &Path, expected_uid: u32) -> Result<(), LocalSubmissionError> {
    let metadata = path
        .symlink_metadata()
        .map_err(LocalSubmissionError::from)?;
    if !metadata.file_type().is_socket() || metadata.uid() != expected_uid {
        return Err(LocalSubmissionError::UnsafeSocket);
    }

    std::fs::remove_file(path).map_err(LocalSubmissionError::from)?;
    Ok(())
}

fn effective_uid() -> u32 {
    rustix::process::geteuid().as_raw()
}

#[derive(Debug, Error)]
pub enum LocalSubmissionError {
    #[error("invalid local socket path or ownership")]
    UnsafeSocket,
    #[error("invalid protocol version")]
    InvalidProtocolVersion,
    #[error("invalid frame")]
    InvalidFrame,
    #[error("invalid peer id")]
    InvalidPeerId,
    #[error("invalid timeout")]
    InvalidTimeout,
    #[error("invalid response")]
    InvalidResponse,
    #[error("server busy")]
    Busy,
    #[error("invalid configuration")]
    InvalidConfig,
    #[error("timed out")]
    Timeout,
    #[error("transport failure")]
    TransportFailure,
    #[error("io error")]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixListener;
    use tokio::net::UnixStream;
    use tokio::time::Duration;

    use super::*;

    fn owner_only_parent() -> TempDir {
        let directory = tempfile::tempdir().expect("temp dir");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("set strict parent permissions");
        directory
    }

    fn owner_only_peer() -> libp2p_identity::PeerId {
        let keypair = libp2p_identity::Keypair::generate_ed25519();
        keypair.public().to_peer_id()
    }

    #[tokio::test]
    async fn exact_roundtrip() {
        let directory = owner_only_parent();
        let socket_path = directory.path().join("guardian.sock");

        let (server, mut rx) =
            SubmissionServer::bind(&socket_path, 4, Duration::from_secs(1)).expect("bind");
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let server_task = tokio::spawn(async move {
            server.run(shutdown_rx).await.expect("run");
        });

        let peer = owner_only_peer();
        let ballot = BallotBytes::new(b"exact ballot".to_vec()).expect("ballot");

        let client_path = socket_path.clone();
        let client_peer = peer;
        let client_ballot = ballot.clone();
        let client = tokio::spawn(async move {
            submit_ballot(
                &client_path,
                &client_peer,
                &client_ballot,
                Duration::from_secs(1),
            )
            .await
        });
        let request = rx.recv().await.expect("request");
        assert_eq!(request.peer, peer);
        assert_eq!(request.ballot.as_bytes(), ballot.as_bytes());
        request
            .response
            .send(LocalSubmissionResult::Accepted)
            .expect("reply");
        let response = client.await.expect("client task").expect("result");
        assert_eq!(response, LocalSubmissionResult::Accepted);

        shutdown_tx.send(()).expect("shutdown");
        server_task.await.expect("server task");
    }

    #[tokio::test]
    async fn oversized_and_invalid_framing_is_rejected() {
        let directory = owner_only_parent();
        let socket_path = directory.path().join("guardian.sock");

        let (server, _rx) =
            SubmissionServer::bind(&socket_path, 4, Duration::from_secs(1)).expect("bind");
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        tokio::spawn(async move {
            server.run(shutdown_rx).await.expect("run");
        });

        let mut malformed = Vec::new();
        malformed.push(PROTOCOL_VERSION);
        malformed.extend_from_slice(&(3_u16).to_be_bytes());
        malformed.extend_from_slice(&[0xff, 0xff, 0xff]);
        malformed.extend_from_slice(&(1_u32).to_be_bytes());
        malformed.push(0x00);

        let mut stream = UnixStream::connect(&socket_path)
            .await
            .expect("connect server");
        stream
            .write_all(&malformed)
            .await
            .expect("send malformed frame");
        stream.shutdown().await.expect("close malformed frame");
        let mut response = [0_u8; 2];
        stream
            .read_exact(&mut response)
            .await
            .expect("read malformed response");
        let status = LocalSubmissionResult::from_u8(response[1]).expect("status");
        assert_eq!(status, LocalSubmissionResult::TransportFailure);

        shutdown_tx.send(()).expect("shutdown");
    }

    #[tokio::test]
    async fn unsafe_parent_is_rejected() {
        let directory = tempfile::tempdir().expect("temp dir");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o755))
            .expect("unsafe permissions");

        let socket_path = directory.path().join("guardian.sock");
        assert!(matches!(
            SubmissionServer::bind(&socket_path, 4, Duration::from_secs(1)),
            Err(LocalSubmissionError::UnsafeSocket)
        ));
    }

    #[tokio::test]
    async fn wrong_response_version_is_rejected() {
        let directory = owner_only_parent();
        let socket_path = directory.path().join("guardian.sock");
        let listener = UnixListener::bind(&socket_path).expect("bind mock");
        fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600))
            .expect("set socket permission");

        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept mock");
            let mut request = [0_u8; 1];
            let _ = stream.read_exact(&mut request).await;
            let _ = stream
                .write_all(&[PROTOCOL_VERSION + 1, LocalSubmissionResult::Accepted as u8])
                .await;
            let _ = stream.shutdown().await;
        });

        let peer = owner_only_peer();
        let ballot = BallotBytes::new(b"hello".to_vec()).expect("ballot");

        let err = submit_ballot(&socket_path, &peer, &ballot, Duration::from_secs(1))
            .await
            .unwrap_err();
        assert!(matches!(err, LocalSubmissionError::InvalidResponse));
    }

    #[tokio::test]
    async fn admission_limit_blocks_concurrent_requests() {
        let directory = owner_only_parent();
        let socket_path = directory.path().join("guardian.sock");

        let (server, mut rx) =
            SubmissionServer::bind(&socket_path, 1, Duration::from_secs(1)).expect("bind");
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let server_task = tokio::spawn(async move {
            server.run(shutdown_rx).await.expect("run");
        });

        let peer = owner_only_peer();
        let ballot = BallotBytes::new(b"payload".to_vec()).expect("ballot");

        let first_path = socket_path.clone();
        let first_peer = peer;
        let first_ballot = ballot.clone();
        let first_task = tokio::spawn(async move {
            submit_ballot(
                &first_path,
                &first_peer,
                &first_ballot,
                Duration::from_secs(1),
            )
            .await
        });
        let first_request = rx.recv().await.expect("first request admitted");

        let second = submit_ballot(&socket_path, &peer, &ballot, Duration::from_secs(1))
            .await
            .expect("second result");
        first_request
            .response
            .send(LocalSubmissionResult::Accepted)
            .expect("first response");
        let first = first_task.await.expect("first task").expect("first result");

        shutdown_tx.send(()).expect("shutdown");
        server_task.await.expect("server task");

        assert_eq!(first, LocalSubmissionResult::Accepted);
        assert_eq!(second, LocalSubmissionResult::Busy);
    }

    #[tokio::test]
    async fn malformed_submit_ballot_path() {
        let directory = owner_only_parent();
        let socket_path = directory.path().join("guardian.sock");
        fs::write(&socket_path, b"not-a-socket").expect("write fixture");
        let peer = owner_only_peer();
        let ballot = BallotBytes::new(b"hello".to_vec()).expect("ballot");

        let err = submit_ballot(&socket_path, &peer, &ballot, Duration::from_secs(1))
            .await
            .unwrap_err();
        assert!(matches!(err, LocalSubmissionError::UnsafeSocket));
    }
}

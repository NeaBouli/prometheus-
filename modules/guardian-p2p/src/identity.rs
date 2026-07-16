//! Persistent, owner-only libp2p transport identity storage.

use std::{
    ffi::{OsStr, OsString},
    fs::File,
    io::{Read, Write},
    path::{Component, Path},
    sync::atomic::{AtomicU64, Ordering},
};

use libp2p_identity::Keypair;
use rustix::{
    fs::{self, AtFlags, FileType, Mode, OFlags},
    io::Errno,
    process,
};
use thiserror::Error;

const MAX_IDENTITY_BYTES: usize = 1_024;
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Failure to securely load or create the transport identity.
#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("transport identity path must be an absolute file path")]
    InvalidPath,
    #[error("transport identity parent must be an owner-only directory")]
    UnsafeParent,
    #[error("transport identity must be an owner-only regular file")]
    UnsafeFile,
    #[error("transport identity encoding is invalid")]
    InvalidIdentity,
    #[error("transport identity filesystem operation failed")]
    Filesystem(#[source] Errno),
    #[error("transport identity I/O operation failed")]
    Io(#[source] std::io::Error),
}

/// Loads an existing transport identity or atomically creates an Ed25519 identity.
///
/// The direct parent directory must be owned by the effective user and mode `0700`.
/// Existing identity files must be regular, owned by the effective user, readable only
/// by that user, and no larger than the bounded protobuf representation.
pub fn load_or_create_transport_identity(path: &Path) -> Result<Keypair, IdentityError> {
    let (parent, file_name) = split_identity_path(path)?;
    let parent_fd = fs::open(
        parent,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(IdentityError::Filesystem)?;
    validate_parent(&parent_fd)?;

    match open_identity(&parent_fd, file_name) {
        Ok(file) => read_identity(file),
        Err(Errno::NOENT) => create_identity(&parent_fd, file_name),
        Err(error) => Err(IdentityError::Filesystem(error)),
    }
}

fn split_identity_path(path: &Path) -> Result<(&Path, &OsStr), IdentityError> {
    if !path.is_absolute() || !matches!(path.components().next_back(), Some(Component::Normal(_))) {
        return Err(IdentityError::InvalidPath);
    }

    let parent = path.parent().ok_or(IdentityError::InvalidPath)?;
    let file_name = path.file_name().ok_or(IdentityError::InvalidPath)?;
    Ok((parent, file_name))
}

fn validate_parent(parent_fd: &impl std::os::fd::AsFd) -> Result<(), IdentityError> {
    let stat = fs::fstat(parent_fd).map_err(IdentityError::Filesystem)?;
    let mode = stat.st_mode as u32;
    let owner = process::geteuid().as_raw();

    if !FileType::from_raw_mode(stat.st_mode).is_dir()
        || stat.st_uid != owner
        || mode & 0o077 != 0
        || mode & 0o700 != 0o700
    {
        return Err(IdentityError::UnsafeParent);
    }

    Ok(())
}

fn open_identity(parent_fd: &impl std::os::fd::AsFd, file_name: &OsStr) -> Result<File, Errno> {
    fs::openat(
        parent_fd,
        file_name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map(File::from)
}

fn validate_identity_file(file: &File) -> Result<(), IdentityError> {
    let stat = fs::fstat(file).map_err(IdentityError::Filesystem)?;
    let mode = stat.st_mode as u32;

    if !FileType::from_raw_mode(stat.st_mode).is_file()
        || stat.st_uid != process::geteuid().as_raw()
        || mode & 0o177 != 0
        || mode & 0o400 == 0
    {
        return Err(IdentityError::UnsafeFile);
    }

    Ok(())
}

fn read_identity(file: File) -> Result<Keypair, IdentityError> {
    validate_identity_file(&file)?;

    let mut encoded = Vec::with_capacity(MAX_IDENTITY_BYTES + 1);
    file.take((MAX_IDENTITY_BYTES + 1) as u64)
        .read_to_end(&mut encoded)
        .map_err(IdentityError::Io)?;
    if encoded.is_empty() || encoded.len() > MAX_IDENTITY_BYTES {
        encoded.fill(0);
        return Err(IdentityError::InvalidIdentity);
    }

    let decoded = Keypair::from_protobuf_encoding(&encoded);
    let mut canonical = decoded
        .as_ref()
        .ok()
        .and_then(|keypair| keypair.to_protobuf_encoding().ok());
    let is_canonical = canonical
        .as_ref()
        .is_some_and(|canonical| canonical == &encoded);
    encoded.fill(0);
    if let Some(canonical) = &mut canonical {
        canonical.fill(0);
    }
    if !is_canonical {
        return Err(IdentityError::InvalidIdentity);
    }
    decoded.map_err(|_| IdentityError::InvalidIdentity)
}

fn create_identity(
    parent_fd: &impl std::os::fd::AsFd,
    file_name: &OsStr,
) -> Result<Keypair, IdentityError> {
    let keypair = Keypair::generate_ed25519();
    let mut encoded = keypair
        .to_protobuf_encoding()
        .map_err(|_| IdentityError::InvalidIdentity)?;
    if encoded.is_empty() || encoded.len() > MAX_IDENTITY_BYTES {
        encoded.fill(0);
        return Err(IdentityError::InvalidIdentity);
    }

    let temp_name = temporary_name(file_name);
    let temp_fd = fs::openat(
        parent_fd,
        &temp_name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(IdentityError::Filesystem)?;
    let mut temp_file = File::from(temp_fd);

    let write_result = temp_file
        .write_all(&encoded)
        .and_then(|()| temp_file.sync_all());
    encoded.fill(0);
    if let Err(error) = write_result {
        let _ = fs::unlinkat(parent_fd, &temp_name, AtFlags::empty());
        return Err(IdentityError::Io(error));
    }
    drop(temp_file);

    let publish_result = fs::linkat(
        parent_fd,
        &temp_name,
        parent_fd,
        file_name,
        AtFlags::empty(),
    );
    let cleanup_result = fs::unlinkat(parent_fd, &temp_name, AtFlags::empty());
    cleanup_result.map_err(IdentityError::Filesystem)?;

    match publish_result {
        Ok(()) => {
            fs::fsync(parent_fd).map_err(IdentityError::Filesystem)?;
            Ok(keypair)
        }
        Err(Errno::EXIST) => {
            let file = open_identity(parent_fd, file_name).map_err(IdentityError::Filesystem)?;
            read_identity(file)
        }
        Err(error) => Err(IdentityError::Filesystem(error)),
    }
}

fn temporary_name(file_name: &OsStr) -> OsString {
    let sequence = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut name = OsString::from(".");
    name.push(file_name);
    name.push(format!(".tmp-{}-{sequence}", std::process::id()));
    name
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        os::unix::fs::{symlink, PermissionsExt},
        sync::{Arc, Barrier},
        thread,
    };

    use tempfile::TempDir;

    use super::*;

    fn secure_tempdir() -> TempDir {
        let directory = tempfile::tempdir().expect("temporary directory");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("secure temporary directory permissions");
        directory
    }

    #[test]
    fn creates_private_identity_and_reuses_peer_id() {
        let directory = secure_tempdir();
        let path = directory.path().join("transport.identity");

        let created = load_or_create_transport_identity(&path).expect("create identity");
        let reloaded = load_or_create_transport_identity(&path).expect("reload identity");

        assert_eq!(
            created.public().to_peer_id(),
            reloaded.public().to_peer_id()
        );
        let mode = fs::metadata(path)
            .expect("identity metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn rejects_unsafe_parent_permissions() {
        let directory = secure_tempdir();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o750))
            .expect("unsafe temporary directory permissions");

        let error = load_or_create_transport_identity(&directory.path().join("identity"))
            .expect_err("unsafe parent must fail");
        assert!(matches!(error, IdentityError::UnsafeParent));
    }

    #[test]
    fn rejects_group_readable_identity() {
        let directory = secure_tempdir();
        let path = directory.path().join("identity");
        fs::write(&path, b"not-secret-test-data").expect("write identity fixture");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640))
            .expect("set unsafe identity permissions");

        let error = load_or_create_transport_identity(&path)
            .expect_err("group-readable identity must fail");
        assert!(matches!(error, IdentityError::UnsafeFile));
    }

    #[test]
    fn rejects_identity_symlink() {
        let directory = secure_tempdir();
        let target = directory.path().join("target");
        let link = directory.path().join("identity");
        fs::write(&target, b"not-secret-test-data").expect("write target fixture");
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600))
            .expect("set target permissions");
        symlink(&target, &link).expect("create identity symlink");

        assert!(load_or_create_transport_identity(&link).is_err());
    }

    #[test]
    fn rejects_parent_symlink() {
        let root = secure_tempdir();
        let target = root.path().join("target");
        let link = root.path().join("linked-parent");
        fs::create_dir(&target).expect("create target directory");
        fs::set_permissions(&target, fs::Permissions::from_mode(0o700))
            .expect("set target permissions");
        symlink(&target, &link).expect("create parent symlink");

        assert!(load_or_create_transport_identity(&link.join("identity")).is_err());
    }

    #[test]
    fn rejects_malformed_and_oversized_identity() {
        for bytes in [vec![0xff], vec![0u8; MAX_IDENTITY_BYTES + 1]] {
            let directory = secure_tempdir();
            let path = directory.path().join("identity");
            fs::write(&path, bytes).expect("write malformed identity");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
                .expect("set identity permissions");

            assert!(matches!(
                load_or_create_transport_identity(&path),
                Err(IdentityError::InvalidIdentity)
            ));
        }
    }

    #[test]
    fn concurrent_creation_returns_one_peer_id() {
        const THREADS: usize = 8;
        let directory = secure_tempdir();
        let path = directory.path().join("identity");
        let barrier = Arc::new(Barrier::new(THREADS));

        let workers: Vec<_> = (0..THREADS)
            .map(|_| {
                let path = path.clone();
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    load_or_create_transport_identity(&path)
                        .expect("concurrent identity creation")
                        .public()
                        .to_peer_id()
                })
            })
            .collect();

        let peer_ids: Vec<_> = workers
            .into_iter()
            .map(|worker| worker.join().expect("identity worker"))
            .collect();
        assert!(peer_ids.iter().all(|peer_id| peer_id == &peer_ids[0]));

        let leftovers: Vec<_> = fs::read_dir(directory.path())
            .expect("read identity directory")
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().contains(".tmp-"))
            .collect();
        assert!(leftovers.is_empty());
    }
}

//! Owner-local byte quarantine vault.
//!
//! This module is a Development-only library foundation. It is not wired into
//! any runtime, scanner, or rule-sync path, and it carries no production
//! authority.
//!
//! What it does: stores exact caller-supplied bytes under a private
//! owner-local directory, keyed by an internally derived SHA-256 digest, and
//! reads them back with exact digest verification.
//!
//! What it does not do (limitations are part of the API contract):
//! - No source-path API: callers pass bytes only. The vault never touches,
//!   moves, or deletes any source file.
//! - No automatic isolation: storing bytes here does not prevent execution,
//!   access, or anything else. It is a byte vault, not a security boundary.
//! - No detection or verdict: the vault does not classify content.
//! - Ancestor directories of the vault root are outside its control; the
//!   owner is responsible for placing the root in a private location.
//!
//! Safety properties enforced on POSIX:
//! - Strict 16 MiB item maximum; oversized input fails closed.
//! - Vault root and items use owner-only modes (0700 / 0600).
//! - Items are opened with `O_NOFOLLOW`; symlink entries are rejected.
//! - Hard-linked, non-regular, over-permissive, length-mismatched, or
//!   digest-mismatched existing entries are rejected.
//! - Store is atomic create-and-publish (temp file, fsync, hard-link
//!   publish, temp cleanup) and idempotent for exact duplicates.
//!
//! Byte contents are never included in `Debug` output or error messages;
//! only digests, lengths, and paths appear.

use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result};
use rustix::fs::{Mode, OFlags};
use sha2::{Digest, Sha256};

/// Strict maximum item size: 16 MiB. Larger items fail closed.
pub const MAX_ITEM_LEN: usize = 16 * 1024 * 1024;

/// Process-local counter for unique temporary file names inside the vault.
static TMP_NAME_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Opaque identity of one stored vault item.
///
/// Derived entirely inside the vault from the exact stored bytes: the
/// SHA-256 digest of the content and its length. Callers cannot supply a
/// digest or identity. Carries no content; `Debug` shows only the digest and
/// length.
#[derive(Clone, PartialEq, Eq)]
pub struct QuarantineRecord {
    digest: [u8; 32],
    len: u64,
}

impl QuarantineRecord {
    /// SHA-256 digest of the exact stored bytes.
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }

    /// Length of the exact stored bytes.
    pub fn len(&self) -> u64 {
        self.len
    }

    /// Whether the stored byte string is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl fmt::Debug for QuarantineRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QuarantineRecord")
            .field("digest", &hex::encode(self.digest))
            .field("len", &self.len)
            .finish()
    }
}

/// Owner-local byte vault. See the module documentation for the full
/// limitation contract; this type provides byte storage only and no
/// isolation, detection, or execution-prevention semantics.
pub struct QuarantineVault {
    root: PathBuf,
}

impl QuarantineVault {
    /// Open an existing vault root or create a new one.
    ///
    /// The root must not be a symlink or a non-directory. A newly created
    /// root gets mode 0700 (POSIX); an existing root must already be
    /// owner-only (no group/other permission bits), otherwise opening fails
    /// closed.
    pub fn open_or_create(root: &Path) -> Result<Self> {
        match fs::symlink_metadata(root) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    anyhow::bail!("quarantine root must not be a symlink");
                }
                if !metadata.is_dir() {
                    anyhow::bail!("quarantine root is not a directory");
                }
                ensure_owner_only_dir(&metadata)?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::DirBuilderExt;
                    let mut builder = fs::DirBuilder::new();
                    builder.mode(0o700);
                    builder
                        .create(root)
                        .context("failed to create private quarantine root")?;
                }
                #[cfg(not(unix))]
                {
                    fs::create_dir(root).context("failed to create quarantine root")?;
                }
            }
            Err(error) => {
                return Err(error).context("failed to inspect quarantine root");
            }
        }
        Ok(Self {
            root: root.to_path_buf(),
        })
    }

    /// The vault root directory.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Store exact caller-supplied bytes and return their internally derived
    /// record identity.
    ///
    /// Idempotent: storing bytes whose exact item already exists returns the
    /// same record, but only after the existing entry passes full structural
    /// and digest verification. A corrupt, symlinked, hard-linked,
    /// over-permissive, or non-regular existing entry fails closed.
    ///
    /// The publish is atomic: bytes go to a fresh owner-only temporary file,
    /// are fsynced, and are published via a hard link that fails rather than
    /// replacing any existing entry. The temporary file is cleaned up on
    /// every path.
    pub fn store(&self, bytes: &[u8]) -> Result<QuarantineRecord> {
        if bytes.len() > MAX_ITEM_LEN {
            anyhow::bail!("quarantine item exceeds the 16 MiB limit");
        }
        let record = QuarantineRecord {
            digest: Sha256::digest(bytes).into(),
            len: bytes.len() as u64,
        };
        let final_path = self.item_path(&record.digest);

        match fs::symlink_metadata(&final_path) {
            Ok(_) => {
                // Duplicate candidate: only valid if it verifies exactly.
                self.verify_duplicate(&record)?;
                return Ok(record);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).context("failed to inspect quarantine entry");
            }
        }

        let tmp_path = self.root.join(format!(
            ".prom-quarantine-tmp-{}-{}",
            std::process::id(),
            TMP_NAME_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));

        if let Err(error) = self.write_and_publish(&tmp_path, &final_path, bytes, &record) {
            let _ = fs::remove_file(&tmp_path);
            return Err(error);
        }
        fs::remove_file(&tmp_path).context("failed to clean quarantine temporary file")?;
        self.sync_root()?;

        Ok(record)
    }

    /// Read back the exact bytes for a record, with full structural checks
    /// and exact SHA-256 verification. Bounded: never reads more than
    /// [`MAX_ITEM_LEN`] + 1 bytes, and any length or digest mismatch fails
    /// closed.
    pub fn read(&self, record: &QuarantineRecord) -> Result<Vec<u8>> {
        if record.len > MAX_ITEM_LEN as u64 {
            anyhow::bail!("quarantine record exceeds the 16 MiB limit");
        }
        let path = self.item_path(&record.digest);
        let metadata = inspect_item(&path)?;
        if metadata.len() != record.len {
            anyhow::bail!("quarantine entry length mismatch");
        }

        let mut file = rustix::fs::open(
            &path,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map(fs::File::from)
        .context("failed to open quarantine entry")?;

        let mut bytes = Vec::with_capacity(record.len as usize);
        (&mut file)
            .take(MAX_ITEM_LEN as u64 + 1)
            .read_to_end(&mut bytes)
            .context("failed to read quarantine entry")?;
        if bytes.len() as u64 != record.len {
            anyhow::bail!("quarantine entry length changed while reading");
        }
        let actual: [u8; 32] = Sha256::digest(&bytes).into();
        if actual != record.digest {
            anyhow::bail!("quarantine entry digest mismatch");
        }
        Ok(bytes)
    }

    /// Write bytes to a fresh owner-only temp file, fsync, and publish via
    /// hard link. Never replaces an existing final entry; a concurrently
    /// published entry is verified instead.
    fn write_and_publish(
        &self,
        tmp_path: &Path,
        final_path: &Path,
        bytes: &[u8],
        record: &QuarantineRecord,
    ) -> Result<()> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut tmp = options
            .open(tmp_path)
            .context("failed to create quarantine temporary file")?;
        tmp.write_all(bytes)
            .context("failed to write quarantine temporary file")?;
        tmp.sync_all()
            .context("failed to sync quarantine temporary file")?;
        drop(tmp);

        match fs::hard_link(tmp_path, final_path) {
            Ok(()) => self.sync_root(),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                // Lost a publish race: accept only an exactly verifying entry.
                self.verify_duplicate(record)
            }
            Err(error) => Err(error).context("failed to publish quarantine entry"),
        }
    }

    fn verify_duplicate(&self, record: &QuarantineRecord) -> Result<()> {
        let mut last_error = None;
        for _ in 0..4 {
            match self.read(record) {
                Ok(_) => return Ok(()),
                Err(error) => {
                    last_error = Some(error);
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
            }
        }
        match last_error {
            Some(error) => Err(error),
            None => Err(anyhow::anyhow!("duplicate verification failed")),
        }
    }

    #[cfg(unix)]
    fn sync_root(&self) -> Result<()> {
        let root = rustix::fs::open(
            &self.root,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map(fs::File::from)
        .context("failed to open quarantine root for sync")?;
        root.sync_all().context("failed to sync quarantine root")
    }

    #[cfg(not(unix))]
    fn sync_root(&self) -> Result<()> {
        Ok(())
    }

    fn item_path(&self, digest: &[u8; 32]) -> PathBuf {
        self.root.join(hex::encode(digest))
    }
}

/// Structural checks for an existing vault entry: must be a regular file,
/// never a symlink, and (POSIX) not hard-linked and owner-only.
fn inspect_item(path: &Path) -> Result<fs::Metadata> {
    let metadata =
        fs::symlink_metadata(path).context("failed to inspect quarantine entry metadata")?;
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        anyhow::bail!("quarantine entry must not be a symlink");
    }
    if !file_type.is_file() {
        anyhow::bail!("quarantine entry is not a regular file");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        use std::os::unix::fs::PermissionsExt;
        if metadata.nlink() != 1 {
            anyhow::bail!("quarantine entry must not be hard-linked");
        }
        if metadata.permissions().mode() & 0o777 != 0o600 {
            anyhow::bail!("quarantine entry permissions must be 0600");
        }
    }
    Ok(metadata)
}

/// Require an existing vault root directory to be owner-only (POSIX).
#[cfg(unix)]
fn ensure_owner_only_dir(metadata: &fs::Metadata) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    if metadata.permissions().mode() & 0o777 != 0o700 {
        anyhow::bail!("quarantine root permissions must be 0700");
    }
    Ok(())
}

/// Non-POSIX fallback: mode enforcement is unavailable.
#[cfg(not(unix))]
fn ensure_owner_only_dir(_metadata: &fs::Metadata) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    fn vault() -> (tempfile::TempDir, QuarantineVault) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("vault");
        let vault = QuarantineVault::open_or_create(&root).unwrap();
        (dir, vault)
    }

    #[cfg(unix)]
    fn mode(path: &Path) -> u32 {
        fs::symlink_metadata(path).unwrap().permissions().mode() & 0o777
    }

    fn record_path(vault: &QuarantineVault, record: &QuarantineRecord) -> PathBuf {
        vault.root().join(hex::encode(record.digest()))
    }

    #[test]
    fn test_store_read_roundtrip() {
        let (_dir, vault) = vault();
        let bytes = b"exact caller-supplied bytes";
        let record = vault.store(bytes).unwrap();
        assert_eq!(record.len(), bytes.len() as u64);
        assert_eq!(vault.read(&record).unwrap(), bytes);
    }

    #[test]
    fn test_store_empty_bytes_roundtrip() {
        let (_dir, vault) = vault();
        let record = vault.store(b"").unwrap();
        assert!(record.is_empty());
        assert_eq!(vault.read(&record).unwrap(), b"");
    }

    #[cfg(unix)]
    #[test]
    fn test_private_modes_on_root_and_item() {
        let (_dir, vault) = vault();
        assert_eq!(mode(vault.root()), 0o700);
        let record = vault.store(b"mode check").unwrap();
        assert_eq!(mode(&record_path(&vault, &record)), 0o600);
    }

    #[test]
    fn test_reopen_existing_root() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("vault");
        let record = {
            let vault = QuarantineVault::open_or_create(&root).unwrap();
            vault.store(b"persisted").unwrap()
        };
        let vault = QuarantineVault::open_or_create(&root).unwrap();
        assert_eq!(vault.read(&record).unwrap(), b"persisted");
    }

    #[cfg(unix)]
    #[test]
    fn test_rejects_over_permissive_existing_root() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("vault");
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(QuarantineVault::open_or_create(&root).is_err());
        fs::set_permissions(&root, fs::Permissions::from_mode(0o500)).unwrap();
        assert!(QuarantineVault::open_or_create(&root).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn test_rejects_symlink_root() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("real");
        fs::create_dir(&target).unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(QuarantineVault::open_or_create(&link).is_err());
    }

    #[test]
    fn test_rejects_non_directory_root() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("file");
        fs::write(&file, b"not a dir").unwrap();
        assert!(QuarantineVault::open_or_create(&file).is_err());
    }

    #[test]
    fn test_rejects_oversized_item_fail_closed() {
        let (_dir, vault) = vault();
        let bytes = vec![0u8; MAX_ITEM_LEN + 1];
        assert!(vault.store(&bytes).is_err());
        // Nothing was published.
        assert!(fs::read_dir(vault.root()).unwrap().next().is_none());
    }

    #[test]
    fn test_accepts_exactly_max_item_boundary() {
        let (_dir, vault) = vault();
        let bytes = vec![b'x'; MAX_ITEM_LEN];
        let record = vault.store(&bytes).unwrap();
        assert_eq!(vault.read(&record).unwrap(), bytes);
    }

    #[test]
    fn test_duplicate_store_is_idempotent() {
        let (_dir, vault) = vault();
        let bytes = b"duplicate content";
        let first = vault.store(bytes).unwrap();
        let second = vault.store(bytes).unwrap();
        assert_eq!(first, second);
        let entries: Vec<_> = fs::read_dir(vault.root()).unwrap().collect();
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn test_no_temporary_leftovers_after_stores() {
        let (_dir, vault) = vault();
        vault.store(b"one").unwrap();
        vault.store(b"two").unwrap();
        vault.store(b"one").unwrap();
        let names: Vec<String> = fs::read_dir(vault.root())
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names.len(), 2);
        assert!(names
            .iter()
            .all(|name| !name.starts_with(".prom-quarantine-tmp-")));
    }

    #[test]
    fn test_corrupt_entry_fails_read_and_store() {
        let (_dir, vault) = vault();
        let record = vault.store(b"integrity matters").unwrap();
        let path = record_path(&vault, &record);
        // Flip one byte in place (same length, owner-writable temp attack).
        let mut corrupted = fs::read(&path).unwrap();
        corrupted[0] ^= 0x01;
        fs::write(&path, &corrupted).unwrap();
        assert!(vault.read(&record).is_err());
        // Storing the original bytes again must not silently succeed.
        assert!(vault.store(b"integrity matters").is_err());
    }

    #[test]
    fn test_length_mismatch_fails_closed() {
        let (_dir, vault) = vault();
        let record = vault.store(b"length check").unwrap();
        let path = record_path(&vault, &record);
        // Append a byte: length no longer matches the record.
        let mut extended = fs::read(&path).unwrap();
        extended.push(0x00);
        fs::write(&path, &extended).unwrap();
        assert!(vault.read(&record).is_err());
        assert!(vault.store(b"length check").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn test_symlink_entry_rejected() {
        let (_dir, vault) = vault();
        let record = vault.store(b"symlink target content").unwrap();
        let path = record_path(&vault, &record);
        let outside = vault.root().join("..").join("outside-payload");
        fs::write(&outside, b"outside").unwrap();
        fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(&outside, &path).unwrap();
        assert!(vault.read(&record).is_err());
        assert!(vault.store(b"symlink target content").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn test_hard_linked_entry_rejected() {
        let (_dir, vault) = vault();
        let record = vault.store(b"hardlink content").unwrap();
        let path = record_path(&vault, &record);
        let alias = vault.root().join("alias");
        fs::hard_link(&path, &alias).unwrap();
        assert!(vault.read(&record).is_err());
        assert!(vault.store(b"hardlink content").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn test_non_regular_entry_rejected() {
        let (_dir, vault) = vault();
        let record = vault.store(b"dir collision").unwrap();
        let path = record_path(&vault, &record);
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();
        assert!(vault.read(&record).is_err());
        assert!(vault.store(b"dir collision").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn test_over_permissive_entry_rejected() {
        let (_dir, vault) = vault();
        let record = vault.store(b"perm content").unwrap();
        let path = record_path(&vault, &record);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(vault.read(&record).is_err());
        assert!(vault.store(b"perm content").is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
        assert!(vault.read(&record).is_err());
    }

    #[test]
    fn test_missing_entry_fails_read() {
        let (_dir, vault) = vault();
        let record = vault.store(b"ephemeral").unwrap();
        fs::remove_file(record_path(&vault, &record)).unwrap();
        assert!(vault.read(&record).is_err());
    }

    #[test]
    fn test_record_identity_derived_internally() {
        let (_dir, vault) = vault();
        let record = vault.store(b"test").unwrap();
        assert_eq!(
            hex::encode(record.digest()),
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
        );
        // Item file name is the hex digest: identity is fully internal.
        assert!(record_path(&vault, &record).exists());
    }

    #[test]
    fn test_debug_and_errors_redact_byte_contents() {
        let (_dir, vault) = vault();
        let marker = "SENSITIVE_BYTE_MARKER_7f3a";
        let mut bytes = marker.as_bytes().to_vec();
        bytes.extend_from_slice(&[0xAA, 0xBB, 0xCC]);
        let record = vault.store(&bytes).unwrap();

        let debug = format!("{record:?}");
        assert!(!debug.contains(marker));

        // Trigger a corruption error and check the message too.
        let path = record_path(&vault, &record);
        let mut corrupted = fs::read(&path).unwrap();
        corrupted[0] ^= 0x01;
        fs::write(&path, &corrupted).unwrap();
        let error = format!("{:#}", vault.read(&record).unwrap_err());
        assert!(!error.contains(marker));
    }

    #[test]
    fn test_distinct_contents_distinct_records() {
        let (_dir, vault) = vault();
        let a = vault.store(b"content-a").unwrap();
        let b = vault.store(b"content-b").unwrap();
        assert_ne!(a, b);
        assert_eq!(vault.read(&a).unwrap(), b"content-a");
        assert_eq!(vault.read(&b).unwrap(), b"content-b");
    }
}

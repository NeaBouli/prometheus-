//! Development-only durable anti-downgrade state for RuleStorage sync (GH-207).
//!
//! All network/content/parser work is completed before the checkpoint lock is
//! taken. A forward checkpoint is written and fsynced before the already
//! validated rules are installed through an infallible assignment. A process
//! crash in that narrow gap converges on the next exact replay: the checkpoint
//! write is skipped, but the prepared rules are still installed.
//!
//! The POSIX store trusts the caller to provide an owner-controlled parent path.
//! It validates the final directory/file components with `NOFOLLOW`, ownership,
//! type and restrictive modes. This is not a production authority boundary.

use std::collections::HashSet;
use std::ffi::OsString;
use std::fmt;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use log::info;
use rustix::fs::{self, AtFlags, FileType, FlockOperation, Mode, OFlags};
use rustix::io::Errno;
use rustix::process;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::runtime::{require_stub_allowed, require_stub_allowed_for, RuntimeMode};
use crate::security::scanner::YaraScanner;

use super::rule_fetch::{validate_canonical_raw_cid, RuleContentSource};
use super::rule_ingest::{PreparedRuleSnapshot, RuleMetadataSnapshotEntry, MAX_RULES_PER_SNAPSHOT};
use super::rule_observation::{
    verify_observation_live_shared, RuleObservationSource, OBSERVATION_NETWORK_ID,
};
use super::rule_sync::RuleSyncEntry;

const CHECKPOINT_FILE: &str = "rule-storage.checkpoint.json";
const LOCK_FILE: &str = "rule-storage.checkpoint.lock";
const CHECKPOINT_KIND: &str = "prometheus.rule-storage.checkpoint.v1";
const DIGEST_DOMAIN: &[u8] = b"prometheus.rule-storage.snapshot.v1\0";
const CHECKPOINT_SCHEMA_VERSION: u64 = 1;
pub const MAX_CHECKPOINT_BYTES: usize = 1024;
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Generic redacted failure for the complete durable path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuleCheckpointError;

impl fmt::Display for RuleCheckpointError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("durable RuleStorage sync failed")
    }
}

impl std::error::Error for RuleCheckpointError {}

/// Locked checkpoint persistence seam for deterministic failure tests.
pub trait RuleCheckpointLock {
    fn read(&self) -> Result<Option<Vec<u8>>, RuleCheckpointError>;
    fn replace(&self, canonical_bytes: &[u8]) -> Result<(), RuleCheckpointError>;
}

/// Nonblocking exclusive checkpoint store.
pub trait RuleCheckpointStore {
    fn lock(&self) -> Result<Box<dyn RuleCheckpointLock + '_>, RuleCheckpointError>;
}

/// Owner-only POSIX checkpoint directory.
pub struct PosixRuleCheckpointStore {
    directory: File,
}

impl PosixRuleCheckpointStore {
    pub fn open(path: &Path) -> Result<Self, RuleCheckpointError> {
        require_stub_allowed("durable RuleStorage sync").map_err(|_| RuleCheckpointError)?;
        let directory = fs::open(
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map(File::from)
        .map_err(|_| RuleCheckpointError)?;
        validate_directory(&directory)?;
        Ok(Self { directory })
    }

    pub fn open_for_mode(mode: RuntimeMode, path: &Path) -> Result<Self, RuleCheckpointError> {
        require_stub_allowed("durable RuleStorage sync").map_err(|_| RuleCheckpointError)?;
        require_stub_allowed_for(mode, "durable RuleStorage sync")
            .map_err(|_| RuleCheckpointError)?;
        Self::open(path)
    }
}

impl RuleCheckpointStore for PosixRuleCheckpointStore {
    fn lock(&self) -> Result<Box<dyn RuleCheckpointLock + '_>, RuleCheckpointError> {
        validate_directory(&self.directory)?;
        let lock = fs::openat(
            &self.directory,
            LOCK_FILE,
            OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map(File::from)
        .map_err(|_| RuleCheckpointError)?;
        validate_private_file(&lock, false)?;
        fs::flock(&lock, FlockOperation::NonBlockingLockExclusive)
            .map_err(|_| RuleCheckpointError)?;
        Ok(Box::new(PosixLock {
            directory: &self.directory,
            _lock: lock,
        }))
    }
}

struct PosixLock<'a> {
    directory: &'a File,
    _lock: File,
}

impl RuleCheckpointLock for PosixLock<'_> {
    fn read(&self) -> Result<Option<Vec<u8>>, RuleCheckpointError> {
        let file = match fs::openat(
            self.directory,
            CHECKPOINT_FILE,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => File::from(fd),
            Err(Errno::NOENT) => return Ok(None),
            Err(_) => return Err(RuleCheckpointError),
        };
        validate_private_file(&file, true)?;
        let mut bytes = Vec::with_capacity(MAX_CHECKPOINT_BYTES + 1);
        file.take((MAX_CHECKPOINT_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| RuleCheckpointError)?;
        if bytes.is_empty() || bytes.len() > MAX_CHECKPOINT_BYTES {
            return Err(RuleCheckpointError);
        }
        Ok(Some(bytes))
    }

    fn replace(&self, canonical_bytes: &[u8]) -> Result<(), RuleCheckpointError> {
        if canonical_bytes.is_empty() || canonical_bytes.len() > MAX_CHECKPOINT_BYTES {
            return Err(RuleCheckpointError);
        }
        let sequence = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let temp = OsString::from(format!(
            ".rule-storage.checkpoint.tmp-{}-{sequence}",
            std::process::id()
        ));
        let fd = fs::openat(
            self.directory,
            &temp,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(|_| RuleCheckpointError)?;
        let mut output = File::from(fd);
        if output
            .write_all(canonical_bytes)
            .and_then(|()| output.sync_all())
            .is_err()
        {
            let _ = fs::unlinkat(self.directory, &temp, AtFlags::empty());
            return Err(RuleCheckpointError);
        }
        drop(output);
        if fs::renameat(self.directory, &temp, self.directory, CHECKPOINT_FILE).is_err() {
            let _ = fs::unlinkat(self.directory, &temp, AtFlags::empty());
            return Err(RuleCheckpointError);
        }
        fs::fsync(self.directory).map_err(|_| RuleCheckpointError)
    }
}

fn validate_directory(directory: &File) -> Result<(), RuleCheckpointError> {
    let stat = fs::fstat(directory).map_err(|_| RuleCheckpointError)?;
    let mode = stat.st_mode as u32;
    if !FileType::from_raw_mode(stat.st_mode).is_dir()
        || stat.st_uid != process::geteuid().as_raw()
        || mode & 0o077 != 0
        || mode & 0o700 != 0o700
        || mode & 0o7000 != 0
    {
        return Err(RuleCheckpointError);
    }
    Ok(())
}

fn validate_private_file(file: &File, require_nonempty: bool) -> Result<(), RuleCheckpointError> {
    let stat = fs::fstat(file).map_err(|_| RuleCheckpointError)?;
    let mode = stat.st_mode as u32;
    if !FileType::from_raw_mode(stat.st_mode).is_file()
        || stat.st_uid != process::geteuid().as_raw()
        || mode & 0o177 != 0
        || mode & 0o7000 != 0
        || (require_nonempty && (stat.st_size <= 0 || stat.st_size as usize > MAX_CHECKPOINT_BYTES))
    {
        return Err(RuleCheckpointError);
    }
    Ok(())
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Checkpoint {
    schema_version: u64,
    kind: String,
    network_id: String,
    order: u64,
    snapshot_digest: String,
}

struct Identity {
    rule_id: String,
    cid: String,
    transaction_id: String,
    index: u32,
    block_daa: u64,
    virtual_daa: u64,
}

fn parse_checkpoint(bytes: &[u8]) -> Result<Checkpoint, RuleCheckpointError> {
    if bytes.is_empty() || bytes.len() > MAX_CHECKPOINT_BYTES {
        return Err(RuleCheckpointError);
    }
    let checkpoint: Checkpoint = serde_json::from_slice(bytes).map_err(|_| RuleCheckpointError)?;
    let canonical = serde_json::to_vec(&checkpoint).map_err(|_| RuleCheckpointError)?;
    if canonical != bytes
        || checkpoint.schema_version != CHECKPOINT_SCHEMA_VERSION
        || checkpoint.kind != CHECKPOINT_KIND
        || checkpoint.network_id != OBSERVATION_NETWORK_ID
        || checkpoint.order == 0
        || checkpoint.snapshot_digest.len() != 64
        || !checkpoint
            .snapshot_digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(RuleCheckpointError);
    }
    Ok(checkpoint)
}

fn digest_snapshot(order: u64, identities: &mut [Identity]) -> String {
    identities.sort_by(|a, b| {
        (
            &a.rule_id,
            &a.cid,
            &a.transaction_id,
            a.index,
            a.block_daa,
            a.virtual_daa,
        )
            .cmp(&(
                &b.rule_id,
                &b.cid,
                &b.transaction_id,
                b.index,
                b.block_daa,
                b.virtual_daa,
            ))
    });
    let mut hash = Sha256::new();
    hash.update(DIGEST_DOMAIN);
    hash.update(CHECKPOINT_SCHEMA_VERSION.to_le_bytes());
    hash.update(OBSERVATION_NETWORK_ID.as_bytes());
    hash.update(order.to_le_bytes());
    hash.update((identities.len() as u64).to_le_bytes());
    for identity in identities {
        for field in [
            identity.rule_id.as_bytes(),
            identity.cid.as_bytes(),
            identity.transaction_id.as_bytes(),
        ] {
            hash.update((field.len() as u64).to_le_bytes());
            hash.update(field);
        }
        hash.update(identity.index.to_le_bytes());
        hash.update(identity.block_daa.to_le_bytes());
        hash.update(identity.virtual_daa.to_le_bytes());
    }
    hex::encode(hash.finalize())
}

/// Durable development-only sync using the owner-local POSIX store.
pub async fn sync_rule_snapshot_durable(
    store: &dyn RuleCheckpointStore,
    scanner: &mut YaraScanner,
    content_source: &dyn RuleContentSource,
    observation_source: &dyn RuleObservationSource,
    entries: &[RuleSyncEntry],
    empty_snapshot_order: Option<u64>,
) -> Result<(), RuleCheckpointError> {
    require_stub_allowed("durable RuleStorage sync").map_err(|_| RuleCheckpointError)?;
    sync_validated(
        store,
        scanner,
        content_source,
        observation_source,
        entries,
        empty_snapshot_order,
    )
    .await
}

pub async fn sync_rule_snapshot_durable_for_mode(
    mode: RuntimeMode,
    store: &dyn RuleCheckpointStore,
    scanner: &mut YaraScanner,
    content_source: &dyn RuleContentSource,
    observation_source: &dyn RuleObservationSource,
    entries: &[RuleSyncEntry],
    empty_snapshot_order: Option<u64>,
) -> Result<(), RuleCheckpointError> {
    require_stub_allowed("durable RuleStorage sync").map_err(|_| RuleCheckpointError)?;
    require_stub_allowed_for(mode, "durable RuleStorage sync").map_err(|_| RuleCheckpointError)?;
    sync_validated(
        store,
        scanner,
        content_source,
        observation_source,
        entries,
        empty_snapshot_order,
    )
    .await
}

async fn sync_validated(
    store: &dyn RuleCheckpointStore,
    scanner: &mut YaraScanner,
    content_source: &dyn RuleContentSource,
    observation_source: &dyn RuleObservationSource,
    entries: &[RuleSyncEntry],
    empty_snapshot_order: Option<u64>,
) -> Result<(), RuleCheckpointError> {
    if entries.len() > MAX_RULES_PER_SNAPSHOT
        || (!entries.is_empty() && empty_snapshot_order.is_some())
    {
        return Err(RuleCheckpointError);
    }
    let mut outpoints = HashSet::with_capacity(entries.len());
    let mut rule_ids = HashSet::with_capacity(entries.len());
    let mut cids = HashSet::with_capacity(entries.len());
    let mut verified = Vec::with_capacity(entries.len());
    for entry in entries {
        let (metadata, observation) = verify_observation_live_shared(
            observation_source,
            &entry.address,
            &entry.expected_manifest_sha256,
            &entry.manifest_json,
            &entry.constructor_json,
        )
        .await
        .map_err(|_| RuleCheckpointError)?;
        if !outpoints.insert(observation.clone())
            || !rule_ids.insert(metadata.rule_id().to_string())
            || !cids.insert(metadata.ipfs_cid().to_string())
        {
            return Err(RuleCheckpointError);
        }
        verified.push((metadata, observation));
    }

    let mut snapshot = Vec::with_capacity(verified.len());
    let mut identities = Vec::with_capacity(verified.len());
    for (metadata, observation) in verified {
        validate_canonical_raw_cid(metadata.ipfs_cid()).map_err(|_| RuleCheckpointError)?;
        let content = content_source
            .fetch_rule_content(metadata.ipfs_cid())
            .await
            .map_err(|_| RuleCheckpointError)?;
        identities.push(Identity {
            rule_id: metadata.rule_id().to_string(),
            cid: metadata.ipfs_cid().to_string(),
            transaction_id: observation.transaction_id,
            index: observation.index,
            block_daa: observation.block_daa_score,
            virtual_daa: observation.observed_virtual_daa_score,
        });
        snapshot.push(RuleMetadataSnapshotEntry { metadata, content });
    }
    let prepared = PreparedRuleSnapshot::prepare(&snapshot).map_err(|_| RuleCheckpointError)?;
    let order = if identities.is_empty() {
        empty_snapshot_order
            .filter(|value| *value > 0)
            .ok_or(RuleCheckpointError)?
    } else {
        identities
            .iter()
            .map(|identity| identity.virtual_daa)
            .min()
            .filter(|value| *value > 0)
            .ok_or(RuleCheckpointError)?
    };
    let digest = digest_snapshot(order, &mut identities);
    let candidate = Checkpoint {
        schema_version: CHECKPOINT_SCHEMA_VERSION,
        kind: CHECKPOINT_KIND.to_string(),
        network_id: OBSERVATION_NETWORK_ID.to_string(),
        order,
        snapshot_digest: digest,
    };
    let encoded = serde_json::to_vec(&candidate).map_err(|_| RuleCheckpointError)?;
    if encoded.len() > MAX_CHECKPOINT_BYTES {
        return Err(RuleCheckpointError);
    }

    // Keep checkpoint replacement and scanner installation synchronous: the
    // coordinator may cancel only before this indivisible mutation tail.
    let lock = store.lock()?;
    let replay = if let Some(current) = lock.read()? {
        let current = parse_checkpoint(&current)?;
        if candidate.order < current.order
            || (candidate.order == current.order
                && candidate.snapshot_digest != current.snapshot_digest)
        {
            return Err(RuleCheckpointError);
        }
        candidate.order == current.order
    } else {
        false
    };
    if !replay {
        lock.replace(&encoded)?;
    }
    scanner.install_prevalidated(prepared.into_rules());
    info!("Installed {} durable CID-bound rules", scanner.rule_count());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generic_error_is_redacted() {
        assert_eq!(
            RuleCheckpointError.to_string(),
            "durable RuleStorage sync failed"
        );
        assert_eq!(format!("{RuleCheckpointError:?}"), "RuleCheckpointError");
    }

    #[test]
    fn checkpoint_parser_rejects_unknown_and_noncanonical_data() {
        let unknown = br#"{"schema_version":1,"kind":"prometheus.rule-storage.checkpoint.v1","network_id":"testnet-10","order":1,"snapshot_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","extra":1}"#;
        assert!(parse_checkpoint(unknown).is_err());
        let pretty = b"{\n  \"schema_version\": 1\n}";
        assert!(parse_checkpoint(pretty).is_err());
    }
}

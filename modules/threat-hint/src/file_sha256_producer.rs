//! Local-only `file_sha256` observable production from exact artifact bytes.

use sha2::{Digest, Sha256};

use crate::{ObservableBundle, ObservableBundleError, ScopeFormat, ScopePlatform};

/// Produces one canonical `file_sha256` bundle from the exact bytes supplied.
///
/// This function performs no filesystem access and establishes no provenance
/// beyond deterministic derivation from `artifact_bytes`. The resulting
/// `public_auto_v1` profile does not authorize disclosure or transport.
pub fn produce_file_sha256_bundle(
    artifact_bytes: &[u8],
    platform: ScopePlatform,
    format: ScopeFormat,
) -> Result<ObservableBundle, ObservableBundleError> {
    let digest: [u8; 32] = Sha256::digest(artifact_bytes).into();
    ObservableBundle::from_file_sha256_digest(platform, format, digest)
}

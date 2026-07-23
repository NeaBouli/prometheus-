//! Local-only `byte_pattern` production from an exact artifact-byte selection.

use crate::observable_bundle::{
    MAX_BYTE_PATTERN_TOKENS, MIN_BYTE_PATTERN_TOKENS, MIN_FIXED_BYTE_PATTERN_TOKENS,
};
use crate::{ObservableBundle, ObservableBundleError, ScopeFormat, ScopePlatform};

/// Produces one review-required `byte_pattern` bundle from exact artifact bytes.
///
/// `wildcard_mask` selects a bounded range beginning at `start`; `true` emits
/// `??`, while `false` emits the corresponding lowercase artifact byte. This
/// function performs no filesystem access and does not authorize disclosure or
/// transport.
pub fn produce_byte_pattern_bundle(
    artifact_bytes: &[u8],
    start: usize,
    wildcard_mask: &[bool],
    platform: ScopePlatform,
    format: ScopeFormat,
) -> Result<ObservableBundle, ObservableBundleError> {
    if !(MIN_BYTE_PATTERN_TOKENS..=MAX_BYTE_PATTERN_TOKENS).contains(&wildcard_mask.len())
        || wildcard_mask.iter().filter(|wildcard| !**wildcard).count()
            < MIN_FIXED_BYTE_PATTERN_TOKENS
    {
        return Err(ObservableBundleError::InvalidObservable);
    }

    let end = start
        .checked_add(wildcard_mask.len())
        .ok_or(ObservableBundleError::InvalidObservable)?;
    let selected = artifact_bytes
        .get(start..end)
        .ok_or(ObservableBundleError::InvalidObservable)?;
    let tokens: Vec<Option<u8>> = selected
        .iter()
        .zip(wildcard_mask)
        .map(|(&byte, &wildcard)| (!wildcard).then_some(byte))
        .collect();

    ObservableBundle::from_byte_pattern_tokens(platform, format, &tokens)
}

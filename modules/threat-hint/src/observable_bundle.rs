//! Local-only canonical Observable Bundle definitions for structural validation.

use core::cmp::Ordering;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use thiserror::Error;

const OBSERVABLE_BUNDLE_SCHEMA_VERSION: u16 = 1;
const MAX_CANONICAL_BYTES: usize = 4096;
const MIN_OBSERVABLES: usize = 1;
const MAX_OBSERVABLES: usize = 16;
const MIN_NETWORK_LEN: usize = 2;
const MAX_NETWORK_LEN: usize = 64;
const MAX_API_IMPORT_LEN: usize = 96;
const NONCE_BYTES: usize = 32;
const MIN_BYTE_PATTERN_TOKENS: usize = 8;
const MAX_BYTE_PATTERN_TOKENS: usize = 64;
const COMMITMENT_DOMAIN: &[u8] = b"prometheus-threat-observable-bundle-v1\0";

#[derive(Debug, Error, PartialEq, Eq)]
/// Errors returned while parsing, validating, or committing an observable bundle.
pub enum ObservableBundleError {
    /// The input is empty, malformed JSON, invalid UTF-8, or otherwise undecodable.
    #[error("invalid observable bundle payload")]
    InvalidPayload,
    /// The bundle uses an unsupported schema version.
    #[error("invalid schema version")]
    InvalidSchemaVersion,
    /// The disclosure policy is incompatible with the bundle contents.
    #[error("invalid disclosure policy")]
    InvalidDisclosurePolicy,
    /// An observable kind or value violates its grammar.
    #[error("invalid observable")]
    InvalidObservable,
    /// The observable count is outside the permitted range.
    #[error("invalid observables")]
    InvalidObservables,
    /// The canonical bundle exceeds 4096 bytes.
    #[error("bundle exceeds 4096-byte canonical limit")]
    BundleTooLarge,
    /// Observables are not in strict `(kind, value)` byte order.
    #[error("observables must be strictly sorted")]
    UnsortedObservables,
    /// The bundle contains the same `(kind, value)` pair more than once.
    #[error("duplicate observable detected")]
    DuplicateObservable,
    /// The input JSON bytes differ from the canonical serialization.
    #[error("non-canonical payload")]
    NotCanonical,
    /// The expected commitment does not have the required length.
    #[error("invalid commitment")]
    InvalidCommitment,
    /// The network identifier violates the canonical network grammar.
    #[error("invalid network id")]
    InvalidNetworkId,
    /// The report nonce is not exactly 32 lowercase-hex bytes.
    #[error("invalid report nonce")]
    InvalidReportNonce,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
/// Classifies structural disclosure handling; it does not authorize transport.
pub enum DisclosurePolicy {
    /// Identifies the public-auto structural profile; this module enables no transport.
    PublicAutoV1,
    /// Identifies the local-only review-required profile.
    ReviewRequiredV1,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
/// Identifies the platform to which the observables apply.
pub enum ScopePlatform {
    /// Microsoft Windows.
    Windows,
    /// Linux.
    Linux,
    /// Apple macOS.
    Macos,
    /// Any supported platform.
    Any,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
/// Identifies the artifact format to which the observables apply.
pub enum ScopeFormat {
    /// Windows Portable Executable.
    Pe,
    /// Executable and Linkable Format.
    Elf,
    /// Mach-O binary.
    Macho,
    /// Script source or bytecode.
    Script,
    /// Document format.
    Document,
    /// Unknown or unclassified format.
    Unknown,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
/// Platform and artifact-format scope for an observable bundle.
pub struct ObservableScope {
    platform: ScopePlatform,
    format: ScopeFormat,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
/// The closed set of supported observable kinds.
pub enum ObservableKind {
    /// A lowercase hexadecimal SHA-256 file digest.
    FileSha256,
    /// An imported API or symbol name.
    ApiImport,
    /// A lowercase hexadecimal byte pattern with optional wildcards.
    BytePattern,
}

#[derive(Clone, Serialize, PartialEq, Eq)]
/// A validated typed observable contained in a bundle.
pub struct ObservableBundleObservable {
    kind: ObservableKind,
    value: String,
}

#[derive(Clone, Serialize, PartialEq, Eq)]
/// A canonical, structurally validated collection of typed observables.
///
/// Direct deserialization is deliberately unavailable; callers must use
/// [`ObservableBundle::parse_canonical`].
///
/// ```compile_fail
/// use prometheus_threat_hint::ObservableBundle;
///
/// let _: ObservableBundle = serde_json::from_slice(b"{}").unwrap();
/// ```
pub struct ObservableBundle {
    schema_version: u16,
    disclosure_policy: DisclosurePolicy,
    scope: ObservableScope,
    observables: Vec<ObservableBundleObservable>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ObservableScopeWire {
    platform: ScopePlatform,
    format: ScopeFormat,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ObservableBundleObservableWire {
    kind: ObservableKind,
    value: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ObservableBundleWire {
    schema_version: u16,
    disclosure_policy: DisclosurePolicy,
    scope: ObservableScopeWire,
    observables: Vec<ObservableBundleObservableWire>,
}

impl ObservableBundle {
    /// The only supported observable bundle schema version.
    pub const SCHEMA_VERSION: u16 = OBSERVABLE_BUNDLE_SCHEMA_VERSION;

    /// Returns the parsed schema version.
    pub fn schema_version(&self) -> u16 {
        self.schema_version
    }

    /// Returns the bundle disclosure policy.
    pub fn disclosure_policy(&self) -> DisclosurePolicy {
        self.disclosure_policy
    }

    /// Returns the bundle scope.
    pub fn scope(&self) -> &ObservableScope {
        &self.scope
    }

    /// Returns the validated observables in canonical order.
    pub fn observables(&self) -> &[ObservableBundleObservable] {
        &self.observables
    }

    /// Parses bytes and accepts them only when they are valid canonical JSON.
    pub fn parse_canonical(bytes: &[u8]) -> Result<Self, ObservableBundleError> {
        if bytes.is_empty() {
            return Err(ObservableBundleError::InvalidPayload);
        }

        if bytes.len() > MAX_CANONICAL_BYTES {
            return Err(ObservableBundleError::BundleTooLarge);
        }

        let wire: ObservableBundleWire =
            serde_json::from_slice(bytes).map_err(|_| ObservableBundleError::InvalidPayload)?;
        let bundle = ObservableBundle {
            schema_version: wire.schema_version,
            disclosure_policy: wire.disclosure_policy,
            scope: ObservableScope {
                platform: wire.scope.platform,
                format: wire.scope.format,
            },
            observables: wire
                .observables
                .into_iter()
                .map(|observable| ObservableBundleObservable {
                    kind: observable.kind,
                    value: observable.value,
                })
                .collect(),
        };

        bundle.validate()?;
        let canonical = bundle.to_canonical_bytes()?;
        if canonical != bytes {
            return Err(ObservableBundleError::NotCanonical);
        }

        Ok(bundle)
    }

    /// Serializes a validated parsed bundle to canonical JSON bytes.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, ObservableBundleError> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|_| ObservableBundleError::InvalidPayload)?;
        if bytes.is_empty() || bytes.len() > MAX_CANONICAL_BYTES {
            return Err(ObservableBundleError::BundleTooLarge);
        }
        Ok(bytes)
    }

    /// Computes the network- and nonce-bound SHA-256 bundle commitment.
    pub fn commitment(
        &self,
        network_id: impl AsRef<str>,
        report_nonce_hex: impl AsRef<str>,
    ) -> Result<[u8; 32], ObservableBundleError> {
        let network_id = network_id.as_ref();
        let report_nonce_hex = report_nonce_hex.as_ref();

        validate_network_id(network_id)?;
        let report_nonce =
            decode_hex(report_nonce_hex).map_err(|_| ObservableBundleError::InvalidReportNonce)?;
        if report_nonce.len() != NONCE_BYTES {
            return Err(ObservableBundleError::InvalidReportNonce);
        }

        let canonical = self.to_canonical_bytes()?;

        let mut hasher = Sha256::new();
        hasher.update(COMMITMENT_DOMAIN);
        hasher
            .update([u8::try_from(network_id.len())
                .map_err(|_| ObservableBundleError::InvalidNetworkId)?]);
        hasher.update(network_id.as_bytes());
        hasher.update(&report_nonce);
        hasher.update((canonical.len() as u32).to_be_bytes());
        hasher.update(&canonical);

        Ok(hasher.finalize().into())
    }

    /// Constant-time compares an expected commitment with a canonical bundle commitment.
    pub fn commitment_matches(
        expected: &[u8],
        network_id: impl AsRef<str>,
        report_nonce_hex: impl AsRef<str>,
        bundle_wire: &[u8],
    ) -> Result<bool, ObservableBundleError> {
        if expected.len() != 32 {
            return Err(ObservableBundleError::InvalidCommitment);
        }

        let bundle = ObservableBundle::parse_canonical(bundle_wire)?;
        let observed = bundle.commitment(network_id, report_nonce_hex)?;

        Ok(bool::from(expected.ct_eq(&observed)))
    }

    fn validate(&self) -> Result<(), ObservableBundleError> {
        if self.schema_version != Self::SCHEMA_VERSION {
            return Err(ObservableBundleError::InvalidSchemaVersion);
        }

        if self.observables.len() < MIN_OBSERVABLES || self.observables.len() > MAX_OBSERVABLES {
            return Err(ObservableBundleError::InvalidObservables);
        }

        let mut previous: Option<(&str, &str)> = None;
        let mut seen: Vec<(&str, &str)> = Vec::with_capacity(self.observables.len());

        for observable in &self.observables {
            validate_observable(observable.kind, observable.value.as_str())?;

            if self.disclosure_policy == DisclosurePolicy::PublicAutoV1
                && observable.kind == ObservableKind::BytePattern
            {
                return Err(ObservableBundleError::InvalidDisclosurePolicy);
            }

            let current = (observable.kind.as_str(), observable.value.as_str());
            for (seen_kind, seen_value) in &seen {
                if seen_kind == &current.0 && seen_value == &current.1 {
                    return Err(ObservableBundleError::DuplicateObservable);
                }
            }

            if let Some((prev_kind, prev_value)) = previous {
                match current.cmp(&(prev_kind, prev_value)) {
                    Ordering::Less => return Err(ObservableBundleError::UnsortedObservables),
                    Ordering::Equal => return Err(ObservableBundleError::DuplicateObservable),
                    Ordering::Greater => {}
                }
            }

            previous = Some(current);
            seen.push(current);
        }

        Ok(())
    }
}

impl ObservableScope {
    /// Returns the scoped platform.
    pub fn platform(&self) -> ScopePlatform {
        self.platform
    }

    /// Returns the scoped artifact format.
    pub fn format(&self) -> ScopeFormat {
        self.format
    }
}

impl ObservableBundleObservable {
    /// Returns the observable kind.
    pub fn kind(&self) -> ObservableKind {
        self.kind
    }

    /// Returns the validated observable value.
    pub fn value(&self) -> &str {
        &self.value
    }
}

impl ObservableKind {
    /// Returns the canonical wire name for this observable kind.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::FileSha256 => "file_sha256",
            Self::ApiImport => "api_import",
            Self::BytePattern => "byte_pattern",
        }
    }
}

fn validate_observable(kind: ObservableKind, value: &str) -> Result<(), ObservableBundleError> {
    match kind {
        ObservableKind::FileSha256 => validate_file_sha256(value),
        ObservableKind::ApiImport => validate_api_import(value),
        ObservableKind::BytePattern => validate_byte_pattern(value),
    }
}

fn validate_file_sha256(value: &str) -> Result<(), ObservableBundleError> {
    if value.len() != 64 {
        return Err(ObservableBundleError::InvalidObservable);
    }

    let decode = decode_hex(value).map_err(|_| ObservableBundleError::InvalidObservable)?;
    if decode.len() != NONCE_BYTES {
        return Err(ObservableBundleError::InvalidObservable);
    }

    Ok(())
}

fn validate_api_import(value: &str) -> Result<(), ObservableBundleError> {
    let bytes = value.as_bytes();

    if bytes.is_empty() || bytes.len() > MAX_API_IMPORT_LEN {
        return Err(ObservableBundleError::InvalidObservable);
    }

    if !matches!(bytes[0], b'A'..=b'Z' | b'a'..=b'z' | b'_') {
        return Err(ObservableBundleError::InvalidObservable);
    }

    for &byte in bytes {
        if !matches!(
            byte,
            b'A'..=b'Z'
                | b'a'..=b'z'
                | b'0'..=b'9'
                | b'_'
                | b'.'
                | b'@'
                | b'-'
        ) {
            return Err(ObservableBundleError::InvalidObservable);
        }
    }

    Ok(())
}

fn validate_byte_pattern(value: &str) -> Result<(), ObservableBundleError> {
    if !value.is_ascii() {
        return Err(ObservableBundleError::InvalidObservable);
    }

    if value.is_empty() || value.starts_with(' ') || value.ends_with(' ') {
        return Err(ObservableBundleError::InvalidObservable);
    }

    let tokens: Vec<&str> = value.split(' ').collect();
    if !(MIN_BYTE_PATTERN_TOKENS..=MAX_BYTE_PATTERN_TOKENS).contains(&tokens.len()) {
        return Err(ObservableBundleError::InvalidObservable);
    }

    let mut fixed = 0;
    for token in tokens {
        if token.is_empty() {
            return Err(ObservableBundleError::InvalidObservable);
        }

        if token == "??" {
            continue;
        }

        if token.len() != 2 {
            return Err(ObservableBundleError::InvalidObservable);
        }

        if !is_ascii_hex(token.as_bytes()) {
            return Err(ObservableBundleError::InvalidObservable);
        }

        fixed += 1;
    }

    if fixed < 8 {
        return Err(ObservableBundleError::InvalidObservable);
    }

    Ok(())
}

fn validate_network_id(network_id: &str) -> Result<(), ObservableBundleError> {
    if network_id.len() < MIN_NETWORK_LEN || network_id.len() > MAX_NETWORK_LEN {
        return Err(ObservableBundleError::InvalidNetworkId);
    }

    let bytes = network_id.as_bytes();
    if !is_alnum(bytes[0]) || !is_alnum(bytes[bytes.len() - 1]) {
        return Err(ObservableBundleError::InvalidNetworkId);
    }

    if !bytes
        .iter()
        .all(|byte| matches!(byte, b'-' | b'0'..=b'9' | b'a'..=b'z'))
    {
        return Err(ObservableBundleError::InvalidNetworkId);
    }

    Ok(())
}

fn is_alnum(byte: u8) -> bool {
    matches!(byte, b'0'..=b'9' | b'a'..=b'z')
}

fn is_ascii_hex(bytes: &[u8]) -> bool {
    bytes
        .iter()
        .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

fn decode_hex(value: &str) -> Result<Vec<u8>, ()> {
    if !value.len().is_multiple_of(2) {
        return Err(());
    }

    let mut bytes = Vec::with_capacity(value.len() / 2);
    for chunk in value.as_bytes().chunks_exact(2) {
        let hi = decode_hex_nibble(chunk[0]).ok_or(())?;
        let lo = decode_hex_nibble(chunk[1]).ok_or(())?;
        bytes.push((hi << 4) | lo);
    }
    Ok(bytes)
}

fn decode_hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

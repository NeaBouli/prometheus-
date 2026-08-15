//! Development-only restricted rule content acquisition.
//!
//! Defines the [`RuleContentSource`] dependency-injection boundary used by the
//! GH-205 content-sync composition, the single shared canonical Raw-CIDv1 /
//! SHA-256 content-binding implementation reused by `rule_ingest`, and one
//! concrete credential-free local IPFS gateway source.
//!
//! The concrete [`LocalIpfsGatewaySource`] enforces a closed URL policy: only
//! `http` URLs with an explicit loopback IP literal host (IPv4 `127.0.0.0/8`
//! or IPv6 `::1`), an explicit port, and the fixed base path `/ipfs/` are
//! accepted. DNS names, non-loopback hosts, credentials, query strings,
//! fragments, and any other scheme or path are rejected at construction. The
//! request path is built only from a CID that has passed canonical Raw-CIDv1
//! validation immediately before the call.
//!
//! The HTTP client disables redirects, proxies, cookies, and automatic
//! compression, sends a static user agent and `Accept-Encoding: identity`,
//! and bounds both connect and total request time to ten seconds. Responses
//! are rejected on non-success status, any non-identity `Content-Encoding`, a
//! declared `Content-Length` above the GH-190 64 KiB cap, or streamed body
//! overflow past that cap.
//!
//! Every error is a single generic [`RuleFetchError`]: Display/Debug/logging
//! never contain URLs, CIDs, digests, manifests, outpoints, or content bytes.
//!
//! This is a development-only path: every public entry point calls
//! `require_stub_allowed` and therefore rejects beta/mainnet. The `_for_mode`
//! helper can only make tests stricter; it can never weaken the process-wide
//! beta/mainnet env gate.

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use log::info;
use sha2::{Digest, Sha256};
use url::{Host, Url};

use crate::runtime::{require_stub_allowed, require_stub_allowed_for, RuntimeMode};

use super::rule_ingest::MAX_CONTENT_BYTES;

/// Exact byte length of a CIDv1 raw sha2-256/32 binary CID.
pub(crate) const CID_RAW_SHA256_LEN: usize = 36;
/// Header of a CIDv1 raw sha2-256/32 binary CID: version 0x01, codec raw
/// (0x55), multihash sha2-256 (0x12), digest length 32 (0x20).
pub(crate) const CID_RAW_SHA256_HEADER: [u8; 4] = [0x01, 0x55, 0x12, 0x20];

/// Connect timeout for the concrete gateway source.
const FETCH_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Total request timeout for the concrete gateway source.
const FETCH_TOTAL_TIMEOUT: Duration = Duration::from_secs(10);
/// Fixed base path the concrete gateway source is pinned to.
const GATEWAY_BASE_PATH: &str = "/ipfs/";
/// Static user agent; never carries host, target, or runtime detail.
const FETCH_USER_AGENT: &str = concat!("prometheus-client/", env!("CARGO_PKG_VERSION"));

/// The single public content-fetch error.
///
/// Deliberately generic: Display/Debug/logging never contain URLs, CIDs,
/// digests, manifests, outpoints, or content bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuleFetchError;

impl fmt::Display for RuleFetchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("rule content fetch failed")
    }
}

impl std::error::Error for RuleFetchError {}

/// Boxed future returned by [`RuleContentSource`].
pub type RuleContentFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Vec<u8>, RuleFetchError>> + Send + 'a>>;

/// Dependency-injected source for exact rule content bytes.
///
/// `canonical_cid` is validated as a canonical Raw-CIDv1 sha2-256 CID by the
/// caller immediately before this call; implementations that build requests
/// from the CID must revalidate it themselves. Implementations other than
/// [`LocalIpfsGatewaySource`] are caller-trusted test or embedding boundaries
/// and do not constitute evidence that any network fetch ran.
pub trait RuleContentSource {
    /// Fetch the exact content bytes bound to `canonical_cid`.
    fn fetch_rule_content<'a>(&'a self, canonical_cid: &'a str) -> RuleContentFuture<'a>;
}

/// Validate that `cid` is a canonical lowercase base32 CIDv1 with the raw
/// codec and a sha2-256/32 multihash, returning the 32-byte digest.
///
/// This is the single canonical-CID validation shared by `rule_ingest`,
/// `rule_sync`, and the concrete source below. It never inspects content.
pub(crate) fn validate_canonical_raw_cid(cid: &str) -> Result<[u8; 32], RuleFetchError> {
    // A canonical base32-lower encoding of exactly 36 bytes is exactly 59
    // ASCII characters including the multibase prefix. Bound before decode so
    // attacker-controlled metadata cannot force an unbounded allocation.
    if cid.len() != 59 || !cid.is_ascii() {
        return Err(RuleFetchError);
    }
    let (base, bytes) = multibase::decode(cid).map_err(|_| RuleFetchError)?;
    if base != multibase::Base::Base32Lower {
        return Err(RuleFetchError);
    }
    // Re-encode to reject non-canonical forms.
    if multibase::encode(base, &bytes) != cid {
        return Err(RuleFetchError);
    }
    if bytes.len() != CID_RAW_SHA256_LEN || bytes[..4] != CID_RAW_SHA256_HEADER {
        return Err(RuleFetchError);
    }
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&bytes[4..CID_RAW_SHA256_LEN]);
    Ok(digest)
}

/// Verify that `cid` is the canonical lowercase base32 CIDv1 raw sha2-256
/// binding of the exact `content` bytes.
///
/// This is the single CID/content binding implementation; `rule_ingest`
/// delegates to it so GH-190 and GH-205 can never drift apart.
pub(crate) fn verify_raw_cid_content_binding(
    cid: &str,
    content: &[u8],
) -> Result<(), RuleFetchError> {
    let expected = validate_canonical_raw_cid(cid)?;
    if Sha256::digest(content)[..] != expected {
        return Err(RuleFetchError);
    }
    Ok(())
}

/// Concrete development-only content source for a local IPFS gateway over
/// plain HTTP on an explicit loopback IP and port.
///
/// Construction and every fetch are development-only and reject beta/mainnet
/// via `require_stub_allowed`.
pub struct LocalIpfsGatewaySource {
    client: reqwest::Client,
    /// Validated base URL; scheme http, loopback IP host, explicit port, and
    /// path exactly `/ipfs/`.
    base: Url,
}

impl fmt::Debug for LocalIpfsGatewaySource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Redacted: the configured gateway URL never appears in diagnostics.
        f.debug_struct("LocalIpfsGatewaySource")
            .finish_non_exhaustive()
    }
}

impl LocalIpfsGatewaySource {
    /// Construct a source for one explicit loopback HTTP gateway base URL.
    ///
    /// `gateway_url` must be an `http` URL with an empty authority userinfo,
    /// an IPv4 or IPv6 loopback literal host, an explicit port, no query or
    /// fragment, and path exactly `/ipfs/`. Everything else fails closed.
    ///
    /// Development-only: rejects beta/mainnet via `require_stub_allowed`.
    pub fn new(gateway_url: &str) -> Result<Self, RuleFetchError> {
        require_stub_allowed("rule content fetch").map_err(|_| RuleFetchError)?;
        Self::build(gateway_url)
    }

    /// Construct under an explicit runtime mode; identical policy to
    /// [`LocalIpfsGatewaySource::new`]. The explicit mode can only be
    /// stricter; it never weakens the process-wide env gate.
    pub fn new_for_mode(mode: RuntimeMode, gateway_url: &str) -> Result<Self, RuleFetchError> {
        require_stub_allowed("rule content fetch").map_err(|_| RuleFetchError)?;
        require_stub_allowed_for(mode, "rule content fetch").map_err(|_| RuleFetchError)?;
        Self::build(gateway_url)
    }

    /// Validate the closed URL policy and build the hardened client.
    fn build(gateway_url: &str) -> Result<Self, RuleFetchError> {
        Self::build_with_timeouts(gateway_url, FETCH_CONNECT_TIMEOUT, FETCH_TOTAL_TIMEOUT)
    }

    /// Internal constructor with injectable timeouts for deterministic tests.
    /// Public constructors always use the fixed bounds above.
    fn build_with_timeouts(
        gateway_url: &str,
        connect_timeout: Duration,
        total_timeout: Duration,
    ) -> Result<Self, RuleFetchError> {
        let base = Url::parse(gateway_url).map_err(|_| RuleFetchError)?;
        if base.scheme() != "http" {
            return Err(RuleFetchError);
        }
        if !base.username().is_empty() || base.password().is_some() {
            return Err(RuleFetchError);
        }
        let loopback = match base.host() {
            Some(Host::Ipv4(ip)) => ip.is_loopback(),
            Some(Host::Ipv6(ip)) => ip.is_loopback(),
            // DNS names and everything else fail closed.
            _ => false,
        };
        if !loopback {
            return Err(RuleFetchError);
        }
        // An explicit port is required; the URL parser has already range-checked it.
        if base.port().is_none() {
            return Err(RuleFetchError);
        }
        if base.query().is_some() || base.fragment().is_some() {
            return Err(RuleFetchError);
        }
        if base.path() != GATEWAY_BASE_PATH {
            return Err(RuleFetchError);
        }

        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::ACCEPT_ENCODING,
            reqwest::header::HeaderValue::from_static("identity"),
        );
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            // rusty-kaspa enables reqwest system-proxy support in this graph;
            // keep this explicit so a local gateway can never leave loopback.
            .no_proxy()
            .connect_timeout(connect_timeout)
            .timeout(total_timeout)
            .user_agent(FETCH_USER_AGENT)
            .default_headers(headers)
            .build()
            .map_err(|_| RuleFetchError)?;

        Ok(Self { client, base })
    }
}

impl RuleContentSource for LocalIpfsGatewaySource {
    fn fetch_rule_content<'a>(&'a self, canonical_cid: &'a str) -> RuleContentFuture<'a> {
        Box::pin(async move {
            require_stub_allowed("rule content fetch").map_err(|_| RuleFetchError)?;
            // The request path is built only from a CID that has just passed
            // canonical Raw-CIDv1 validation; a validated canonical CID is a
            // plain lowercase base32 segment and cannot alter the URL shape.
            validate_canonical_raw_cid(canonical_cid)?;
            let url = self.base.join(canonical_cid).map_err(|_| RuleFetchError)?;

            let mut response = self
                .client
                .get(url)
                .send()
                .await
                .map_err(|_| RuleFetchError)?;

            if !response.status().is_success() {
                return Err(RuleFetchError);
            }
            for encoding in response
                .headers()
                .get_all(reqwest::header::CONTENT_ENCODING)
                .iter()
            {
                let identity = encoding
                    .to_str()
                    .map(|value| value.eq_ignore_ascii_case("identity"))
                    .unwrap_or(false);
                if !identity {
                    return Err(RuleFetchError);
                }
            }
            if let Some(length) = response.content_length() {
                if length > MAX_CONTENT_BYTES as u64 {
                    return Err(RuleFetchError);
                }
            }

            let mut body = Vec::new();
            while let Some(chunk) = response.chunk().await.map_err(|_| RuleFetchError)? {
                let next = body.len().checked_add(chunk.len()).ok_or(RuleFetchError)?;
                if next > MAX_CONTENT_BYTES {
                    return Err(RuleFetchError);
                }
                body.extend_from_slice(&chunk);
            }
            info!("Fetched {} rule content bytes", body.len());
            Ok(body)
        })
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    use super::*;
    use crate::security::scanner::compute_sha256;

    fn cid_for(content: &[u8]) -> String {
        let digest = compute_sha256(content);
        let mut bytes = Vec::with_capacity(CID_RAW_SHA256_LEN);
        bytes.extend_from_slice(&CID_RAW_SHA256_HEADER);
        bytes.extend_from_slice(&digest);
        multibase::encode(multibase::Base::Base32Lower, &bytes)
    }

    #[test]
    fn test_validate_canonical_raw_cid_accepts_and_rejects() {
        let content = b"payload";
        assert!(validate_canonical_raw_cid(&cid_for(content)).is_ok());
        // Wrong length, uppercase, and dag-pb codec all fail closed.
        assert!(validate_canonical_raw_cid("bafkrei").is_err());
        assert!(validate_canonical_raw_cid(&cid_for(content).to_uppercase()).is_err());
        let digest = compute_sha256(content);
        let mut bytes = vec![0x01, 0x70, 0x12, 0x20];
        bytes.extend_from_slice(&digest);
        let dag_pb = multibase::encode(multibase::Base::Base32Lower, &bytes);
        assert!(validate_canonical_raw_cid(&dag_pb).is_err());
    }

    #[tokio::test]
    async fn test_fetch_times_out_when_gateway_never_responds() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0u8; 1024];
            let _ = stream.read(&mut request);
            thread::sleep(Duration::from_millis(200));
        });
        let source = LocalIpfsGatewaySource::build_with_timeouts(
            &format!("http://127.0.0.1:{port}/ipfs/"),
            Duration::from_millis(50),
            Duration::from_millis(50),
        )
        .unwrap();

        assert!(source
            .fetch_rule_content(&cid_for(b"content"))
            .await
            .is_err());
        server.join().unwrap();
    }

    #[tokio::test]
    async fn test_fetch_times_out_during_slow_response_body() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0u8; 1024];
            let _ = stream.read(&mut request);
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nx")
                .unwrap();
            stream.flush().unwrap();
            thread::sleep(Duration::from_millis(200));
            let _ = stream.write_all(b"content");
        });
        let source = LocalIpfsGatewaySource::build_with_timeouts(
            &format!("http://127.0.0.1:{port}/ipfs/"),
            Duration::from_millis(50),
            Duration::from_millis(50),
        )
        .unwrap();

        assert!(source
            .fetch_rule_content(&cid_for(b"content"))
            .await
            .is_err());
        server.join().unwrap();
    }

    #[test]
    fn test_verify_binding_matches_exact_bytes_only() {
        let content = b"exact bytes";
        assert!(verify_raw_cid_content_binding(&cid_for(content), content).is_ok());
        assert!(verify_raw_cid_content_binding(&cid_for(content), b"other").is_err());
    }

    #[test]
    fn test_error_is_generic() {
        let err = RuleFetchError;
        assert_eq!(err.to_string(), "rule content fetch failed");
        assert_eq!(format!("{err:?}"), "RuleFetchError");
    }
}

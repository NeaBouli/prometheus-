//! Integration tests for the GH-205 restricted rule content fetch boundary.
//!
//! All HTTP behavior is tested deterministically against an owner-local
//! ephemeral TCP server bound to 127.0.0.1:0. No test touches an external
//! network, and no test prints URLs, CIDs, digests, or content bytes.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::mpsc::{self, Receiver};
use std::thread;

use prometheus_client::blockchain::rule_fetch::{LocalIpfsGatewaySource, RuleContentSource};
use prometheus_client::runtime::RuntimeMode;
use prometheus_client::security::scanner::compute_sha256;

/// Canonical raw CIDv1 sha2-256 CID for exact content bytes.
fn cid_for(content: &[u8]) -> String {
    let digest = compute_sha256(content);
    let mut bytes = vec![0x01u8, 0x55, 0x12, 0x20];
    bytes.extend_from_slice(&digest);
    multibase::encode(multibase::Base::Base32Lower, &bytes)
}

/// Build one raw HTTP/1.1 response with `Connection: close`.
fn http_response(status: &str, extra_headers: &[String], body: &[u8]) -> Vec<u8> {
    let mut head = format!("HTTP/1.1 {status}\r\nConnection: close\r\n");
    for header in extra_headers {
        head.push_str(header);
        head.push_str("\r\n");
    }
    head.push_str("\r\n");
    let mut response = head.into_bytes();
    response.extend_from_slice(body);
    response
}

/// Serve exactly one connection on an ephemeral loopback port: record the
/// request head, write the canned response, and close.
fn serve_once(response: Vec<u8>) -> (u16, Receiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") && head.len() <= 8192 {
            if stream.read(&mut byte).unwrap_or(0) == 0 {
                break;
            }
            head.push(byte[0]);
        }
        let _ = tx.send(String::from_utf8_lossy(&head).to_string());
        let _ = stream.write_all(&response);
        let _ = stream.flush();
    });
    (port, rx)
}

fn source_for_port(port: u16) -> LocalIpfsGatewaySource {
    LocalIpfsGatewaySource::new(&format!("http://127.0.0.1:{port}/ipfs/")).unwrap()
}

#[test]
fn url_policy_accepts_only_explicit_loopback_ipfs_base() {
    assert!(LocalIpfsGatewaySource::new("http://127.0.0.1:8080/ipfs/").is_ok());
    assert!(LocalIpfsGatewaySource::new("http://127.1.2.3:1/ipfs/").is_ok());
    assert!(LocalIpfsGatewaySource::new("http://[::1]:8080/ipfs/").is_ok());

    let rejected = [
        "http://localhost:8080/ipfs/",           // DNS name
        "http://192.168.1.1:8080/ipfs/",         // non-loopback
        "http://10.0.0.1:8080/ipfs/",            // non-loopback
        "http://[fe80::1]:8080/ipfs/",           // non-loopback literal
        "http://user:pass@127.0.0.1:8080/ipfs/", // credentials
        "http://user@127.0.0.1:8080/ipfs/",      // credentials
        "http://127.0.0.1:8080/ipfs/?x=1",       // query
        "http://127.0.0.1:8080/ipfs/#frag",      // fragment
        "http://127.0.0.1/ipfs/",                // missing explicit port
        "https://127.0.0.1:8080/ipfs/",          // unsupported scheme
        "http://127.0.0.1:8080/",                // unsupported path
        "http://127.0.0.1:8080/ipfs",            // unsupported path
        "http://127.0.0.1:8080/api/ipfs/",       // unsupported path
        "http://127.0.0.1:99999/ipfs/",          // unparseable port
        "not a url",
    ];
    for url in rejected {
        assert!(
            LocalIpfsGatewaySource::new(url).is_err(),
            "accepted {url:?}"
        );
    }
}

#[test]
fn beta_and_mainnet_modes_fail_closed() {
    for mode in [RuntimeMode::Beta, RuntimeMode::Mainnet] {
        assert!(LocalIpfsGatewaySource::new_for_mode(mode, "http://127.0.0.1:8080/ipfs/").is_err());
    }
    assert!(LocalIpfsGatewaySource::new_for_mode(
        RuntimeMode::Development,
        "http://127.0.0.1:8080/ipfs/"
    )
    .is_ok());
}

#[tokio::test]
async fn fetch_returns_exact_bytes_and_requests_only_the_cid_path() {
    let content = b"rule R {\nstrings:\n$a = \"ABC\"\ncondition:\nany of them\n}\n";
    let cid = cid_for(content);
    let response = http_response(
        "200 OK",
        &[format!("Content-Length: {}", content.len())],
        content,
    );
    let (port, rx) = serve_once(response);
    let source = source_for_port(port);

    let fetched = source.fetch_rule_content(&cid).await.unwrap();
    assert_eq!(fetched, content);

    let head = rx.recv().unwrap();
    let request_line = head.lines().next().unwrap();
    assert_eq!(request_line, format!("GET /ipfs/{cid} HTTP/1.1"));
    let lowered = head.to_lowercase();
    assert!(lowered.contains("accept-encoding: identity"));
    assert!(!lowered.contains("authorization"));
    assert!(!lowered.contains("cookie"));
}

#[tokio::test]
async fn fetch_accepts_body_at_exact_cap() {
    let content = vec![b'x'; 64 * 1024];
    let cid = cid_for(&content);
    let response = http_response(
        "200 OK",
        &[format!("Content-Length: {}", content.len())],
        &content,
    );
    let (port, _rx) = serve_once(response);
    let source = source_for_port(port);
    assert_eq!(source.fetch_rule_content(&cid).await.unwrap(), content);
}

#[tokio::test]
async fn fetch_rejects_non_success_and_redirect_status() {
    for status in ["404 Not Found", "302 Found", "500 Internal Server Error"] {
        let mut headers = Vec::new();
        if status.starts_with("302") {
            headers.push("Location: http://127.0.0.1:1/ipfs/other".to_string());
        }
        let (port, _rx) = serve_once(http_response(status, &headers, b"nope"));
        let source = source_for_port(port);
        let cid = cid_for(b"content");
        assert!(source.fetch_rule_content(&cid).await.is_err(), "{status}");
    }
}

#[tokio::test]
async fn fetch_rejects_non_identity_content_encoding() {
    let content = b"payload";
    let cid = cid_for(content);
    let response = http_response(
        "200 OK",
        &[
            "Content-Encoding: gzip".to_string(),
            format!("Content-Length: {}", content.len()),
        ],
        content,
    );
    let (port, _rx) = serve_once(response);
    let source = source_for_port(port);
    assert!(source.fetch_rule_content(&cid).await.is_err());
}

#[tokio::test]
async fn fetch_rejects_declared_length_over_cap_without_reading_body() {
    // Declared length above the 64 KiB cap; the server closes without a body.
    let response = http_response("200 OK", &["Content-Length: 65537".to_string()], b"");
    let (port, _rx) = serve_once(response);
    let source = source_for_port(port);
    let cid = cid_for(b"content");
    assert!(source.fetch_rule_content(&cid).await.is_err());
}

#[tokio::test]
async fn fetch_rejects_streamed_body_overflow() {
    // No Content-Length: close-delimited body one byte over the cap.
    let body = vec![b'y'; 64 * 1024 + 1];
    let response = http_response("200 OK", &[], &body);
    let (port, _rx) = serve_once(response);
    let source = source_for_port(port);
    let cid = cid_for(b"content");
    assert!(source.fetch_rule_content(&cid).await.is_err());
}

#[tokio::test]
async fn fetch_rejects_noncanonical_cid_before_any_connection() {
    // Nonblocking listener: prove the source never opened a connection.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    let source = source_for_port(port);

    let uppercase = cid_for(b"content").to_uppercase();
    assert!(source.fetch_rule_content(&uppercase).await.is_err());
    assert!(source.fetch_rule_content("bafkrei").await.is_err());
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[test]
fn source_debug_is_redacted() {
    let source = LocalIpfsGatewaySource::new("http://127.0.0.1:8080/ipfs/").unwrap();
    let debugged = format!("{source:?}");
    assert!(!debugged.contains("127.0.0.1"));
    assert!(!debugged.contains("8080"));
    assert!(!debugged.contains("ipfs"));
}

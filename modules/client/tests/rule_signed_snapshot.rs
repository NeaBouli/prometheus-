//! Deterministic GH-211 signed snapshot provider and coordinator tests.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use kaspa_addresses::Address;
use prometheus_client::blockchain::rule_checkpoint::{
    RuleCheckpointError, RuleCheckpointLock, RuleCheckpointStore,
};
use prometheus_client::blockchain::rule_coordinator::{
    RuleCoordinator, RuleCoordinatorConfig, RuleSnapshotProvider,
};
use prometheus_client::blockchain::rule_fetch::{RuleContentFuture, RuleContentSource};
use prometheus_client::blockchain::rule_ingest::MAX_RULES_PER_SNAPSHOT;
use prometheus_client::blockchain::rule_observation::{
    RuleObservationFuture, RuleObservationSource, MAX_MANIFEST_JSON_BYTES,
};
use prometheus_client::blockchain::rule_signed_snapshot::{
    RuleSnapshotEnvelopeError, RuleSnapshotTimeSource, SignedRuleSnapshotProvider,
    MAX_ADDRESS_BYTES, MAX_ENVELOPE_BYTES, MAX_VALIDITY_WINDOW_SECONDS,
};
use prometheus_client::blockchain::rule_state::MAX_STATE_JSON_BYTES;
use prometheus_client::runtime::RuntimeMode;
use prometheus_client::security::scanner::{CompiledRule, YaraScanner};
use secp256k1::{Keypair, Message, Secp256k1, SecretKey};
use serde::Serialize;
use sha2::{Digest, Sha256};
use tokio::sync::watch;
use tokio::time::sleep;

const NOW: u64 = 1_700_000_000;
const SIGNING_DOMAIN: &[u8] = b"prometheus.rule-snapshot.envelope.v1\0";

#[derive(Clone, Serialize)]
struct TestEntry {
    expected_manifest_sha256: String,
    manifest_json: String,
    constructor_json: String,
    address: String,
}

#[derive(Clone, Serialize)]
struct TestPayload {
    schema_version: u64,
    kind: String,
    network_id: String,
    sequence: u64,
    valid_from: u64,
    valid_until: u64,
    empty_snapshot_order: Option<u64>,
    entries: Vec<TestEntry>,
}

fn empty_payload(order: u64) -> TestPayload {
    TestPayload {
        schema_version: 1,
        kind: "prometheus.rule-snapshot.envelope.v1".to_string(),
        network_id: "testnet-10".to_string(),
        sequence: 7,
        valid_from: NOW - 10,
        valid_until: NOW + 10,
        empty_snapshot_order: Some(order),
        entries: Vec::new(),
    }
}

fn test_entry() -> TestEntry {
    TestEntry {
        expected_manifest_sha256: "a".repeat(64),
        manifest_json: "{}".to_string(),
        constructor_json: "{}".to_string(),
        address: "kaspatest:qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"
            .to_string(),
    }
}

fn secret(byte: u8) -> SecretKey {
    SecretKey::from_slice(&[byte; 32]).unwrap()
}

fn public_key(secret: &SecretKey) -> [u8; 32] {
    let secp = Secp256k1::new();
    Keypair::from_secret_key(&secp, secret)
        .x_only_public_key()
        .0
        .serialize()
}

fn domain_digest(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(SIGNING_DOMAIN);
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    hasher.finalize().into()
}

fn signed_wire(payload: &TestPayload, secret: &SecretKey) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(payload).unwrap();
    let message = Message::from_digest(domain_digest(&bytes));
    let secp = Secp256k1::new();
    let keypair = Keypair::from_secret_key(&secp, secret);
    let signature = secp.sign_schnorr_no_aux_rand(&message, &keypair);
    assert_eq!(bytes.pop(), Some(b'}'));
    bytes.extend_from_slice(
        format!(",\"signature\":\"{}\"}}", hex::encode(signature.as_ref())).as_bytes(),
    );
    bytes
}

struct TestClock(AtomicU64);

impl TestClock {
    fn new(now: u64) -> Self {
        Self(AtomicU64::new(now))
    }

    fn set(&self, now: u64) {
        self.0.store(now, Ordering::SeqCst);
    }
}

impl RuleSnapshotTimeSource for TestClock {
    fn current_unix_seconds(&self) -> Result<u64, RuleSnapshotEnvelopeError> {
        Ok(self.0.load(Ordering::SeqCst))
    }
}

struct FailingClock;

impl RuleSnapshotTimeSource for FailingClock {
    fn current_unix_seconds(&self) -> Result<u64, RuleSnapshotEnvelopeError> {
        Err(RuleSnapshotEnvelopeError)
    }
}

fn provider(
    payload: &TestPayload,
    key: &SecretKey,
    minimum_sequence: u64,
    clock: Arc<TestClock>,
) -> Result<SignedRuleSnapshotProvider, RuleSnapshotEnvelopeError> {
    SignedRuleSnapshotProvider::new(
        &signed_wire(payload, key),
        &public_key(key),
        minimum_sequence,
        clock,
    )
}

#[tokio::test]
async fn valid_envelopes_fetch_exact_requests_and_redact_debug() {
    let key = secret(0x42);
    let clock = Arc::new(TestClock::new(NOW));
    let empty = provider(&empty_payload(9), &key, 7, clock.clone()).unwrap();
    let request = empty.fetch_snapshot().await.unwrap();
    assert!(request.entries.is_empty());
    assert_eq!(request.empty_snapshot_order, Some(9));
    assert!(!format!("{empty:?}").contains("kaspatest"));

    let mut payload = empty_payload(9);
    payload.entries = vec![test_entry()];
    payload.empty_snapshot_order = None;
    let non_empty = provider(&payload, &key, 7, clock).unwrap();
    let request = non_empty.fetch_snapshot().await.unwrap();
    assert_eq!(request.entries.len(), 1);
    assert_eq!(request.entries[0].expected_manifest_sha256, "a".repeat(64));
    assert_eq!(request.empty_snapshot_order, None);
}

#[tokio::test]
async fn every_fetch_rechecks_trusted_time() {
    let key = secret(0x42);
    let clock = Arc::new(TestClock::new(NOW));
    let provider = provider(&empty_payload(9), &key, 7, clock.clone()).unwrap();
    assert!(provider.fetch_snapshot().await.is_ok());
    clock.set(NOW + 11);
    assert!(provider.fetch_snapshot().await.is_err());
}

#[test]
fn policy_and_owner_sequence_floor_fail_closed() {
    let key = secret(0x42);
    let clock = Arc::new(TestClock::new(NOW));
    let cases = [
        {
            let mut p = empty_payload(9);
            p.schema_version = 2;
            p
        },
        {
            let mut p = empty_payload(9);
            p.kind = "other".to_string();
            p
        },
        {
            let mut p = empty_payload(9);
            p.network_id = "mainnet".to_string();
            p
        },
        {
            let mut p = empty_payload(9);
            p.sequence = 0;
            p
        },
        {
            let mut p = empty_payload(9);
            p.valid_from = 0;
            p
        },
        {
            let mut p = empty_payload(9);
            p.valid_until = p.valid_from;
            p
        },
        {
            let mut p = empty_payload(9);
            p.valid_until = p.valid_from + MAX_VALIDITY_WINDOW_SECONDS + 1;
            p
        },
        {
            let mut p = empty_payload(9);
            p.empty_snapshot_order = None;
            p
        },
        {
            let mut p = empty_payload(9);
            p.empty_snapshot_order = Some(0);
            p
        },
    ];
    for payload in cases {
        assert!(provider(&payload, &key, 1, clock.clone()).is_err());
    }
    assert!(provider(&empty_payload(9), &key, 0, clock.clone()).is_err());
    assert!(provider(&empty_payload(9), &key, 8, clock).is_err());
}

#[test]
fn untrusted_clock_failure_is_redacted_and_rejected() {
    let key = secret(0x42);
    let result = SignedRuleSnapshotProvider::new(
        &signed_wire(&empty_payload(9), &key),
        &public_key(&key),
        7,
        Arc::new(FailingClock),
    );
    assert_eq!(result.unwrap_err(), RuleSnapshotEnvelopeError);
}

#[test]
fn signature_canonicality_and_key_tamper_fail_closed() {
    let key = secret(0x42);
    let attacker = secret(0x24);
    let clock = Arc::new(TestClock::new(NOW));
    let payload = empty_payload(9);
    let wire = signed_wire(&payload, &key);

    assert!(SignedRuleSnapshotProvider::new(
        &signed_wire(&payload, &attacker),
        &public_key(&key),
        7,
        clock.clone(),
    )
    .is_err());
    assert!(SignedRuleSnapshotProvider::new(&wire, &[0xff; 32], 7, clock.clone(),).is_err());

    let mut tampered = wire.clone();
    let position = tampered
        .windows(12)
        .position(|w| w == b"\"sequence\":7")
        .unwrap();
    tampered[position + 11] = b'8';
    assert!(
        SignedRuleSnapshotProvider::new(&tampered, &public_key(&key), 7, clock.clone(),).is_err()
    );

    let pretty =
        serde_json::to_vec_pretty(&serde_json::from_slice::<serde_json::Value>(&wire).unwrap())
            .unwrap();
    assert!(SignedRuleSnapshotProvider::new(&pretty, &public_key(&key), 7, clock,).is_err());
}

#[test]
fn strict_schema_and_signature_shapes_are_required() {
    let key = secret(0x42);
    let clock = Arc::new(TestClock::new(NOW));
    let wire = signed_wire(&empty_payload(9), &key);
    let text = String::from_utf8(wire.clone()).unwrap();

    let missing_order = text.replace("\"empty_snapshot_order\":9,", "");
    let unknown = text.replacen("{", "{\"unknown\":1,", 1);
    let duplicate_sequence = text.replacen("\"sequence\":7,", "\"sequence\":7,\"sequence\":7,", 1);
    let uppercase_signature = {
        let mut value: serde_json::Value = serde_json::from_slice(&wire).unwrap();
        value["signature"] = serde_json::Value::String("A".repeat(128));
        serde_json::to_vec(&value).unwrap()
    };
    for candidate in [
        missing_order.into_bytes(),
        unknown.into_bytes(),
        duplicate_sequence.into_bytes(),
        uppercase_signature,
        vec![b'x'; MAX_ENVELOPE_BYTES + 1],
    ] {
        assert!(
            SignedRuleSnapshotProvider::new(&candidate, &public_key(&key), 7, clock.clone(),)
                .is_err()
        );
    }
}

#[test]
fn exact_time_boundaries_are_enforced() {
    let key = secret(0x42);
    let mut payload = empty_payload(9);
    payload.valid_from = NOW;
    payload.valid_until = NOW + MAX_VALIDITY_WINDOW_SECONDS;
    assert!(provider(
        &payload,
        &key,
        7,
        Arc::new(TestClock::new(payload.valid_from)),
    )
    .is_ok());
    assert!(provider(
        &payload,
        &key,
        7,
        Arc::new(TestClock::new(payload.valid_until)),
    )
    .is_ok());
    assert!(provider(
        &payload,
        &key,
        7,
        Arc::new(TestClock::new(payload.valid_from - 1)),
    )
    .is_err());
    assert!(provider(
        &payload,
        &key,
        7,
        Arc::new(TestClock::new(payload.valid_until + 1)),
    )
    .is_err());
}

#[test]
fn limits_empty_semantics_and_modes_are_enforced() {
    let key = secret(0x42);
    let clock = Arc::new(TestClock::new(NOW));
    assert!(SignedRuleSnapshotProvider::new(
        &vec![b'x'; MAX_ENVELOPE_BYTES + 1],
        &public_key(&key),
        7,
        clock.clone(),
    )
    .is_err());

    let mut payload = empty_payload(9);
    payload.entries = vec![test_entry()];
    payload.entries[0].address = "x".repeat(MAX_ADDRESS_BYTES + 1);
    payload.empty_snapshot_order = None;
    assert!(provider(&payload, &key, 7, clock.clone()).is_err());

    let invalid_entries = [
        {
            let mut entry = test_entry();
            entry.expected_manifest_sha256 = "A".repeat(64);
            entry
        },
        {
            let mut entry = test_entry();
            entry.manifest_json = "x".repeat(MAX_MANIFEST_JSON_BYTES + 1);
            entry
        },
        {
            let mut entry = test_entry();
            entry.constructor_json = "x".repeat(MAX_STATE_JSON_BYTES + 1);
            entry
        },
    ];
    for entry in invalid_entries {
        let mut payload = empty_payload(9);
        payload.entries = vec![entry];
        payload.empty_snapshot_order = None;
        assert!(provider(&payload, &key, 7, clock.clone()).is_err());
    }

    let mut too_many = empty_payload(9);
    too_many.entries = vec![test_entry(); MAX_RULES_PER_SNAPSHOT + 1];
    too_many.empty_snapshot_order = None;
    assert!(provider(&too_many, &key, 7, clock.clone()).is_err());

    let wire = signed_wire(&empty_payload(9), &key);
    for mode in [RuntimeMode::Beta, RuntimeMode::Mainnet] {
        assert!(SignedRuleSnapshotProvider::new_for_mode(
            mode,
            &wire,
            &public_key(&key),
            7,
            clock.clone(),
        )
        .is_err());
    }
}

#[derive(Default)]
struct MemoryStore {
    state: Mutex<Option<Vec<u8>>>,
    replacements: AtomicU64,
}

struct MemoryLock<'a>(&'a MemoryStore);

impl RuleCheckpointStore for MemoryStore {
    fn lock(&self) -> Result<Box<dyn RuleCheckpointLock + '_>, RuleCheckpointError> {
        Ok(Box::new(MemoryLock(self)))
    }
}

impl RuleCheckpointLock for MemoryLock<'_> {
    fn read(&self) -> Result<Option<Vec<u8>>, RuleCheckpointError> {
        Ok(self.0.state.lock().unwrap().clone())
    }

    fn replace(&self, bytes: &[u8]) -> Result<(), RuleCheckpointError> {
        *self.0.state.lock().unwrap() = Some(bytes.to_vec());
        self.0.replacements.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

impl MemoryStore {
    fn seed(&self, order: u64) {
        let bytes = format!(
            "{{\"schema_version\":1,\"kind\":\"prometheus.rule-storage.checkpoint.v1\",\"network_id\":\"testnet-10\",\"order\":{order},\"snapshot_digest\":\"{}\"}}",
            "a".repeat(64)
        )
        .into_bytes();
        *self.state.lock().unwrap() = Some(bytes);
    }

    fn bytes(&self) -> Option<Vec<u8>> {
        self.state.lock().unwrap().clone()
    }
}

struct NeverContent;

impl RuleContentSource for NeverContent {
    fn fetch_rule_content<'a>(&'a self, _cid: &'a str) -> RuleContentFuture<'a> {
        Box::pin(async { unreachable!("empty snapshots never fetch content") })
    }
}

struct NeverObservation;

impl RuleObservationSource for NeverObservation {
    fn observe_address<'a>(&'a self, _address: &'a Address) -> RuleObservationFuture<'a> {
        Box::pin(async { unreachable!("empty snapshots never observe addresses") })
    }
}

fn old_scanner() -> YaraScanner {
    let mut scanner = YaraScanner::new().unwrap();
    scanner
        .add_rule(CompiledRule {
            name: "old_rule".to_string(),
            patterns: vec![b"old".to_vec()],
            required_matches: 1,
        })
        .unwrap();
    scanner
}

#[tokio::test(start_paused = true)]
async fn signed_provider_composes_with_coordinator_and_checkpoint() {
    let key = secret(0x42);
    let provider = provider(&empty_payload(9), &key, 7, Arc::new(TestClock::new(NOW))).unwrap();
    let coordinator = RuleCoordinator::new(
        RuleCoordinatorConfig::new(
            Duration::from_secs(1),
            Duration::from_millis(100),
            Duration::from_millis(200),
            Duration::from_millis(100),
        )
        .unwrap(),
    )
    .unwrap();
    let store = MemoryStore::default();
    let mut scanner = old_scanner();
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
    let driver = async {
        while coordinator.status().successes == 0 {
            sleep(Duration::from_millis(1)).await;
        }
        let _ = shutdown_tx.send(true);
    };
    let run = coordinator.run(
        &mut shutdown_rx,
        &store,
        &mut scanner,
        &NeverContent,
        &NeverObservation,
        &provider,
    );
    let (result, ()) = tokio::join!(run, driver);
    result.unwrap();
    assert_eq!(scanner.rule_count(), 0);
    assert_eq!(store.replacements.load(Ordering::SeqCst), 1);
}

#[tokio::test(start_paused = true)]
async fn signed_rollback_attempt_preserves_checkpoint_and_scanner() {
    let key = secret(0x42);
    let provider = provider(&empty_payload(9), &key, 7, Arc::new(TestClock::new(NOW))).unwrap();
    let coordinator = RuleCoordinator::new(
        RuleCoordinatorConfig::new(
            Duration::from_secs(1),
            Duration::from_millis(100),
            Duration::from_millis(200),
            Duration::from_millis(100),
        )
        .unwrap(),
    )
    .unwrap();
    let store = MemoryStore::default();
    store.seed(10);
    let before = store.bytes();
    let mut scanner = old_scanner();
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
    let driver = async {
        while coordinator.status().failures == 0 {
            sleep(Duration::from_millis(1)).await;
        }
        let _ = shutdown_tx.send(true);
    };
    let run = coordinator.run(
        &mut shutdown_rx,
        &store,
        &mut scanner,
        &NeverContent,
        &NeverObservation,
        &provider,
    );
    let (result, ()) = tokio::join!(run, driver);
    result.unwrap();
    assert_eq!(store.bytes(), before);
    assert_eq!(store.replacements.load(Ordering::SeqCst), 0);
    assert_eq!(scanner.rule_count(), 1);
    assert!(scanner.scan_bytes(b"old").unwrap().is_threat);
}

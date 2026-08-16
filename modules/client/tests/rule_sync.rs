//! Integration tests for the GH-205 complete-snapshot content sync.
//!
//! Composes the GH-203 injected live observation path, GH-197 verification,
//! GH-193 metadata, the GH-205 content source, and GH-190 metadata-native
//! atomic ingest. Both the observation source and the content source are
//! dependency-injected mocks; no network access occurs. No test prints
//! hashes, outpoints, CIDs, rule IDs, or content bytes.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::sync::Mutex;

use kaspa_addresses::{Address, Prefix, Version};
use kaspa_hashes::Hash;
use kaspa_rpc_core::{
    RpcScriptPublicKey, RpcTransactionOutpoint, RpcUtxoEntry, RpcUtxosByAddressesEntry,
};
use kaspa_wrpc_client::prelude::{NetworkId, NetworkType};
use prometheus_client::blockchain::rule_checkpoint::{
    sync_rule_snapshot_durable, sync_rule_snapshot_durable_for_mode, PosixRuleCheckpointStore,
    RuleCheckpointError, RuleCheckpointLock, RuleCheckpointStore,
};
use prometheus_client::blockchain::rule_fetch::{
    RuleContentFuture, RuleContentSource, RuleFetchError,
};
use prometheus_client::blockchain::rule_ingest::{
    ingest_rule_state_snapshot, ingest_rule_state_snapshot_for_mode, RuleMetadataSnapshotEntry,
};
use prometheus_client::blockchain::rule_observation::{
    RuleObservationError, RuleObservationFuture, RuleObservationSnapshot, RuleObservationSource,
    MANIFEST_KIND, OBSERVATION_NETWORK_ID,
};
use prometheus_client::blockchain::rule_state::decode_rule_state;
use prometheus_client::blockchain::rule_sync::{
    sync_rule_snapshot, sync_rule_snapshot_for_mode, RuleSyncEntry,
};
use prometheus_client::runtime::RuntimeMode;
use prometheus_client::security::scanner::{compute_sha256, CompiledRule, YaraScanner};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const COVENANT: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const SCRIPT: &str = "51";
const AMOUNT: u64 = 100_000_000;
const BLOCK_DAA: u64 = 1_000;
const MIN_MATURITY: u64 = 100;
const OBSERVED_DAA: u64 = BLOCK_DAA + MIN_MATURITY;

fn txid(byte: char) -> String {
    byte.to_string().repeat(64)
}

/// The raw byte whose lowercase hex is `byte` repeated twice.
fn hex_byte(byte: char) -> u8 {
    u8::from_str_radix(&byte.to_string().repeat(2), 16).unwrap()
}

/// Valid rule content for the GH-193-derived rule id of `proposal_id`.
fn rule_content(proposal_id: u64, literal: &str) -> Vec<u8> {
    format!("rule PROM-RULE-{proposal_id:04} {{\nstrings:\n$a = \"{literal}\"\ncondition:\nany of them\n}}\n")
        .into_bytes()
}

/// Canonical raw CIDv1 sha2-256 CID string for exact content bytes.
fn cid_string_for(content: &[u8]) -> String {
    let digest = compute_sha256(content);
    let mut bytes = vec![0x01u8, 0x55, 0x12, 0x20];
    bytes.extend_from_slice(&digest);
    multibase::encode(multibase::Base::Base32Lower, &bytes)
}

fn int(value: i64) -> Value {
    json!({"kind": "int", "data": value})
}

fn bytes(values: &[u8]) -> Value {
    let data: Vec<_> = values
        .iter()
        .map(|value| json!({"kind": "byte", "data": value}))
        .collect();
    json!({"kind": "array", "data": data})
}

/// One valid GH-193 accepted-state constructor document whose CID bytes bind
/// the exact `content`.
fn constructor_document(proposal_id: i64, content: &[u8]) -> String {
    let mut cid = vec![0x01, 0x55, 0x12, 0x20];
    cid.extend(compute_sha256(content));
    serde_json::to_string(&json!([
        bytes(&[4; 32]), int(proposal_id + 1), int(proposal_id), bytes(&[5; 32]),
        bytes(&[6; 32]), int(0), bytes(&cid), int(9_000), int(100_000), int(3),
        int(1), int(964_000), int(2), int(3), int(2), int(50_000), int(7_500),
        int(965_000), {"kind": "bool", "data": true}, int(1)
    ]))
    .unwrap()
}

fn sha256_hex(data: &str) -> String {
    hex::encode(Sha256::digest(data.as_bytes()))
}

fn manifest_json(txid: &str, index: u32, constructor_hash: &str) -> String {
    format!(
        "{{\"schema_version\":1,\"kind\":\"{MANIFEST_KIND}\",\"network_id\":\"{OBSERVATION_NETWORK_ID}\",\
\"outpoint\":{{\"transaction_id\":\"{txid}\",\"index\":{index}}},\"covenant_id\":\"{COVENANT}\",\
\"script_public_key\":{{\"version\":0,\"script_hex\":\"{SCRIPT}\"}},\"amount_sompi\":{AMOUNT},\
\"block_daa_score\":{BLOCK_DAA},\"minimum_virtual_daa_maturity\":{MIN_MATURITY},\
\"constructor_json_sha256\":\"{constructor_hash}\"}}"
    )
}

fn test_address(payload: u8) -> Address {
    Address::new(Prefix::Testnet, Version::PubKey, &[payload; 32])
}

/// Canned node snapshot returned by the mock observation source.
struct CannedSnapshot {
    network_id: NetworkId,
    virtual_daa_score: u64,
    utxos: Vec<RpcUtxosByAddressesEntry>,
}

/// One fully valid sync entry plus the matching node observation: an explicit
/// Testnet-10 address, an owner-pinned manifest, a CID-bound constructor, and
/// the exact UTXO the GH-203 adapter converts into the canonical observation.
struct EntryFixture {
    entry: RuleSyncEntry,
    address: Address,
    snapshot: CannedSnapshot,
}

fn entry_fixture(proposal_id: i64, txid_byte: char, index: u32, content: &[u8]) -> EntryFixture {
    let address = test_address(txid_byte as u8);
    let constructor = constructor_document(proposal_id, content);
    let manifest = manifest_json(&txid(txid_byte), index, &sha256_hex(&constructor));
    let utxo = RpcUtxosByAddressesEntry {
        address: Some(address.clone()),
        outpoint: RpcTransactionOutpoint {
            transaction_id: Hash::from_bytes([hex_byte(txid_byte); 32]),
            index,
        },
        utxo_entry: RpcUtxoEntry::new(
            AMOUNT,
            RpcScriptPublicKey::from_vec(0, vec![0x51]),
            BLOCK_DAA,
            false,
            Some(Hash::from_bytes([0x22; 32])),
        ),
    };
    EntryFixture {
        entry: RuleSyncEntry {
            expected_manifest_sha256: sha256_hex(&manifest),
            manifest_json: manifest,
            constructor_json: constructor,
            address: address.to_string(),
        },
        address,
        snapshot: CannedSnapshot {
            network_id: NetworkId::with_suffix(NetworkType::Testnet, 10),
            virtual_daa_score: OBSERVED_DAA,
            utxos: vec![utxo],
        },
    }
}

fn entries_of(fixtures: &[&EntryFixture]) -> Vec<RuleSyncEntry> {
    fixtures
        .iter()
        .map(|fixture| RuleSyncEntry {
            expected_manifest_sha256: fixture.entry.expected_manifest_sha256.clone(),
            manifest_json: fixture.entry.manifest_json.clone(),
            constructor_json: fixture.entry.constructor_json.clone(),
            address: fixture.entry.address.clone(),
        })
        .collect()
}

/// Injected observation source with per-address canned snapshots, forced
/// failures, and a call log. Caller-trusted test boundary; no network access.
#[derive(Default)]
struct MockObservationSource {
    responses: HashMap<String, CannedSnapshot>,
    failing: HashSet<String>,
    calls: Mutex<Vec<String>>,
}

impl MockObservationSource {
    fn with_fixtures(fixtures: &[&EntryFixture]) -> Self {
        let mut source = Self::default();
        for fixture in fixtures {
            source.responses.insert(
                fixture.address.to_string(),
                CannedSnapshot {
                    network_id: fixture.snapshot.network_id,
                    virtual_daa_score: fixture.snapshot.virtual_daa_score,
                    utxos: fixture.snapshot.utxos.clone(),
                },
            );
        }
        source
    }

    fn with_snapshot(address: &Address, snapshot: CannedSnapshot) -> Self {
        let mut source = Self::default();
        source.responses.insert(address.to_string(), snapshot);
        source
    }

    fn call_count(&self) -> usize {
        self.calls.lock().unwrap().len()
    }
}

impl RuleObservationSource for MockObservationSource {
    fn observe_address<'a>(&'a self, address: &'a Address) -> RuleObservationFuture<'a> {
        Box::pin(async move {
            let key = address.to_string();
            self.calls.lock().unwrap().push(key.clone());
            if self.failing.contains(&key) {
                return Err(RuleObservationError);
            }
            let canned = self.responses.get(&key).ok_or(RuleObservationError)?;
            Ok(RuleObservationSnapshot {
                network_id: canned.network_id,
                virtual_daa_score: canned.virtual_daa_score,
                utxos: canned.utxos.clone(),
            })
        })
    }
}

/// Injected content source with per-CID canned bytes, forced failures, and a
/// call log. Caller-trusted test boundary; no network access.
#[derive(Default)]
struct MockContentSource {
    responses: HashMap<String, Vec<u8>>,
    failing: HashSet<String>,
    calls: Mutex<Vec<String>>,
}

impl MockContentSource {
    fn with_content(cid: &str, content: &[u8]) -> Self {
        let mut source = Self::default();
        source.responses.insert(cid.to_string(), content.to_vec());
        source
    }

    fn call_count(&self) -> usize {
        self.calls.lock().unwrap().len()
    }
}

impl RuleContentSource for MockContentSource {
    fn fetch_rule_content<'a>(&'a self, canonical_cid: &'a str) -> RuleContentFuture<'a> {
        Box::pin(async move {
            self.calls.lock().unwrap().push(canonical_cid.to_string());
            if self.failing.contains(canonical_cid) {
                return Err(RuleFetchError);
            }
            self.responses
                .get(canonical_cid)
                .cloned()
                .ok_or(RuleFetchError)
        })
    }
}

fn scanner_with_old_rule() -> YaraScanner {
    let mut scanner = YaraScanner::new().unwrap();
    scanner
        .add_rule(CompiledRule {
            name: "OLD-RULE".to_string(),
            patterns: vec![b"OLDPATTERN".to_vec()],
            required_matches: 1,
        })
        .unwrap();
    scanner
}

fn old_rule_intact(scanner: &YaraScanner) -> bool {
    scanner.rule_count() == 1
        && scanner.scan_bytes(b"xx OLDPATTERN yy").unwrap().is_threat
        && !scanner.scan_bytes(b"xx ALPHA yy").unwrap().is_threat
}

#[tokio::test]
async fn success_replaces_scanner_exactly_once() {
    let content_a = rule_content(7, "ALPHA");
    let content_b = rule_content(8, "BRAVO");
    let cid_a = cid_string_for(&content_a);
    let cid_b = cid_string_for(&content_b);
    let fixture_a = entry_fixture(7, '1', 1, &content_a);
    let fixture_b = entry_fixture(8, '3', 1, &content_b);
    let fixtures = [&fixture_a, &fixture_b];
    let entries = entries_of(&fixtures);
    let observation = MockObservationSource::with_fixtures(&fixtures);
    let mut content = MockContentSource::with_content(&cid_a, &content_a);
    content.responses.insert(cid_b.clone(), content_b.clone());

    let mut scanner = scanner_with_old_rule();
    sync_rule_snapshot(&mut scanner, &content, &observation, &entries)
        .await
        .unwrap();

    assert_eq!(scanner.rule_count(), 2);
    assert!(scanner.scan_bytes(b"xx ALPHA yy").unwrap().is_threat);
    assert!(scanner.scan_bytes(b"xx BRAVO yy").unwrap().is_threat);
    // The old rule was replaced, not appended.
    assert!(!scanner.scan_bytes(b"xx OLDPATTERN yy").unwrap().is_threat);
    assert_eq!(observation.call_count(), 2);
    assert_eq!(content.call_count(), 2);
}

#[tokio::test]
async fn content_source_failure_preserves_prior_state() {
    let content_a = rule_content(7, "ALPHA");
    let cid = cid_string_for(&content_a);
    let fixture = entry_fixture(7, '1', 1, &content_a);
    let fixtures = [&fixture];
    let entries = entries_of(&fixtures);
    let observation = MockObservationSource::with_fixtures(&fixtures);
    let mut content = MockContentSource::default();
    content.failing.insert(cid);

    let mut scanner = scanner_with_old_rule();
    assert!(
        sync_rule_snapshot(&mut scanner, &content, &observation, &entries)
            .await
            .is_err()
    );
    assert!(old_rule_intact(&scanner));
}

#[tokio::test]
async fn wrong_bytes_fail_cid_binding_and_preserve_state() {
    let content_a = rule_content(7, "ALPHA");
    let cid = cid_string_for(&content_a);
    let fixture = entry_fixture(7, '1', 1, &content_a);
    let fixtures = [&fixture];
    let entries = entries_of(&fixtures);
    let observation = MockObservationSource::with_fixtures(&fixtures);
    // The source returns bytes that do not hash to the pinned CID.
    let content = MockContentSource::with_content(&cid, b"forged content");

    let mut scanner = scanner_with_old_rule();
    assert!(
        sync_rule_snapshot(&mut scanner, &content, &observation, &entries)
            .await
            .is_err()
    );
    assert!(old_rule_intact(&scanner));
}

#[tokio::test]
async fn duplicate_rule_ids_rejected_before_any_fetch() {
    // Same proposal-derived rule id, distinct addresses, outpoints, contents.
    let content_a = rule_content(7, "ALPHA");
    let content_b = rule_content(7, "BRAVO");
    let fixture_a = entry_fixture(7, '1', 1, &content_a);
    let fixture_b = entry_fixture(7, '3', 1, &content_b);
    let fixtures = [&fixture_a, &fixture_b];
    let entries = entries_of(&fixtures);
    let observation = MockObservationSource::with_fixtures(&fixtures);
    let content = MockContentSource::default();

    let mut scanner = scanner_with_old_rule();
    assert!(
        sync_rule_snapshot(&mut scanner, &content, &observation, &entries)
            .await
            .is_err()
    );
    assert!(old_rule_intact(&scanner));
    assert_eq!(content.call_count(), 0);
}

#[tokio::test]
async fn duplicate_verified_outpoints_rejected_before_any_fetch() {
    // Distinct proposals (distinct rule ids and CIDs) sharing one outpoint.
    let content_a = rule_content(7, "ALPHA");
    let content_b = rule_content(8, "BRAVO");
    let fixture_a = entry_fixture(7, '1', 1, &content_a);
    let fixture_b = entry_fixture(8, '1', 1, &content_b);
    let fixtures = [&fixture_a, &fixture_b];
    let entries = entries_of(&fixtures);
    let observation = MockObservationSource::with_fixtures(&fixtures);
    let content = MockContentSource::default();

    let mut scanner = scanner_with_old_rule();
    assert!(
        sync_rule_snapshot(&mut scanner, &content, &observation, &entries)
            .await
            .is_err()
    );
    assert!(old_rule_intact(&scanner));
    assert_eq!(content.call_count(), 0);
}

#[tokio::test]
async fn duplicate_canonical_cids_rejected_before_any_fetch() {
    // Distinct proposals and outpoints but identical content, hence one CID.
    let content_a = rule_content(7, "ALPHA");
    let content_b = content_a.clone();
    let fixture_a = entry_fixture(7, '1', 1, &content_a);
    let fixture_b = entry_fixture(8, '3', 1, &content_b);
    let fixtures = [&fixture_a, &fixture_b];
    let entries = entries_of(&fixtures);
    let observation = MockObservationSource::with_fixtures(&fixtures);
    let content = MockContentSource::default();

    let mut scanner = scanner_with_old_rule();
    assert!(
        sync_rule_snapshot(&mut scanner, &content, &observation, &entries)
            .await
            .is_err()
    );
    assert!(old_rule_intact(&scanner));
    assert_eq!(content.call_count(), 0);
}

#[tokio::test]
async fn partial_fetch_failure_rolls_back_completely() {
    let content_a = rule_content(7, "ALPHA");
    let content_b = rule_content(8, "BRAVO");
    let cid_a = cid_string_for(&content_a);
    let cid_b = cid_string_for(&content_b);
    let fixture_a = entry_fixture(7, '1', 1, &content_a);
    let fixture_b = entry_fixture(8, '3', 1, &content_b);
    let fixtures = [&fixture_a, &fixture_b];
    let entries = entries_of(&fixtures);
    let observation = MockObservationSource::with_fixtures(&fixtures);
    // First fetch succeeds, second fails: no partial swap may occur.
    let mut content = MockContentSource::with_content(&cid_a, &content_a);
    content.failing.insert(cid_b);

    let mut scanner = scanner_with_old_rule();
    assert!(
        sync_rule_snapshot(&mut scanner, &content, &observation, &entries)
            .await
            .is_err()
    );
    assert!(old_rule_intact(&scanner));
}

#[tokio::test]
async fn empty_snapshot_clears_rules_without_observing_or_fetching() {
    let observation = MockObservationSource::default();
    let content = MockContentSource::default();
    let mut scanner = scanner_with_old_rule();
    sync_rule_snapshot(&mut scanner, &content, &observation, &[])
        .await
        .unwrap();
    assert_eq!(scanner.rule_count(), 0);
    assert!(!scanner.scan_bytes(b"xx OLDPATTERN yy").unwrap().is_threat);
    assert_eq!(observation.call_count(), 0);
    assert_eq!(content.call_count(), 0);
}

#[tokio::test]
async fn beta_and_mainnet_modes_fail_closed() {
    let content_a = rule_content(7, "ALPHA");
    let cid = cid_string_for(&content_a);
    let fixture = entry_fixture(7, '1', 1, &content_a);
    let fixtures = [&fixture];
    let entries = entries_of(&fixtures);
    let observation = MockObservationSource::with_fixtures(&fixtures);
    let content = MockContentSource::with_content(&cid, &content_a);

    for mode in [RuntimeMode::Beta, RuntimeMode::Mainnet] {
        let mut scanner = scanner_with_old_rule();
        assert!(
            sync_rule_snapshot_for_mode(mode, &mut scanner, &content, &observation, &entries)
                .await
                .is_err()
        );
        assert!(old_rule_intact(&scanner));
    }
    assert_eq!(observation.call_count(), 0);
    assert_eq!(content.call_count(), 0);
}

#[tokio::test]
async fn invalid_manifest_preserves_state_and_never_fetches() {
    let content_a = rule_content(7, "ALPHA");
    let fixture = entry_fixture(7, '1', 1, &content_a);
    let fixtures = [&fixture];
    let mut entries = entries_of(&fixtures);
    // Break the owner-pin: the manifest no longer hashes to the expected root.
    entries[0].expected_manifest_sha256 = "0".repeat(64);
    let observation = MockObservationSource::with_fixtures(&fixtures);
    let content = MockContentSource::default();

    let mut scanner = scanner_with_old_rule();
    assert!(
        sync_rule_snapshot(&mut scanner, &content, &observation, &entries)
            .await
            .is_err()
    );
    assert!(old_rule_intact(&scanner));
    assert_eq!(content.call_count(), 0);
}

#[tokio::test]
async fn invalid_or_non_testnet_address_never_calls_any_source() {
    let content_a = rule_content(7, "ALPHA");
    let fixture = entry_fixture(7, '1', 1, &content_a);
    let fixtures = [&fixture];
    let observation = MockObservationSource::with_fixtures(&fixtures);
    let content = MockContentSource::default();

    let mut invalid = entries_of(&fixtures);
    invalid[0].address = "not-an-address".to_string();
    let mut scanner = scanner_with_old_rule();
    assert!(
        sync_rule_snapshot(&mut scanner, &content, &observation, &invalid)
            .await
            .is_err()
    );
    assert!(old_rule_intact(&scanner));

    let mut mainnet = entries_of(&fixtures);
    mainnet[0].address = Address::new(Prefix::Mainnet, Version::PubKey, &[7; 32]).to_string();
    let mut scanner = scanner_with_old_rule();
    assert!(
        sync_rule_snapshot(&mut scanner, &content, &observation, &mainnet)
            .await
            .is_err()
    );
    assert!(old_rule_intact(&scanner));

    // The address is parsed and checked before the observation source runs.
    assert_eq!(observation.call_count(), 0);
    assert_eq!(content.call_count(), 0);
}

#[tokio::test]
async fn observation_source_failure_never_fetches_content() {
    let content_a = rule_content(7, "ALPHA");
    let fixture = entry_fixture(7, '1', 1, &content_a);
    let fixtures = [&fixture];
    let entries = entries_of(&fixtures);
    let mut observation = MockObservationSource::default();
    observation.failing.insert(fixture.address.to_string());
    let content = MockContentSource::default();

    let mut scanner = scanner_with_old_rule();
    assert!(
        sync_rule_snapshot(&mut scanner, &content, &observation, &entries)
            .await
            .is_err()
    );
    assert!(old_rule_intact(&scanner));
    assert_eq!(content.call_count(), 0);
}

#[tokio::test]
async fn wrong_node_network_fails_closed() {
    let content_a = rule_content(7, "ALPHA");
    let fixture = entry_fixture(7, '1', 1, &content_a);
    let fixtures = [&fixture];
    let entries = entries_of(&fixtures);
    // The node reports Testnet-11 instead of the exact Testnet-10 pin.
    let observation = MockObservationSource::with_snapshot(
        &fixture.address,
        CannedSnapshot {
            network_id: NetworkId::with_suffix(NetworkType::Testnet, 11),
            virtual_daa_score: OBSERVED_DAA,
            utxos: fixture.snapshot.utxos.clone(),
        },
    );
    let content = MockContentSource::default();

    let mut scanner = scanner_with_old_rule();
    assert!(
        sync_rule_snapshot(&mut scanner, &content, &observation, &entries)
            .await
            .is_err()
    );
    assert!(old_rule_intact(&scanner));
    assert_eq!(content.call_count(), 0);
}

#[tokio::test]
async fn returned_address_mismatch_fails_closed() {
    let content_a = rule_content(7, "ALPHA");
    let fixture = entry_fixture(7, '1', 1, &content_a);
    let fixtures = [&fixture];
    let entries = entries_of(&fixtures);
    let content = MockContentSource::default();

    // The node returns a UTXO carrying a different address.
    let mut wrong_address = fixture.snapshot.utxos.clone();
    wrong_address[0].address = Some(test_address(9));
    let observation = MockObservationSource::with_snapshot(
        &fixture.address,
        CannedSnapshot {
            network_id: NetworkId::with_suffix(NetworkType::Testnet, 10),
            virtual_daa_score: OBSERVED_DAA,
            utxos: wrong_address,
        },
    );
    let mut scanner = scanner_with_old_rule();
    assert!(
        sync_rule_snapshot(&mut scanner, &content, &observation, &entries)
            .await
            .is_err()
    );
    assert!(old_rule_intact(&scanner));

    // The node returns a UTXO carrying no address at all.
    let mut missing_address = fixture.snapshot.utxos.clone();
    missing_address[0].address = None;
    let observation = MockObservationSource::with_snapshot(
        &fixture.address,
        CannedSnapshot {
            network_id: NetworkId::with_suffix(NetworkType::Testnet, 10),
            virtual_daa_score: OBSERVED_DAA,
            utxos: missing_address,
        },
    );
    let mut scanner = scanner_with_old_rule();
    assert!(
        sync_rule_snapshot(&mut scanner, &content, &observation, &entries)
            .await
            .is_err()
    );
    assert!(old_rule_intact(&scanner));

    assert_eq!(content.call_count(), 0);
}

#[test]
fn metadata_native_ingest_uses_rule_state_fields_directly() {
    let content = rule_content(9, "CHARLIE");
    let constructor = constructor_document(9, &content);
    let metadata = decode_rule_state(&constructor).unwrap();
    assert_eq!(metadata.rule_id(), "PROM-RULE-0009");

    let mut scanner = YaraScanner::new().unwrap();
    let entries = [RuleMetadataSnapshotEntry {
        metadata,
        content: content.clone(),
    }];
    ingest_rule_state_snapshot(&mut scanner, &entries).unwrap();
    assert_eq!(scanner.rule_count(), 1);
    assert!(scanner.scan_bytes(b"xx CHARLIE yy").unwrap().is_threat);
}

#[test]
fn metadata_native_ingest_enforces_binding_and_mode_gate() {
    let content = rule_content(9, "CHARLIE");
    let constructor = constructor_document(9, &content);

    // Wrong bytes fail the shared CID binding and preserve prior state.
    let mut scanner = scanner_with_old_rule();
    let forged = [RuleMetadataSnapshotEntry {
        metadata: decode_rule_state(&constructor).unwrap(),
        content: b"forged".to_vec(),
    }];
    assert!(ingest_rule_state_snapshot(&mut scanner, &forged).is_err());
    assert!(old_rule_intact(&scanner));

    // Explicit beta/mainnet modes fail closed.
    for mode in [RuntimeMode::Beta, RuntimeMode::Mainnet] {
        let ok = [RuleMetadataSnapshotEntry {
            metadata: decode_rule_state(&constructor).unwrap(),
            content: content.clone(),
        }];
        assert!(ingest_rule_state_snapshot_for_mode(mode, &mut scanner, &ok).is_err());
        assert!(old_rule_intact(&scanner));
    }
}

#[test]
fn errors_and_entries_stay_redacted() {
    let err = prometheus_client::blockchain::rule_sync::RuleSyncError;
    assert_eq!(format!("{err:?}"), "RuleSyncError");
    let fetch_err = RuleFetchError;
    assert_eq!(format!("{fetch_err:?}"), "RuleFetchError");

    let fixture = entry_fixture(7, '1', 1, &rule_content(7, "SENSITIVE-LITERAL"));
    let debugged = format!("{:?}", fixture.entry);
    assert!(!debugged.contains("SENSITIVE"));
    assert!(!debugged.contains(&txid('1')));
    assert!(!debugged.contains(COVENANT));
    assert!(!debugged.contains(&fixture.address.to_string()));
}

fn secure_checkpoint_dir() -> tempfile::TempDir {
    let directory = tempfile::tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    directory
}

fn source_at(fixture: &EntryFixture, virtual_daa: u64) -> MockObservationSource {
    let mut source = MockObservationSource::with_fixtures(&[fixture]);
    source
        .responses
        .get_mut(&fixture.address.to_string())
        .unwrap()
        .virtual_daa_score = virtual_daa;
    source
}

#[tokio::test]
async fn durable_first_write_restart_replay_and_forward_update() {
    let directory = secure_checkpoint_dir();
    let content_bytes = rule_content(7, "ALPHA");
    let cid = cid_string_for(&content_bytes);
    let fixture = entry_fixture(7, '1', 1, &content_bytes);
    let entries = entries_of(&[&fixture]);
    let content = MockContentSource::with_content(&cid, &content_bytes);
    let store = PosixRuleCheckpointStore::open(directory.path()).unwrap();

    let mut scanner = scanner_with_old_rule();
    sync_rule_snapshot_durable(
        &store,
        &mut scanner,
        &content,
        &source_at(&fixture, OBSERVED_DAA),
        &entries,
        None,
    )
    .await
    .unwrap();
    assert!(scanner.scan_bytes(b"ALPHA").unwrap().is_threat);
    let checkpoint = directory.path().join("rule-storage.checkpoint.json");
    let first = fs::read(&checkpoint).unwrap();

    // A fresh store/scanner converges through exact replay without rewriting.
    let restarted = PosixRuleCheckpointStore::open(directory.path()).unwrap();
    let mut fresh_scanner = YaraScanner::new().unwrap();
    sync_rule_snapshot_durable(
        &restarted,
        &mut fresh_scanner,
        &content,
        &source_at(&fixture, OBSERVED_DAA),
        &entries,
        None,
    )
    .await
    .unwrap();
    assert!(fresh_scanner.scan_bytes(b"ALPHA").unwrap().is_threat);
    assert_eq!(fs::read(&checkpoint).unwrap(), first);

    sync_rule_snapshot_durable(
        &restarted,
        &mut fresh_scanner,
        &content,
        &source_at(&fixture, OBSERVED_DAA + 10),
        &entries,
        None,
    )
    .await
    .unwrap();
    assert_ne!(fs::read(checkpoint).unwrap(), first);
}

#[tokio::test]
async fn durable_rollback_and_same_order_equivocation_preserve_scanner() {
    let directory = secure_checkpoint_dir();
    let a = rule_content(7, "ALPHA");
    let b = rule_content(8, "BRAVO");
    let fixture_a = entry_fixture(7, '1', 1, &a);
    let fixture_b = entry_fixture(8, '3', 1, &b);
    let content_a = MockContentSource::with_content(&cid_string_for(&a), &a);
    let content_b = MockContentSource::with_content(&cid_string_for(&b), &b);
    let store = PosixRuleCheckpointStore::open(directory.path()).unwrap();
    let mut scanner = scanner_with_old_rule();

    sync_rule_snapshot_durable(
        &store,
        &mut scanner,
        &content_a,
        &source_at(&fixture_a, OBSERVED_DAA + 10),
        &entries_of(&[&fixture_a]),
        None,
    )
    .await
    .unwrap();
    let checkpoint = fs::read(directory.path().join("rule-storage.checkpoint.json")).unwrap();

    assert!(sync_rule_snapshot_durable(
        &store,
        &mut scanner,
        &content_a,
        &source_at(&fixture_a, OBSERVED_DAA),
        &entries_of(&[&fixture_a]),
        None,
    )
    .await
    .is_err());
    assert!(scanner.scan_bytes(b"ALPHA").unwrap().is_threat);

    assert!(sync_rule_snapshot_durable(
        &store,
        &mut scanner,
        &content_b,
        &source_at(&fixture_b, OBSERVED_DAA + 10),
        &entries_of(&[&fixture_b]),
        None,
    )
    .await
    .is_err());
    assert!(scanner.scan_bytes(b"ALPHA").unwrap().is_threat);
    assert!(!scanner.scan_bytes(b"BRAVO").unwrap().is_threat);
    assert_eq!(
        fs::read(directory.path().join("rule-storage.checkpoint.json")).unwrap(),
        checkpoint
    );
}

#[tokio::test]
async fn durable_newest_rule_removal_and_explicit_empty_transitions() {
    let directory = secure_checkpoint_dir();
    let a = rule_content(7, "ALPHA");
    let b = rule_content(8, "BRAVO");
    let fixture_a = entry_fixture(7, '1', 1, &a);
    let fixture_b = entry_fixture(8, '3', 1, &b);
    let mut observation = MockObservationSource::with_fixtures(&[&fixture_a, &fixture_b]);
    observation
        .responses
        .get_mut(&fixture_a.address.to_string())
        .unwrap()
        .virtual_daa_score = OBSERVED_DAA;
    observation
        .responses
        .get_mut(&fixture_b.address.to_string())
        .unwrap()
        .virtual_daa_score = OBSERVED_DAA + 20;
    let mut content = MockContentSource::with_content(&cid_string_for(&a), &a);
    content.responses.insert(cid_string_for(&b), b);
    let store = PosixRuleCheckpointStore::open(directory.path()).unwrap();
    let mut scanner = scanner_with_old_rule();
    sync_rule_snapshot_durable(
        &store,
        &mut scanner,
        &content,
        &observation,
        &entries_of(&[&fixture_a, &fixture_b]),
        None,
    )
    .await
    .unwrap();

    // Removing the newest-created rule is valid when verified observation time advances.
    sync_rule_snapshot_durable(
        &store,
        &mut scanner,
        &content,
        &source_at(&fixture_a, OBSERVED_DAA + 10),
        &entries_of(&[&fixture_a]),
        None,
    )
    .await
    .unwrap();
    assert_eq!(scanner.rule_count(), 1);
    assert!(scanner.scan_bytes(b"ALPHA").unwrap().is_threat);

    assert!(sync_rule_snapshot_durable(
        &store,
        &mut scanner,
        &content,
        &MockObservationSource::default(),
        &[],
        None
    )
    .await
    .is_err());
    assert!(sync_rule_snapshot_durable(
        &store,
        &mut scanner,
        &content,
        &MockObservationSource::default(),
        &[],
        Some(0)
    )
    .await
    .is_err());
    assert!(scanner.scan_bytes(b"ALPHA").unwrap().is_threat);

    sync_rule_snapshot_durable(
        &store,
        &mut scanner,
        &content,
        &MockObservationSource::default(),
        &[],
        Some(OBSERVED_DAA + 30),
    )
    .await
    .unwrap();
    assert_eq!(scanner.rule_count(), 0);
    // Exact empty replay succeeds; lower and same-order nonempty equivocation fail.
    sync_rule_snapshot_durable(
        &store,
        &mut scanner,
        &content,
        &MockObservationSource::default(),
        &[],
        Some(OBSERVED_DAA + 30),
    )
    .await
    .unwrap();
    assert!(sync_rule_snapshot_durable(
        &store,
        &mut scanner,
        &content,
        &MockObservationSource::default(),
        &[],
        Some(OBSERVED_DAA + 20)
    )
    .await
    .is_err());
    assert!(sync_rule_snapshot_durable(
        &store,
        &mut scanner,
        &content,
        &source_at(&fixture_a, OBSERVED_DAA + 30),
        &entries_of(&[&fixture_a]),
        None
    )
    .await
    .is_err());
    assert_eq!(scanner.rule_count(), 0);
}

struct FailingStore;
struct FailingLock;

impl RuleCheckpointStore for FailingStore {
    fn lock(&self) -> Result<Box<dyn RuleCheckpointLock + '_>, RuleCheckpointError> {
        Ok(Box::new(FailingLock))
    }
}

impl RuleCheckpointLock for FailingLock {
    fn read(&self) -> Result<Option<Vec<u8>>, RuleCheckpointError> {
        Ok(None)
    }
    fn replace(&self, _canonical_bytes: &[u8]) -> Result<(), RuleCheckpointError> {
        Err(RuleCheckpointError)
    }
}

#[tokio::test]
async fn injected_commit_failure_and_mode_gates_preserve_prior_state() {
    let a = rule_content(7, "ALPHA");
    let fixture = entry_fixture(7, '1', 1, &a);
    let content = MockContentSource::with_content(&cid_string_for(&a), &a);
    let entries = entries_of(&[&fixture]);
    let mut scanner = scanner_with_old_rule();
    assert!(sync_rule_snapshot_durable(
        &FailingStore,
        &mut scanner,
        &content,
        &source_at(&fixture, OBSERVED_DAA),
        &entries,
        None
    )
    .await
    .is_err());
    assert!(old_rule_intact(&scanner));

    let directory = secure_checkpoint_dir();
    let store = PosixRuleCheckpointStore::open(directory.path()).unwrap();
    for mode in [RuntimeMode::Beta, RuntimeMode::Mainnet] {
        assert!(sync_rule_snapshot_durable_for_mode(
            mode,
            &store,
            &mut scanner,
            &content,
            &source_at(&fixture, OBSERVED_DAA),
            &entries,
            None
        )
        .await
        .is_err());
        assert!(old_rule_intact(&scanner));
    }
}

#[test]
fn posix_store_rejects_unsafe_state_and_contention() {
    let unsafe_dir = tempfile::tempdir().unwrap();
    fs::set_permissions(unsafe_dir.path(), fs::Permissions::from_mode(0o755)).unwrap();
    assert!(PosixRuleCheckpointStore::open(unsafe_dir.path()).is_err());

    let directory = secure_checkpoint_dir();
    let linked = directory.path().with_extension("link");
    symlink(directory.path(), &linked).unwrap();
    assert!(PosixRuleCheckpointStore::open(&linked).is_err());
    fs::remove_file(linked).unwrap();

    let store_a = PosixRuleCheckpointStore::open(directory.path()).unwrap();
    let store_b = PosixRuleCheckpointStore::open(directory.path()).unwrap();
    let held = store_a.lock().unwrap();
    assert!(store_b.lock().is_err());
    drop(held);

    let checkpoint = directory.path().join("rule-storage.checkpoint.json");
    fs::write(&checkpoint, b"not-json").unwrap();
    fs::set_permissions(&checkpoint, fs::Permissions::from_mode(0o600)).unwrap();
    let lock = store_a.lock().unwrap();
    assert!(lock.read().is_ok());
    drop(lock);

    fs::set_permissions(&checkpoint, fs::Permissions::from_mode(0o644)).unwrap();
    let lock = store_a.lock().unwrap();
    assert!(lock.read().is_err());
    drop(lock);

    fs::remove_file(&checkpoint).unwrap();
    fs::write(&checkpoint, vec![b'x'; 2048]).unwrap();
    fs::set_permissions(&checkpoint, fs::Permissions::from_mode(0o600)).unwrap();
    let lock = store_a.lock().unwrap();
    assert!(lock.read().is_err());
    drop(lock);

    fs::remove_file(&checkpoint).unwrap();
    let target = directory.path().join("checkpoint-target");
    fs::write(&target, b"target").unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
    symlink(&target, &checkpoint).unwrap();
    let lock = store_a.lock().unwrap();
    assert!(lock.read().is_err());
    drop(lock);

    fs::remove_file(&checkpoint).unwrap();
    fs::create_dir(&checkpoint).unwrap();
    let lock = store_a.lock().unwrap();
    assert!(lock.read().is_err());
}

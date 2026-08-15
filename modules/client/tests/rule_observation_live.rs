use kaspa_addresses::{Address, Prefix, Version};
use kaspa_hashes::Hash;
use kaspa_rpc_core::{
    RpcScriptPublicKey, RpcTransactionOutpoint, RpcUtxoEntry, RpcUtxosByAddressesEntry,
};
use kaspa_wrpc_client::prelude::{NetworkId, NetworkType};
use prometheus_client::blockchain::connection::{KaspaConnection, TESTNET_WRPC_URL};
use prometheus_client::blockchain::rule_observation::{
    verify_rule_storage_observation_live, verify_rule_storage_observation_live_for_mode,
    verify_rule_storage_observation_live_with_source, RuleObservationError, RuleObservationFuture,
    RuleObservationSnapshot, RuleObservationSource, MANIFEST_KIND, MAX_OBSERVATION_ENTRIES,
    OBSERVATION_NETWORK_ID,
};
use prometheus_client::runtime::RuntimeMode;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const AMOUNT: u64 = 100_000_000;
const BLOCK_DAA: u64 = 1_000;
const MIN_MATURITY: u64 = 100;
const OBSERVED_DAA: u64 = BLOCK_DAA + MIN_MATURITY;

fn int(value: i64) -> Value {
    json!({"kind": "int", "data": value})
}

fn bytes(values: &[u8]) -> Value {
    json!({
        "kind": "array",
        "data": values
            .iter()
            .map(|value| json!({"kind": "byte", "data": value}))
            .collect::<Vec<_>>()
    })
}

fn constructor_document() -> String {
    let mut cid = vec![0x01, 0x55, 0x12, 0x20];
    cid.extend(0u8..32);
    serde_json::to_string(&json!([
        bytes(&[4; 32]),
        int(8),
        int(7),
        bytes(&[5; 32]),
        bytes(&[6; 32]),
        int(0),
        bytes(&cid),
        int(9_000),
        int(100_000),
        int(3),
        int(1),
        int(964_000),
        int(2),
        int(3),
        int(2),
        int(50_000),
        int(7_500),
        int(965_000),
        {"kind": "bool", "data": true},
        int(1)
    ]))
    .unwrap()
}

fn sha256_hex(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}

fn manifest_json(constructor_hash: &str) -> String {
    format!(
        "{{\"schema_version\":1,\"kind\":\"{MANIFEST_KIND}\",\"network_id\":\"{OBSERVATION_NETWORK_ID}\",\
\"outpoint\":{{\"transaction_id\":\"{}\",\"index\":1}},\"covenant_id\":\"{}\",\
\"script_public_key\":{{\"version\":0,\"script_hex\":\"51\"}},\"amount_sompi\":{AMOUNT},\
\"block_daa_score\":{BLOCK_DAA},\"minimum_virtual_daa_maturity\":{MIN_MATURITY},\
\"constructor_json_sha256\":\"{constructor_hash}\"}}",
        "11".repeat(32),
        "22".repeat(32)
    )
}

fn test_address(payload: u8) -> Address {
    Address::new(Prefix::Testnet, Version::PubKey, &[payload; 32])
}

#[allow(clippy::too_many_arguments)]
fn rpc_entry(
    txid_byte: u8,
    index: u32,
    amount: u64,
    script: Vec<u8>,
    block_daa_score: u64,
    is_coinbase: bool,
    covenant_byte: Option<u8>,
    address: Option<Address>,
) -> RpcUtxosByAddressesEntry {
    RpcUtxosByAddressesEntry {
        address,
        outpoint: RpcTransactionOutpoint {
            transaction_id: Hash::from_bytes([txid_byte; 32]),
            index,
        },
        utxo_entry: RpcUtxoEntry::new(
            amount,
            RpcScriptPublicKey::from_vec(0, script),
            block_daa_score,
            is_coinbase,
            covenant_byte.map(|byte| Hash::from_bytes([byte; 32])),
        ),
    }
}

fn matching_entry(address: &Address) -> RpcUtxosByAddressesEntry {
    rpc_entry(
        0x11,
        1,
        AMOUNT,
        vec![0x51],
        BLOCK_DAA,
        false,
        Some(0x22),
        Some(address.clone()),
    )
}

fn unrelated_entry(address: &Address) -> RpcUtxosByAddressesEntry {
    rpc_entry(0x33, 0, 42, vec![0], 10, false, None, Some(address.clone()))
}

struct MockSource {
    network_id: NetworkId,
    virtual_daa_score: u64,
    utxos: Vec<RpcUtxosByAddressesEntry>,
    fail: bool,
}

impl RuleObservationSource for MockSource {
    fn observe_address<'a>(&'a self, _address: &'a Address) -> RuleObservationFuture<'a> {
        Box::pin(async move {
            if self.fail {
                return Err(RuleObservationError);
            }
            Ok(RuleObservationSnapshot {
                network_id: self.network_id,
                virtual_daa_score: self.virtual_daa_score,
                utxos: self.utxos.clone(),
            })
        })
    }
}

struct Fixture {
    address: Address,
    expected_manifest_hash: String,
    manifest: String,
    constructor: String,
}

fn fixture() -> Fixture {
    let constructor = constructor_document();
    let manifest = manifest_json(&sha256_hex(&constructor));
    Fixture {
        address: test_address(7),
        expected_manifest_hash: sha256_hex(&manifest),
        manifest,
        constructor,
    }
}

fn source(utxos: Vec<RpcUtxosByAddressesEntry>) -> MockSource {
    MockSource {
        network_id: NetworkId::with_suffix(NetworkType::Testnet, 10),
        virtual_daa_score: OBSERVED_DAA,
        utxos,
        fail: false,
    }
}

async fn verify(
    fixture: &Fixture,
    source: &MockSource,
) -> Result<prometheus_client::blockchain::rule_state::RuleStateMetadata, RuleObservationError> {
    verify_rule_storage_observation_live_with_source(
        source,
        &fixture.address.to_string(),
        &fixture.expected_manifest_hash,
        &fixture.manifest,
        &fixture.constructor,
    )
    .await
}

#[tokio::test]
async fn live_adapter_converts_rpc_fields_and_decodes_state() {
    let fixture = fixture();
    let source = source(vec![
        unrelated_entry(&fixture.address),
        matching_entry(&fixture.address),
    ]);
    let metadata = verify(&fixture, &source).await.unwrap();
    assert_eq!(metadata.proposal_id(), 7);
    assert_eq!(metadata.rule_id(), "PROM-RULE-0007");
    assert!(metadata.active());
}

#[tokio::test]
async fn source_failure_and_wrong_network_fail_closed() {
    let fixture = fixture();
    let failed = MockSource {
        network_id: NetworkId::with_suffix(NetworkType::Testnet, 10),
        virtual_daa_score: OBSERVED_DAA,
        utxos: vec![],
        fail: true,
    };
    assert!(verify(&fixture, &failed).await.is_err());

    let wrong_network = MockSource {
        network_id: NetworkId::with_suffix(NetworkType::Testnet, 11),
        virtual_daa_score: OBSERVED_DAA,
        utxos: vec![matching_entry(&fixture.address)],
        fail: false,
    };
    assert!(verify(&fixture, &wrong_network).await.is_err());
}

#[tokio::test]
async fn invalid_or_non_testnet_address_fails_before_source_use() {
    let fixture = fixture();
    let source = source(vec![matching_entry(&fixture.address)]);
    assert!(verify_rule_storage_observation_live_with_source(
        &source,
        "not-an-address",
        &fixture.expected_manifest_hash,
        &fixture.manifest,
        &fixture.constructor,
    )
    .await
    .is_err());

    let mainnet = Address::new(Prefix::Mainnet, Version::PubKey, &[7; 32]);
    assert!(verify_rule_storage_observation_live_with_source(
        &source,
        &mainnet.to_string(),
        &fixture.expected_manifest_hash,
        &fixture.manifest,
        &fixture.constructor,
    )
    .await
    .is_err());
}

#[tokio::test]
async fn mismatched_reported_address_fails_closed() {
    let fixture = fixture();
    let mut entry = matching_entry(&fixture.address);
    entry.address = Some(test_address(8));
    assert!(verify(&fixture, &source(vec![entry])).await.is_err());

    let mut missing_address = matching_entry(&fixture.address);
    missing_address.address = None;
    assert!(verify(&fixture, &source(vec![missing_address]))
        .await
        .is_err());
}

#[tokio::test]
async fn missing_covenant_duplicate_and_field_mismatch_fail_closed() {
    let fixture = fixture();

    let mut no_covenant = matching_entry(&fixture.address);
    no_covenant.utxo_entry.covenant_id = None;
    assert!(verify(&fixture, &source(vec![no_covenant])).await.is_err());

    let matching = matching_entry(&fixture.address);
    assert!(verify(&fixture, &source(vec![matching.clone(), matching]))
        .await
        .is_err());

    let mut wrong_amount = matching_entry(&fixture.address);
    wrong_amount.utxo_entry.amount -= 1;
    assert!(verify(&fixture, &source(vec![wrong_amount])).await.is_err());
}

#[tokio::test]
async fn coinbase_immaturity_and_oversize_fail_closed() {
    let fixture = fixture();

    let mut coinbase = matching_entry(&fixture.address);
    coinbase.utxo_entry.is_coinbase = true;
    assert!(verify(&fixture, &source(vec![coinbase])).await.is_err());

    let mut immature = source(vec![matching_entry(&fixture.address)]);
    immature.virtual_daa_score = OBSERVED_DAA - 1;
    assert!(verify(&fixture, &immature).await.is_err());

    let oversized = vec![unrelated_entry(&fixture.address); MAX_OBSERVATION_ENTRIES + 1];
    assert!(verify(&fixture, &source(oversized)).await.is_err());
}

#[tokio::test]
async fn disconnected_connection_and_restricted_modes_fail_closed() {
    let fixture = fixture();
    let connection = KaspaConnection::new(TESTNET_WRPC_URL).unwrap();
    assert!(verify_rule_storage_observation_live(
        &connection,
        &fixture.address.to_string(),
        &fixture.expected_manifest_hash,
        &fixture.manifest,
        &fixture.constructor,
    )
    .await
    .is_err());

    for mode in [RuntimeMode::Beta, RuntimeMode::Mainnet] {
        assert!(verify_rule_storage_observation_live_for_mode(
            mode,
            &connection,
            &fixture.address.to_string(),
            &fixture.expected_manifest_hash,
            &fixture.manifest,
            &fixture.constructor,
        )
        .await
        .is_err());
    }
}

#[test]
fn public_error_is_redacted() {
    let rendered = format!("{0} / {0:?}", RuleObservationError);
    assert_eq!(
        rendered,
        "invalid RuleStorage UTXO observation / RuleObservationError"
    );
}

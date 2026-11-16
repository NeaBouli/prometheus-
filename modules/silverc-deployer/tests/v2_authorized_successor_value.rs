//! MSB-R1: value-backed v2 transitions must bind the covenant value to the
//! authorized successor output, not to a fixed output index.
//!
//! The pinned SilverScript transition wrapper validates the successor state at
//! `OpAuthOutputIdx(activeInputIndex, 0)`, while the value checks in the contract
//! policy read `tx.outputs[0]`. These tests execute the pinned rusty-kaspa script
//! engine offline on synthetic transactions: the authorized successor is placed at
//! output 1 and a non-covenant decoy at output 0 carries the value the policy
//! expects. No network, wallet or chain is involved; keys are ephemeral.

use kaspa_addresses::{Address, Prefix, Version as AddressVersion};
use kaspa_bip32::secp256k1::{rand::thread_rng, Keypair, Message, SECP256K1};
use kaspa_consensus_core::hashing::sighash::{
    calc_schnorr_signature_hash, SigHashReusedValuesUnsync,
};
use kaspa_consensus_core::hashing::sighash_type::SIG_HASH_ALL;
use kaspa_consensus_core::subnets::SUBNETWORK_ID_NATIVE;
use kaspa_consensus_core::tx::{
    CovenantBinding, PopulatedTransaction, Transaction, TransactionInput, TransactionOutpoint,
    TransactionOutput, UtxoEntry, VerifiableTransaction,
};
use kaspa_consensus_core::Hash;
use kaspa_txscript::caches::Cache;
use kaspa_txscript::covenants::CovenantsContext;
use kaspa_txscript::script_builder::ScriptBuilder;
use kaspa_txscript::{
    pay_to_address_script, pay_to_script_hash_script, EngineCtx, EngineFlags, TxScriptEngine,
};
use silverscript_lang::ast::Expr;
use silverscript_lang::compiler::{compile_contract, CompileOptions, CovenantDeclCallOptions};

const SOURCE: &str = include_str!("../../contracts/silverc/CommunityDonationsState.sil");
const SOMPI_PER_KAS: u64 = 100_000_000;
const POOL_KAS: i64 = 50;
const DONATION_KAS: i64 = 1;
const DAA: u64 = 1_000;
const COMPUTE_BUDGET: u16 = 1_000;

struct DonationsState {
    governance_pk: Vec<u8>,
    donation_count: i64,
    total_donated_kas: i64,
    pool_balance_kas: i64,
    last_donor_pk: Vec<u8>,
    last_message_hash: Vec<u8>,
    last_donation_block: i64,
}

impl DonationsState {
    fn args(&self) -> Vec<Expr<'static>> {
        vec![
            Expr::bytes(self.governance_pk.clone()),
            Expr::int(self.donation_count),
            Expr::int(self.total_donated_kas),
            Expr::int(self.pool_balance_kas),
            Expr::int(0),
            Expr::int(0),
            Expr::bytes(vec![0; 32]),
            Expr::int(0),
            Expr::bytes(vec![0; 32]),
            Expr::int(0),
            Expr::int(0),
            Expr::int(0),
            Expr::int(0),
            Expr::bool(false),
            Expr::bytes(self.last_donor_pk.clone()),
            Expr::bytes(self.last_message_hash.clone()),
            Expr::int(self.last_donation_block),
        ]
    }
}

#[derive(Clone, Copy)]
enum Layout {
    /// Authorized successor at output 0 carrying the backed value (control case).
    SuccessorFirst,
    /// Non-covenant decoy at output 0 carrying the backed value; underfunded
    /// authorized successor at output 1.
    DecoyFirst,
}

fn script_for(state: &DonationsState) -> Vec<u8> {
    compile_contract(SOURCE, &state.args(), CompileOptions::default())
        .expect("CommunityDonationsState must compile at the pinned SilverScript revision")
        .script
}

/// Builds and executes a donateKas transition; returns the engine result of the
/// covenant input.
fn run_donation(layout: Layout) -> Result<(), String> {
    let donor = Keypair::new(SECP256K1, &mut thread_rng());
    let donor_pk = donor.x_only_public_key().0.serialize().to_vec();
    let donor_address = Address::new(Prefix::Testnet, AddressVersion::PubKey, &donor_pk);
    let donor_spk = pay_to_address_script(&donor_address);
    let message_hash = vec![0x42; 32];

    let predecessor_state = DonationsState {
        governance_pk: vec![0x23; 32],
        donation_count: 0,
        total_donated_kas: 0,
        pool_balance_kas: POOL_KAS,
        last_donor_pk: vec![0; 32],
        last_message_hash: vec![0; 32],
        last_donation_block: 0,
    };
    let successor_state = DonationsState {
        governance_pk: vec![0x23; 32],
        donation_count: 1,
        total_donated_kas: DONATION_KAS,
        pool_balance_kas: POOL_KAS + DONATION_KAS,
        last_donor_pk: donor_pk.clone(),
        last_message_hash: message_hash.clone(),
        last_donation_block: DAA as i64,
    };
    let predecessor =
        compile_contract(SOURCE, &predecessor_state.args(), CompileOptions::default())
            .expect("predecessor compiles");
    let predecessor_spk = pay_to_script_hash_script(&predecessor.script);
    let successor_spk = pay_to_script_hash_script(&script_for(&successor_state));

    let pool_value = POOL_KAS as u64 * SOMPI_PER_KAS;
    let donation_value = DONATION_KAS as u64 * SOMPI_PER_KAS;
    let donor_funding = donation_value + 10_000_000;
    let covenant_id = Hash::from_bytes([0x5a; 32]);
    let successor_binding = Some(CovenantBinding {
        authorizing_input: 0,
        covenant_id,
    });

    let backed_value = pool_value + donation_value;
    let outputs = match layout {
        Layout::SuccessorFirst => vec![TransactionOutput {
            value: backed_value,
            script_public_key: successor_spk.clone(),
            covenant: successor_binding,
        }],
        Layout::DecoyFirst => vec![
            TransactionOutput {
                value: backed_value,
                script_public_key: donor_spk.clone(),
                covenant: None,
            },
            TransactionOutput {
                value: 1_000,
                script_public_key: successor_spk.clone(),
                covenant: successor_binding,
            },
        ],
    };

    let sigscript = |signature: Vec<u8>| -> Vec<u8> {
        let mut script = predecessor
            .build_sig_script_for_covenant_decl(
                "donateKas",
                vec![
                    Expr::bytes(donor_pk.clone()),
                    Expr::int(DONATION_KAS),
                    Expr::bytes(message_hash.clone()),
                    Expr::int(DAA as i64),
                    Expr::bytes(signature),
                ],
                CovenantDeclCallOptions { is_leader: false },
            )
            .expect("donateKas sigscript");
        let mut builder = ScriptBuilder::with_flags(EngineFlags {
            covenants_enabled: true,
            ..Default::default()
        });
        builder
            .add_data(&predecessor.script)
            .expect("redeem script push");
        script.extend_from_slice(&builder.drain());
        script
    };

    let mut tx = Transaction::new(
        1,
        vec![
            TransactionInput::new_with_compute_budget(
                TransactionOutpoint::new(Hash::from_bytes([0x11; 32]), 0),
                sigscript(vec![0; 65]),
                0,
                COMPUTE_BUDGET,
            ),
            TransactionInput::new_with_compute_budget(
                TransactionOutpoint::new(Hash::from_bytes([0x22; 32]), 0),
                vec![0; 66],
                0,
                10,
            ),
        ],
        outputs,
        DAA,
        SUBNETWORK_ID_NATIVE,
        0,
        Vec::new(),
    );
    let entries = vec![
        UtxoEntry::new(pool_value, predecessor_spk, DAA, false, Some(covenant_id)),
        UtxoEntry::new(donor_funding, donor_spk, DAA, false, None),
    ];

    let reused = SigHashReusedValuesUnsync::new();
    let sighash = {
        let populated = PopulatedTransaction::new(&tx, entries.clone());
        calc_schnorr_signature_hash(&populated, 0, SIG_HASH_ALL, &reused)
    };
    let message = Message::from_digest_slice(sighash.as_bytes().as_slice()).expect("digest");
    let mut signature = donor.sign_schnorr(message).serialize().to_vec();
    signature.push(SIG_HASH_ALL.to_u8());
    tx.inputs[0].signature_script = sigscript(signature);

    let populated = PopulatedTransaction::new(&tx, entries);
    let covenants = CovenantsContext::from_tx(&populated).map_err(|e| e.to_string())?;
    let cache = Cache::new(1_000);
    let reused = SigHashReusedValuesUnsync::new();
    let utxo = populated.utxo(0).expect("covenant utxo");
    let mut engine = TxScriptEngine::from_transaction_input_with_script_units_limit(
        &populated,
        &tx.inputs[0],
        0,
        utxo,
        EngineCtx::new(&cache)
            .with_reused(&reused)
            .with_covenants_ctx(&covenants),
        EngineFlags {
            covenants_enabled: true,
            ..Default::default()
        },
        tx.inputs[0].compute_commit.allowed_script_units(),
    );
    engine.execute().map_err(|e| e.to_string())
}

#[test]
fn donation_with_successor_at_output_zero_is_accepted() {
    run_donation(Layout::SuccessorFirst).expect("control case must execute");
}

#[test]
fn donation_with_decoy_at_output_zero_is_rejected() {
    assert!(
        run_donation(Layout::DecoyFirst).is_err(),
        "an underfunded authorized successor behind a value-carrying decoy must be rejected"
    );
}

/// Every value-backed v2 policy that reads `tx.outputs[0]` must first bind the
/// authorized successor to output 0, so a future transition cannot silently
/// reintroduce the fixed-index gap.
#[test]
fn every_fixed_index_value_check_is_guarded() {
    for (name, source) in [
        ("CommunityDonationsState", SOURCE),
        (
            "ValidatorStakingState",
            include_str!("../../contracts/silverc/ValidatorStakingState.sil"),
        ),
    ] {
        let mut checked = 0;
        for function in source.split("    function ").skip(1) {
            let body = function.split("\n    }\n").next().unwrap_or(function);
            if let Some(first_output) = body.find("tx.outputs[") {
                checked += 1;
                let guard = body.find("requireAuthorizedSuccessorAtZero();");
                assert!(
                    matches!(guard, Some(position) if position < first_output),
                    "{name}: function {} reads tx.outputs before binding the authorized successor",
                    body.split('(').next().unwrap_or("?")
                );
            }
        }
        assert!(checked > 0, "{name}: no fixed-index value check found");
    }
}

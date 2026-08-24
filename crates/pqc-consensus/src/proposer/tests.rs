// SPDX-License-Identifier: BUSL-1.1
//! Tests for `proposer`.
//!
//! Extracted from `proposer.rs` 2026-05-10. `use super::*;`
//! brings every private item from the parent module into scope.

use ciborium::value::Value;
use pqc_crypto::{sign::StubVerifier, AlgId};
use pqc_mempool::{admission::try_admit, Mempool};
use pqc_state::StateStore;
use pqc_tx::{codec::encode_tx, validate::FeeParams};
use pqc_types::{
    account::{Account, Address},
    block::BlockHash,
    keyset::{allowed_tx, KeyEntry, KeySet, KeyStatus},
    transaction::{MsgType, Transaction},
};

use super::{LocalProposer, LocalProposerConfig};

fn cbor_map(pairs: Vec<(u64, CborVal)>) -> Vec<u8> {
    let entries: Vec<(Value, Value)> = pairs
        .into_iter()
        .map(|(key, value)| {
            let key = Value::Integer(key.into());
            let value = match value {
                CborVal::Int(int) => Value::Integer(int.into()),
                CborVal::Bytes(bytes) => Value::Bytes(bytes),
            };
            (key, value)
        })
        .collect();

    let mut out = Vec::new();
    ciborium::into_writer(&Value::Map(entries), &mut out).unwrap();
    out
}

enum CborVal {
    Int(u64),
    Bytes(Vec<u8>),
}

fn signer_account(address: Address, balance: u128, nonce: u64, alg_id: AlgId) -> Account {
    Account {
        address,
        balance,
        nonce,
        keys: KeySet(vec![KeyEntry {
            alg_id,
            pk_bytes: vec![0u8; 32].into(),
            key_version: 1,
            valid_from_height: 0,
            status: KeyStatus::Active,
            allowed_tx_types: allowed_tx::ALL,
        }]),
        policy_version: 0,
        policy_hash: None,
        verifier_template_id: pqc_types::account::VERIFIER_TEMPLATE_ID_EOA,
        auth_data: Vec::new(),
    }
}

fn transfer_payload(recipient: &Address, amount: u64) -> Vec<u8> {
    cbor_map(vec![
        (1, CborVal::Bytes(recipient.0.to_vec())),
        (2, CborVal::Int(amount)),
    ])
}

fn transfer_tx(
    sender: Address,
    recipient: Address,
    nonce: u64,
    fee: u64,
    fee_tip: u64,
    signature_fill: u8,
) -> Transaction {
    Transaction {
        tx_version: 1,
        chain_id: Vec::new(),
        msg_type: MsgType::TokenTransfer,
        sender,
        nonce,
        fee,
        fee_tip,
        gas_limit: 100_000,
        payload: transfer_payload(&recipient, 100),
        sig_alg_id: AlgId::MlDsa65,
        sig_key_version: 1,
        signature: vec![signature_fill; 3_309],
    }
}

fn admit(pool: &mut Mempool, store: &StateStore, tx: &Transaction) -> [u8; 32] {
    let raw = encode_tx(tx).expect("encode must succeed");
    let verifier = StubVerifier;
    try_admit(pool, raw, store, &verifier, &FeeParams::default())
        .expect("admission must succeed")
        .tx_hash
}

fn proposer() -> LocalProposer {
    LocalProposer::new(
        [0x99; 32],
        LocalProposerConfig {
            assembly: crate::AssemblyConfig::default(),
            initial_prev_hash: BlockHash([0x11; 32]),
        },
    )
}

#[test]
fn build_next_block_is_read_only_until_commit() {
    let sender = Address([0xA1; 32]);
    let recipient = Address([0x11; 32]);

    let mut store = StateStore::new();
    store.insert_account(signer_account(sender.clone(), 10_000, 0, AlgId::MlDsa65));

    let mut pool = Mempool::new();
    let tx = transfer_tx(sender.clone(), recipient, 0, 100, 0, 0x01);
    let tx_hash = admit(&mut pool, &store, &tx);

    let mut proposer = proposer();
    let proposal = proposer
        .build_next_block(&store, &pool, 1_710_000_000)
        .expect("build must succeed");

    assert_eq!(
        store.block_height(),
        0,
        "build must not mutate original state"
    );
    assert!(
        pool.get(&tx_hash).is_some(),
        "build must not evict pending tx"
    );
    assert_eq!(proposal.execution.included.len(), 1);

    let result = proposer
        .commit_block(&mut store, &mut pool, proposal)
        .expect("commit must succeed");

    assert_eq!(result.new_height, 1);
    assert_eq!(store.block_height(), 1);
    assert!(pool.is_empty(), "commit must apply pending eviction");
    assert_eq!(proposer.committed_blocks().len(), 1);
}

#[test]
fn run_once_evicts_included_and_keeps_deferred() {
    let sender_a = Address([0xA1; 32]);
    let sender_b = Address([0xB2; 32]);
    let recipient_a = Address([0x11; 32]);
    let recipient_b = Address([0x22; 32]);

    let mut store = StateStore::new();
    store.insert_account(signer_account(sender_a.clone(), 10_000, 0, AlgId::MlDsa65));
    store.insert_account(signer_account(sender_b.clone(), 10_000, 0, AlgId::MlDsa65));

    let mut pool = Mempool::new();
    let first = transfer_tx(sender_a, recipient_a, 0, 200, 0, 0x01);
    let second = transfer_tx(sender_b, recipient_b, 0, 100, 0, 0x02);

    let first_hash = admit(&mut pool, &store, &first);
    let second_hash = admit(&mut pool, &store, &second);
    let first_bytes = pool.get(&first_hash).unwrap().raw_bytes.len();

    let mut proposer = LocalProposer::new(
        [0x99; 32],
        LocalProposerConfig {
            assembly: crate::AssemblyConfig {
                max_block_bytes: first_bytes,
                fee_params: FeeParams::default(),
                ..crate::AssemblyConfig::default()
            },
            initial_prev_hash: BlockHash([0x11; 32]),
        },
    );

    let result = proposer
        .run_once(&mut store, &mut pool, 1_710_000_000)
        .expect("run_once must succeed");

    assert_eq!(result.included.len(), 1);
    assert_eq!(result.included[0].0, first_hash);
    assert_eq!(result.deferred.len(), 1);
    assert_eq!(result.deferred[0].0, second_hash);
    assert!(
        pool.get(&second_hash).is_some(),
        "deferred tx must remain pending"
    );
}

#[test]
fn run_once_on_empty_mempool_emits_empty_block() {
    let mut store = StateStore::new();
    let mut pool = Mempool::new();
    let mut proposer = proposer();

    let result = proposer
        .run_once(&mut store, &mut pool, 1_710_000_000)
        .expect("empty mempool should still produce an empty block");

    assert!(result.included.is_empty());
    assert!(result.deferred.is_empty());
    assert!(result.skipped.is_empty());
    assert_eq!(result.bytes_used, 0);
    assert_eq!(result.new_height, 1);
    assert_eq!(store.block_height(), 1);
    assert_eq!(proposer.committed_blocks().len(), 1);
}

#[test]
fn run_once_is_deterministic_for_same_inputs() {
    let sender_a = Address([0xA1; 32]);
    let sender_b = Address([0xB2; 32]);
    let recipient_a = Address([0x11; 32]);
    let recipient_b = Address([0x22; 32]);

    let tx_a = transfer_tx(sender_a.clone(), recipient_a, 0, 100, 0, 0x01);
    let tx_b = transfer_tx(sender_b.clone(), recipient_b, 0, 200, 0, 0x02);

    let mut store_1 = StateStore::new();
    let mut store_2 = StateStore::new();
    for store in [&mut store_1, &mut store_2] {
        store.insert_account(signer_account(sender_a.clone(), 10_000, 0, AlgId::MlDsa65));
        store.insert_account(signer_account(sender_b.clone(), 10_000, 0, AlgId::MlDsa65));
    }

    let mut pool_1 = Mempool::new();
    let mut pool_2 = Mempool::new();
    for tx in [&tx_a, &tx_b] {
        admit(&mut pool_1, &store_1, tx);
        admit(&mut pool_2, &store_2, tx);
    }

    let mut proposer_1 = proposer();
    let mut proposer_2 = proposer();

    let result_1 = proposer_1
        .run_once(&mut store_1, &mut pool_1, 1_710_000_000)
        .expect("first run_once must succeed");
    let result_2 = proposer_2
        .run_once(&mut store_2, &mut pool_2, 1_710_000_000)
        .expect("second run_once must succeed");

    assert_eq!(result_1.included, result_2.included);
    assert_eq!(result_1.deferred, result_2.deferred);
    assert_eq!(result_1.bytes_used, result_2.bytes_used);
    assert_eq!(result_1.state_root, result_2.state_root);
    assert_eq!(result_1.tx_root, result_2.tx_root);
    assert_eq!(result_1.block.header.height, result_2.block.header.height);
    assert_eq!(
        result_1.block.header.prev_hash,
        result_2.block.header.prev_hash
    );
    assert_eq!(proposer_1.tip_hash(), proposer_2.tip_hash());
}

#[test]
fn multiple_runs_advance_height_monotonically() {
    let sender = Address([0xA1; 32]);
    let recipient = Address([0x11; 32]);

    let mut store = StateStore::new();
    store.insert_account(signer_account(sender.clone(), 10_000, 0, AlgId::MlDsa65));

    let mut pool = Mempool::new();
    let first = transfer_tx(sender.clone(), recipient.clone(), 0, 100, 0, 0x01);
    admit(&mut pool, &store, &first);

    let mut proposer = proposer();

    let result_1 = proposer
        .run_once(&mut store, &mut pool, 1_710_000_000)
        .expect("first run_once must succeed");
    let first_tip = proposer.tip_hash().clone();

    let second = transfer_tx(sender, recipient, 1, 100, 0, 0x02);
    admit(&mut pool, &store, &second);

    let result_2 = proposer
        .run_once(&mut store, &mut pool, 1_710_000_001)
        .expect("second run_once must succeed");

    assert_eq!(result_1.new_height, 1);
    assert_eq!(result_2.new_height, 2);
    assert_eq!(store.block_height(), 2);
    assert_eq!(result_2.block.header.prev_hash, first_tip);
    assert_ne!(proposer.tip_hash().0, first_tip.0);
    assert_eq!(proposer.committed_blocks().len(), 2);
}

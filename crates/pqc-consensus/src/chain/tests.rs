// SPDX-License-Identifier: BUSL-1.1
//! Tests for `chain`.
//!
//! Extracted from `chain.rs` 2026-05-10. `use super::*;`
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

use crate::{AssemblyConfig, LocalProposer, LocalProposerConfig};

use super::{ChainError, ChainStore};

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

fn admit(pool: &mut Mempool, store: &StateStore, tx: &Transaction) {
    let raw = encode_tx(tx).expect("encode must succeed");
    let verifier = StubVerifier;
    try_admit(pool, raw, store, &verifier, &FeeParams::default()).expect("admission must succeed");
}

fn proposer() -> LocalProposer {
    LocalProposer::new(
        [0x99; 32],
        LocalProposerConfig {
            assembly: AssemblyConfig::default(),
            initial_prev_hash: BlockHash([0x11; 32]),
        },
    )
}

fn chain_store() -> ChainStore {
    ChainStore::new(BlockHash([0x11; 32]))
}

#[test]
fn append_block_tracks_tip_and_supports_lookups() {
    let sender = Address([0xA1; 32]);
    let recipient = Address([0x11; 32]);

    let mut store = StateStore::new();
    store.insert_account(signer_account(sender.clone(), 10_000, 0, AlgId::MlDsa65));

    let mut pool = Mempool::new();
    let mut proposer = proposer();
    let mut chain = chain_store();

    let first = transfer_tx(sender.clone(), recipient.clone(), 0, 100, 0, 0x01);
    admit(&mut pool, &store, &first);
    let result_1 = proposer
        .run_once(&mut store, &mut pool, 1_710_000_000)
        .expect("first run_once must succeed");
    let metadata_1 = chain.append_block(&result_1).expect("append must succeed");

    assert_eq!(chain.height(), 1);
    assert_eq!(chain.tip_hash(), Some(&metadata_1.block_hash));
    assert_eq!(chain.get_block_by_height(1).unwrap().header.height, 1);
    assert_eq!(
        chain.get_metadata_by_hash(&metadata_1.block_hash).unwrap(),
        &metadata_1
    );

    let second = transfer_tx(sender, recipient, 1, 100, 0, 0x02);
    admit(&mut pool, &store, &second);
    let result_2 = proposer
        .run_once(&mut store, &mut pool, 1_710_000_001)
        .expect("second run_once must succeed");
    let metadata_2 = chain.append_block(&result_2).expect("append must succeed");

    assert_eq!(chain.height(), 2);
    assert_eq!(chain.tip_hash(), Some(&metadata_2.block_hash));
    assert_eq!(
        chain.get_block_by_height(2).unwrap().header.prev_hash,
        metadata_1.block_hash
    );
    assert_eq!(
        chain
            .get_block_by_hash(&metadata_2.block_hash)
            .unwrap()
            .header
            .height,
        2
    );

    let ordered_heights: Vec<u64> = chain
        .blocks_in_order()
        .into_iter()
        .map(|stored| stored.metadata.height)
        .collect();
    assert_eq!(ordered_heights, vec![1, 2]);
}

#[test]
fn append_block_rejects_wrong_parent_hash() {
    let sender = Address([0xA1; 32]);
    let recipient = Address([0x11; 32]);

    let mut store = StateStore::new();
    store.insert_account(signer_account(sender.clone(), 10_000, 0, AlgId::MlDsa65));

    let mut pool = Mempool::new();
    let mut proposer = proposer();
    let mut chain = chain_store();

    let first = transfer_tx(sender.clone(), recipient.clone(), 0, 100, 0, 0x01);
    admit(&mut pool, &store, &first);
    let result_1 = proposer
        .run_once(&mut store, &mut pool, 1_710_000_000)
        .expect("first run_once must succeed");
    let metadata_1 = chain
        .append_block(&result_1)
        .expect("first append must succeed");

    let second = transfer_tx(sender, recipient, 1, 100, 0, 0x02);
    admit(&mut pool, &store, &second);
    let mut result_2 = proposer
        .run_once(&mut store, &mut pool, 1_710_000_001)
        .expect("second run_once must succeed");
    result_2.block.header.prev_hash = BlockHash([0xFF; 32]);

    let err = chain.append_block(&result_2).unwrap_err();
    assert_eq!(
        err,
        ChainError::ParentHashMismatch {
            expected: metadata_1.block_hash,
            got: BlockHash([0xFF; 32]),
        }
    );
}

#[test]
fn append_block_rejects_duplicate_hash() {
    let sender = Address([0xA1; 32]);
    let recipient = Address([0x11; 32]);

    let mut store = StateStore::new();
    store.insert_account(signer_account(sender, 10_000, 0, AlgId::MlDsa65));

    let mut pool = Mempool::new();
    let mut proposer = proposer();
    let mut chain = chain_store();

    let first = transfer_tx(Address([0xA1; 32]), recipient, 0, 100, 0, 0x01);
    admit(&mut pool, &store, &first);
    let result = proposer
        .run_once(&mut store, &mut pool, 1_710_000_000)
        .expect("run_once must succeed");

    chain
        .append_block(&result)
        .expect("first append must succeed");
    let err = chain.append_block(&result).unwrap_err();
    assert_eq!(err, ChainError::DuplicateBlockHash);
}

#[test]
fn append_block_rejects_duplicate_height() {
    let sender = Address([0xA1; 32]);
    let recipient = Address([0x11; 32]);

    let mut store = StateStore::new();
    store.insert_account(signer_account(sender, 10_000, 0, AlgId::MlDsa65));

    let mut pool = Mempool::new();
    let mut proposer = proposer();
    let mut chain = chain_store();

    let first = transfer_tx(Address([0xA1; 32]), recipient, 0, 100, 0, 0x01);
    admit(&mut pool, &store, &first);
    let mut result = proposer
        .run_once(&mut store, &mut pool, 1_710_000_000)
        .expect("run_once must succeed");

    chain
        .append_block(&result)
        .expect("first append must succeed");
    result.block.header.timestamp += 1;

    let err = chain.append_block(&result).unwrap_err();
    assert_eq!(err, ChainError::DuplicateBlockHeight(1));
}

#[test]
fn replay_same_sequence_produces_same_chain_metadata() {
    let sender = Address([0xA1; 32]);
    let recipient = Address([0x11; 32]);

    let mut store_1 = StateStore::new();
    let mut store_2 = StateStore::new();
    for store in [&mut store_1, &mut store_2] {
        store.insert_account(signer_account(sender.clone(), 10_000, 0, AlgId::MlDsa65));
    }

    let mut pool_1 = Mempool::new();
    let mut pool_2 = Mempool::new();
    let mut proposer_1 = proposer();
    let mut proposer_2 = proposer();
    let mut chain_1 = chain_store();
    let mut chain_2 = chain_store();

    let first = transfer_tx(sender.clone(), recipient.clone(), 0, 100, 0, 0x01);
    for (pool, store) in [(&mut pool_1, &store_1), (&mut pool_2, &store_2)] {
        admit(pool, store, &first);
    }

    let result_1a = proposer_1
        .run_once(&mut store_1, &mut pool_1, 1_710_000_000)
        .expect("first node run_once must succeed");
    let result_2a = proposer_2
        .run_once(&mut store_2, &mut pool_2, 1_710_000_000)
        .expect("second node run_once must succeed");
    chain_1
        .append_block(&result_1a)
        .expect("first append must succeed");
    chain_2
        .append_block(&result_2a)
        .expect("second append must succeed");

    let second = transfer_tx(sender, recipient, 1, 100, 0, 0x02);
    for (pool, store) in [(&mut pool_1, &store_1), (&mut pool_2, &store_2)] {
        admit(pool, store, &second);
    }

    let result_1b = proposer_1
        .run_once(&mut store_1, &mut pool_1, 1_710_000_001)
        .expect("first node second run_once must succeed");
    let result_2b = proposer_2
        .run_once(&mut store_2, &mut pool_2, 1_710_000_001)
        .expect("second node second run_once must succeed");
    chain_1
        .append_block(&result_1b)
        .expect("first append must succeed");
    chain_2
        .append_block(&result_2b)
        .expect("second append must succeed");

    assert_eq!(chain_1.metadata_in_order(), chain_2.metadata_in_order());
    assert_eq!(chain_1.tip_hash(), chain_2.tip_hash());
    assert_eq!(chain_1.height(), 2);
}

/// ADR-054 test support: rebuild a `StoredBlock` from an existing one
/// with the timestamp shifted by `delta_ns`. The result is a state-
/// equivalent sibling: same `prev_hash`, `state_root`, `tx_root`,
/// `proposer`, `tx_hashes`, `commit_signatures`, but a different
/// `block_hash` (because the header timestamp is folded in).
fn shift_timestamp_sibling(stored: &super::StoredBlock, delta_ns: u64) -> super::StoredBlock {
    use crate::engine::compute_block_hash;
    let mut block = stored.block.clone();
    block.header.timestamp = block.header.timestamp.saturating_add(delta_ns);
    let block_hash = compute_block_hash(&block);
    let mut metadata = stored.metadata.clone();
    metadata.timestamp = block.header.timestamp;
    metadata.block_hash = block_hash;
    super::StoredBlock {
        block,
        metadata,
        included_transactions: stored.included_transactions.clone(),
    }
}

#[test]
fn replace_tip_block_swaps_state_equivalent_sibling() {
    // Build a 1-block chain, then attempt to replace the tip with a
    // sibling that differs only in timestamp. The swap MUST succeed
    // and produce a tip with the new hash; height + state_root +
    // tx_root + prev_hash MUST remain unchanged.
    let sender = Address([0xA1; 32]);
    let recipient = Address([0x11; 32]);
    let mut store = StateStore::new();
    store.insert_account(signer_account(sender.clone(), 10_000, 0, AlgId::MlDsa65));
    let mut pool = Mempool::new();
    let mut proposer = proposer();
    let mut chain = chain_store();
    let tx = transfer_tx(sender, recipient, 0, 100, 0, 0x01);
    admit(&mut pool, &store, &tx);
    let result = proposer
        .run_once(&mut store, &mut pool, 1_710_000_000)
        .expect("run_once must succeed");
    let metadata_a = chain.append_block(&result).expect("append must succeed");
    let original = chain.tip().unwrap().clone();

    let sibling = shift_timestamp_sibling(&original, 2_000_000_000);
    assert_ne!(sibling.metadata.block_hash, metadata_a.block_hash);
    assert_eq!(sibling.metadata.state_root, metadata_a.state_root);
    assert_eq!(sibling.metadata.tx_root, metadata_a.tx_root);
    assert_eq!(sibling.metadata.prev_hash, metadata_a.prev_hash);

    let displaced = chain.replace_tip_block(sibling.clone()).expect("swap ok");
    assert_eq!(displaced.metadata.block_hash, metadata_a.block_hash);
    assert_eq!(chain.tip_hash(), Some(&sibling.metadata.block_hash));
    assert_eq!(chain.height(), 1);
    assert_eq!(
        chain.get_block_by_height(1).unwrap().header.timestamp,
        sibling.block.header.timestamp
    );
    // by_hash must no longer contain the replaced variant.
    assert!(chain.get_block_by_hash(&metadata_a.block_hash).is_none());
    assert!(chain
        .get_block_by_hash(&sibling.metadata.block_hash)
        .is_some());
}

#[test]
fn replace_tip_block_rejects_state_divergent_candidate() {
    // A candidate with a different `state_root` is NOT a sibling — it
    // is a competing-history block. The swap MUST refuse and the
    // chain state MUST remain untouched.
    let sender = Address([0xA1; 32]);
    let recipient = Address([0x11; 32]);
    let mut store = StateStore::new();
    store.insert_account(signer_account(sender.clone(), 10_000, 0, AlgId::MlDsa65));
    let mut pool = Mempool::new();
    let mut proposer = proposer();
    let mut chain = chain_store();
    let tx = transfer_tx(sender, recipient, 0, 100, 0, 0x01);
    admit(&mut pool, &store, &tx);
    let result = proposer
        .run_once(&mut store, &mut pool, 1_710_000_000)
        .expect("run_once must succeed");
    chain.append_block(&result).expect("append ok");
    let original = chain.tip().unwrap().clone();

    // Synthesize a candidate with a tampered state_root. Recompute
    // the block_hash so it is internally consistent.
    let mut tampered_block = original.block.clone();
    tampered_block.header.state_root = BlockHash([0xBB; 32]);
    tampered_block.header.timestamp += 2_000_000_000;
    let tampered_hash = crate::engine::compute_block_hash(&tampered_block);
    let mut tampered_metadata = original.metadata.clone();
    tampered_metadata.state_root = BlockHash([0xBB; 32]);
    tampered_metadata.timestamp = tampered_block.header.timestamp;
    tampered_metadata.block_hash = tampered_hash.clone();
    let tampered = super::StoredBlock {
        block: tampered_block,
        metadata: tampered_metadata,
        included_transactions: original.included_transactions.clone(),
    };

    let err = chain.replace_tip_block(tampered).unwrap_err();
    assert!(matches!(
        err,
        ChainError::SiblingStateDivergence {
            field: "state_root",
            ..
        }
    ));
    // Chain unchanged.
    assert_eq!(chain.tip_hash(), Some(&original.metadata.block_hash));
}

#[test]
fn replace_tip_block_rejects_duplicate_hash_collision() {
    let sender = Address([0xA1; 32]);
    let recipient = Address([0x11; 32]);
    let mut store = StateStore::new();
    store.insert_account(signer_account(sender.clone(), 10_000, 0, AlgId::MlDsa65));
    let mut pool = Mempool::new();
    let mut proposer = proposer();
    let mut chain = chain_store();
    let tx = transfer_tx(sender, recipient, 0, 100, 0, 0x01);
    admit(&mut pool, &store, &tx);
    let result = proposer
        .run_once(&mut store, &mut pool, 1_710_000_000)
        .expect("run_once must succeed");
    chain.append_block(&result).expect("append ok");
    let original = chain.tip().unwrap().clone();

    let err = chain.replace_tip_block(original.clone()).unwrap_err();
    assert_eq!(err, ChainError::SiblingHashCollision);
}

#[test]
fn replace_tip_block_rejects_empty_chain() {
    let mut chain = chain_store();
    // Build a synthetic stored block (any shape — gate fires before structural checks).
    let mut store = StateStore::new();
    store.insert_account(signer_account(
        Address([0xA1; 32]),
        10_000,
        0,
        AlgId::MlDsa65,
    ));
    let mut pool = Mempool::new();
    let mut proposer = proposer();
    let tx = transfer_tx(Address([0xA1; 32]), Address([0x11; 32]), 0, 100, 0, 0x01);
    admit(&mut pool, &store, &tx);
    let result = proposer
        .run_once(&mut store, &mut pool, 1_710_000_000)
        .expect("run_once must succeed");
    // Manufacture a StoredBlock without going through append.
    let block_hash = crate::engine::compute_block_hash(&result.block);
    let stored = super::StoredBlock {
        metadata: super::BlockMetadata {
            block_hash,
            height: result.block.header.height,
            prev_hash: result.block.header.prev_hash.clone(),
            state_root: result.state_root.clone(),
            tx_root: result.tx_root.clone(),
            timestamp: result.block.header.timestamp,
            bytes_used: result.bytes_used,
            included_count: result.included.len(),
            deferred_count: result.deferred.len(),
            skipped_count: result.skipped.len(),
            vc_budget_consumed: result.vc_budget_consumed,
        },
        block: result.block.clone(),
        included_transactions: result.included_transactions.clone(),
    };
    let err = chain.replace_tip_block(stored).unwrap_err();
    assert_eq!(err, ChainError::ReplaceEmptyChain);
}

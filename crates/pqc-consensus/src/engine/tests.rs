// SPDX-License-Identifier: BUSL-1.1
//! Tests for `engine`.
//!
//! Extracted from `engine.rs` 2026-05-10. `use super::*;`
//! brings every private item from the parent module into scope.

use pqc_crypto::{sign::StubVerifier, AlgId};
use pqc_mempool::{admission::try_admit, Mempool};
use pqc_state::StateStore;
use pqc_tx::{codec::encode_tx, validate::FeeParams};
use pqc_types::account::Address;

use super::*;
use crate::test_support::{admit, signer_account, transfer_tx, vault_create_tx};

fn base_context(height: u64) -> AssemblyContext {
    AssemblyContext {
        height,
        prev_hash: BlockHash([0x11; 32]),
        timestamp: 1_710_000_000,
        proposer: vec![0x99; 32],
    }
}

#[test]
fn assembler_orders_transactions_deterministically() {
    let sender_a = Address([0xA1; 32]);
    let sender_b = Address([0xB2; 32]);
    let sender_c = Address([0xC3; 32]);
    let recipient_a = Address([0x11; 32]);
    let recipient_b = Address([0x22; 32]);
    let recipient_c = Address([0x33; 32]);

    let mut store = StateStore::new();
    store.insert_account(signer_account(sender_a.clone(), 10_000, 0, AlgId::MlDsa65));
    store.insert_account(signer_account(sender_b.clone(), 10_000, 0, AlgId::MlDsa65));
    store.insert_account(signer_account(sender_c.clone(), 10_000, 0, AlgId::MlDsa65));

    let mut pool = Mempool::new();
    let low = transfer_tx(sender_a, recipient_a, 0, 100, 0, 0x01, AlgId::MlDsa65);
    let high = transfer_tx(sender_b, recipient_b, 0, 300, 0, 0x02, AlgId::MlDsa65);
    let high_tip = transfer_tx(sender_c, recipient_c, 0, 300, 10, 0x03, AlgId::MlDsa65);

    let low_hash = admit(&mut pool, &store, &low);
    let high_hash = admit(&mut pool, &store, &high);
    let high_tip_hash = admit(&mut pool, &store, &high_tip);

    let result = assemble_block(
        &mut store,
        &mut pool,
        &base_context(1),
        AssemblyConfig::default(),
    )
    .expect("assembly must succeed");

    let ordered: Vec<[u8; 32]> = result.included.iter().map(|hash| hash.0).collect();
    assert_eq!(ordered, vec![high_tip_hash, high_hash, low_hash]);
    assert_eq!(store.block_height(), 1);
    assert!(pool.is_empty(), "included transactions must be evicted");
}

#[test]
fn assembler_applies_valid_transactions_and_skips_conflicting_ones() {
    let sender_a = Address([0xA1; 32]);
    let sender_b = Address([0xB2; 32]);
    let genesis_pk = vec![0xAB; 1_952];

    let mut store = StateStore::new();
    store.insert_account(signer_account(sender_a.clone(), 10_000, 0, AlgId::MlDsa65));
    store.insert_account(signer_account(sender_b.clone(), 10_000, 0, AlgId::MlDsa65));

    let mut pool = Mempool::new();
    let first = vault_create_tx(sender_a, 0, 500, 0x01, genesis_pk.clone());
    let second = vault_create_tx(sender_b, 0, 100, 0x02, genesis_pk.clone());

    let first_hash = admit(&mut pool, &store, &first);
    let second_hash = admit(&mut pool, &store, &second);

    let result = assemble_block(
        &mut store,
        &mut pool,
        &base_context(1),
        AssemblyConfig::default(),
    )
    .expect("assembly must succeed");

    assert_eq!(
        result.included.len(),
        1,
        "only the first vault_create should be included"
    );
    assert_eq!(result.included[0].0, first_hash);
    assert_eq!(
        result.skipped,
        vec![SkippedTx {
            tx_hash: TxHash(second_hash),
            reason: SkipReason::ApplyFailed(ApplyError::AccountExists),
        }]
    );
    assert!(
        pool.is_empty(),
        "included and invalidated entries must be evicted"
    );
    assert_ne!(
        result.state_root.0, [0u8; 32],
        "state root must change after inclusion"
    );
}

#[test]
fn assembler_respects_block_byte_limit_and_leaves_overflow_pending() {
    let sender_a = Address([0xA1; 32]);
    let sender_b = Address([0xB2; 32]);
    let recipient_a = Address([0x11; 32]);
    let recipient_b = Address([0x22; 32]);

    let mut store = StateStore::new();
    store.insert_account(signer_account(sender_a.clone(), 10_000, 0, AlgId::MlDsa65));
    store.insert_account(signer_account(sender_b.clone(), 10_000, 0, AlgId::MlDsa65));

    let mut pool = Mempool::new();
    let first = transfer_tx(sender_a, recipient_a, 0, 200, 0, 0x01, AlgId::MlDsa65);
    let second = transfer_tx(sender_b, recipient_b, 0, 100, 0, 0x02, AlgId::MlDsa65);

    let first_hash = admit(&mut pool, &store, &first);
    let second_hash = admit(&mut pool, &store, &second);
    let first_bytes = pool
        .get(&first_hash)
        .expect("first tx must be pending")
        .raw_bytes
        .len();

    let result = assemble_block(
        &mut store,
        &mut pool,
        &base_context(1),
        AssemblyConfig {
            max_block_bytes: first_bytes,
            fee_params: FeeParams::default(),
            ..AssemblyConfig::default()
        },
    )
    .expect("assembly must succeed");

    assert_eq!(result.included.len(), 1);
    assert_eq!(result.included[0].0, first_hash);
    assert_eq!(result.deferred, vec![TxHash(second_hash)]);
    assert!(
        pool.get(&second_hash).is_some(),
        "overflow tx must remain pending"
    );
}

#[test]
fn assembler_resets_vc_admission_budget_for_next_block_interval() {
    let sender = Address([0xA1; 32]);
    let recipient = Address([0x11; 32]);

    let mut store = StateStore::new();
    store.insert_account(signer_account(
        sender.clone(),
        10_000,
        0,
        AlgId::SlhDsaSha2128s,
    ));

    let mut pool = Mempool::new();
    pool.vc_per_block_cap = 1;

    let first = transfer_tx(
        sender.clone(),
        recipient.clone(),
        0,
        100,
        0,
        0x01,
        AlgId::SlhDsaSha2128s,
    );
    admit(&mut pool, &store, &first);

    assemble_block(
        &mut store,
        &mut pool,
        &base_context(1),
        AssemblyConfig::default(),
    )
    .expect("assembly must succeed");

    let second = transfer_tx(sender, recipient, 1, 100, 0, 0x02, AlgId::SlhDsaSha2128s);

    let raw = encode_tx(&second).expect("encode must succeed");
    let verifier = StubVerifier;
    let admit_again = try_admit(&mut pool, raw, &store, &verifier, &FeeParams::default());
    assert!(admit_again.is_ok(), "V-C cap must reset after assembly");
}

#[test]
fn assembler_is_deterministic_across_input_permutations() {
    let sender_a = Address([0xA1; 32]);
    let sender_b = Address([0xB2; 32]);
    let sender_c = Address([0xC3; 32]);
    let recipient_a = Address([0x11; 32]);
    let recipient_b = Address([0x22; 32]);
    let recipient_c = Address([0x33; 32]);

    let tx_a = transfer_tx(
        sender_a.clone(),
        recipient_a,
        0,
        100,
        0,
        0x01,
        AlgId::MlDsa65,
    );
    let tx_b = transfer_tx(
        sender_b.clone(),
        recipient_b,
        0,
        300,
        0,
        0x02,
        AlgId::MlDsa65,
    );
    let tx_c = transfer_tx(
        sender_c.clone(),
        recipient_c,
        0,
        300,
        10,
        0x03,
        AlgId::MlDsa65,
    );

    let mut store_1 = StateStore::new();
    let mut store_2 = StateStore::new();
    for store in [&mut store_1, &mut store_2] {
        store.insert_account(signer_account(sender_a.clone(), 10_000, 0, AlgId::MlDsa65));
        store.insert_account(signer_account(sender_b.clone(), 10_000, 0, AlgId::MlDsa65));
        store.insert_account(signer_account(sender_c.clone(), 10_000, 0, AlgId::MlDsa65));
    }

    let mut pool_1 = Mempool::new();
    let mut pool_2 = Mempool::new();

    for tx in [&tx_a, &tx_b, &tx_c] {
        admit(&mut pool_1, &store_1, tx);
    }
    for tx in [&tx_c, &tx_a, &tx_b] {
        admit(&mut pool_2, &store_2, tx);
    }

    let result_1 = assemble_block(
        &mut store_1,
        &mut pool_1,
        &base_context(1),
        AssemblyConfig::default(),
    )
    .expect("first assembly must succeed");
    let result_2 = assemble_block(
        &mut store_2,
        &mut pool_2,
        &base_context(1),
        AssemblyConfig::default(),
    )
    .expect("second assembly must succeed");

    assert_eq!(
        result_1
            .included
            .iter()
            .map(|hash| hash.0)
            .collect::<Vec<_>>(),
        result_2
            .included
            .iter()
            .map(|hash| hash.0)
            .collect::<Vec<_>>(),
    );
    assert_eq!(result_1.state_root, result_2.state_root);
    assert_eq!(result_1.tx_root, result_2.tx_root);
    assert_eq!(result_1.bytes_used, result_2.bytes_used);
}

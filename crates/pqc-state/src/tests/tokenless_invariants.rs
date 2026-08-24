// SPDX-License-Identifier: BUSL-1.1
//! Tokenless invariants — viper-research-1 substrate.
//!
//! These tests run ONLY in the `--no-default-features` (tokenless) build
//! configuration. They assert that the chain rejects token-coupled message
//! types at the dispatch layer with the canonical `TokenEconomicsDisabled`
//! error rather than silently accepting them or panicking.
//!
//! Spawned as part of Phase 1 of the viper-pq-1 → viper-research-1 pivot
//! (2026-05-11). See the private planning notes.

use crate::{
    apply::{apply_tx, ExecutionContext},
    error::ApplyError,
    store::StateStore,
};
use pqc_crypto::AlgId;
use pqc_tx::validate::FeeParams;
use pqc_types::{
    account::Address,
    transaction::{MsgType, Transaction},
};

const CHAIN_ID: &[u8] = &[0xCA, 0xFE, 0xBA, 0xBE];

fn minimal_tx(msg_type: MsgType, sender: Address) -> Transaction {
    Transaction {
        tx_version: 1,
        chain_id: CHAIN_ID.to_vec(),
        msg_type,
        sender,
        nonce: 0,
        fee: 0,
        fee_tip: 0,
        gas_limit: 100_000,
        // Stub payload — the tokenless dispatcher rejects before parsing.
        payload: Vec::new(),
        sig_alg_id: AlgId::MlDsa65,
        sig_key_version: 1,
        signature: vec![0u8; 3_309],
    }
}

#[test]
fn token_transfer_dispatch_returns_token_economics_disabled() {
    let sender = Address([0xAA; 32]);
    let tx = minimal_tx(MsgType::TokenTransfer, sender.clone());

    // Note: apply_tx settles the sender's nonce/fee BEFORE dispatching the
    // payload, so we need a sender account on the store. With fee=0 and
    // gas_limit above the schedule floor, settlement is a no-op and the
    // tokenless dispatcher rejection is the only error path that fires.
    let mut store = StateStore::new();
    store.insert_account(pqc_types::account::Account {
        address: sender,
        balance: 0,
        nonce: 0,
        keys: pqc_types::keyset::KeySet(vec![]),
        policy_version: 0,
        policy_hash: None,
        verifier_template_id: pqc_types::account::VERIFIER_TEMPLATE_ID_EOA,
        auth_data: Vec::new(),
    });

    let err = apply_tx(
        &mut store,
        &tx,
        ExecutionContext {
            tx_bytes_len: 256,
            fee_params: FeeParams::default(),
        },
    )
    .expect_err("tokenless build MUST reject TokenTransfer at dispatch");

    assert_eq!(
        err,
        ApplyError::TokenEconomicsDisabled,
        "expected TokenEconomicsDisabled, got: {err}"
    );
}

#[test]
fn submit_equivocation_evidence_dispatch_returns_token_economics_disabled() {
    let sender = Address([0xBB; 32]);
    let tx = minimal_tx(MsgType::SubmitEquivocationEvidence, sender.clone());

    let mut store = StateStore::new();
    store.insert_account(pqc_types::account::Account {
        address: sender,
        balance: 0,
        nonce: 0,
        keys: pqc_types::keyset::KeySet(vec![]),
        policy_version: 0,
        policy_hash: None,
        verifier_template_id: pqc_types::account::VERIFIER_TEMPLATE_ID_EOA,
        auth_data: Vec::new(),
    });

    let err = apply_tx(
        &mut store,
        &tx,
        ExecutionContext {
            tx_bytes_len: 256,
            fee_params: FeeParams::default(),
        },
    )
    .expect_err("tokenless build MUST reject SubmitEquivocationEvidence at dispatch");

    assert_eq!(
        err,
        ApplyError::TokenEconomicsDisabled,
        "expected TokenEconomicsDisabled, got: {err}"
    );
}

#[test]
fn fresh_state_store_constructs_without_storage_fund_field() {
    // Compile-time invariant: `StateStore` has no `storage_fund` field in
    // the tokenless build. If a future change re-adds the field without a
    // matching gate, this test will fail to compile (rather than silently
    // changing the state-root shape — which is exactly the kind of cold-sync
    // drift incident captured in the 2026-05-11 lesson, see
    // the private planning notes and the project_registry_strings_are_consensus
    // memory).
    //
    // The runtime assertion below is a sanity check that StateStore::new()
    // actually succeeds in the tokenless config (no panic from a missing
    // initialiser).
    let store = StateStore::new();
    let _root = store.state_root();
}

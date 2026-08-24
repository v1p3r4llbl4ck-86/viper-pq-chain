// SPDX-License-Identifier: BUSL-1.1
//! Integration tests for the first vertical slice: validate → apply.
//!
//! These tests exercise the full path for vault_create and token_transfer:
//! encode payload → build tx → validate → apply → assert state.

// Some GAS_* constants are referenced only from the gated `token_transfer`
// submodule; in --no-default-features builds they appear unused here.
#[cfg_attr(not(feature = "token_economics"), allow(unused_imports))]
use crate::{
    apply::consensus_rotate::ROTATION_WINDOW,
    apply::{apply_tx, ExecutionContext, ExecutionStatus},
    gas_schedule::{
        GAS_ATTESTATION_CREATE, GAS_ATTESTATION_REVOKE, GAS_CONSENSUS_KEY_ROTATE,
        GAS_GOVERNANCE_PROPOSAL, GAS_KEY_ADD, GAS_KEY_REVOKE, GAS_KEY_ROTATE, GAS_PROOF_ANCHOR,
        GAS_TOKEN_TRANSFER, GAS_VAULT_POLICY_UPDATE,
    },
    store::StateStore,
};
use ciborium::value::Value;
use pqc_crypto::sign::StubVerifier;
use pqc_crypto::{AlgId, Lifecycle};
use pqc_tx::{
    codec::encode_tx,
    compute_tx_hash,
    validate::{validate_tx, FeeParams, ValidationContext},
};
#[cfg(feature = "token_economics")]
use pqc_types::governance::GovernanceProposalType;
use pqc_types::{
    account::{Account, Address},
    attestation::{AttestationId, AttestationStatus},
    churn::ChurnConfig,
    keyset::{allowed_tx, KeyEntry, KeySet, KeyStatus},
    proof_anchor::AnchorId,
    transaction::{MsgType, Transaction},
    ForkDigest,
};

const CHAIN_ID: &[u8] = &[0xCA, 0xFE, 0xBA, 0xBE];
const CURRENT_HEIGHT: u64 = 10;

static TEST_FORK_DIGEST: std::sync::LazyLock<ForkDigest> =
    std::sync::LazyLock::new(ForkDigest::viper_research_1);

fn active_lifecycle(alg: AlgId) -> Option<Lifecycle> {
    match alg {
        AlgId::MlDsa44
        | AlgId::MlDsa65
        | AlgId::MlDsa87
        | AlgId::FnDsaPadded512
        | AlgId::SlhDsaSha2128s => Some(Lifecycle::Active),
        _ => None,
    }
}

fn zero_min_fee(alg: AlgId) -> Option<u64> {
    active_lifecycle(alg).map(|_| 0)
}

/// Encode a CBOR map payload from (key, value) integer/bytes pairs.
fn cbor_map(pairs: Vec<(u64, CborVal)>) -> Vec<u8> {
    let entries: Vec<(Value, Value)> = pairs
        .into_iter()
        .map(|(k, v)| {
            let key = Value::Integer(k.into());
            let val = match v {
                CborVal::Int(i) => Value::Integer(i.into()),
                CborVal::Bytes(b) => Value::Bytes(b),
            };
            (key, val)
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

fn creator_account(creator_addr: Address, current_nonce: u64) -> Account {
    Account {
        address: creator_addr.clone(),
        balance: 1_000_000,
        nonce: current_nonce,
        keys: KeySet(vec![KeyEntry {
            alg_id: AlgId::MlDsa65,
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

fn exec_ctx(tx: &Transaction) -> ExecutionContext {
    ExecutionContext {
        tx_bytes_len: encode_tx(tx).unwrap().len(),
        fee_params: FeeParams::default(),
    }
}

fn attestation_payload(
    subject: [u8; 32],
    attestation_type: u16,
    content_hash: [u8; 32],
    schema_id: [u8; 32],
    metadata_hash: Option<[u8; 32]>,
    expires_at_height: Option<u64>,
) -> Vec<u8> {
    let mut pairs = vec![
        (1, CborVal::Bytes(subject.to_vec())),
        (2, CborVal::Int(attestation_type as u64)),
        (3, CborVal::Bytes(content_hash.to_vec())),
        (4, CborVal::Bytes(schema_id.to_vec())),
    ];

    if let Some(metadata_hash) = metadata_hash {
        pairs.push((5, CborVal::Bytes(metadata_hash.to_vec())));
    }
    if let Some(expires_at_height) = expires_at_height {
        pairs.push((6, CborVal::Int(expires_at_height)));
    }

    cbor_map(pairs)
}

fn attestation_revoke_payload(
    attestation_id: &AttestationId,
    revocation_reason_hash: Option<[u8; 32]>,
) -> Vec<u8> {
    let mut pairs = vec![(1, CborVal::Bytes(attestation_id.0.to_vec()))];
    if let Some(hash) = revocation_reason_hash {
        pairs.push((2, CborVal::Bytes(hash.to_vec())));
    }
    cbor_map(pairs)
}

// Payload helpers used only by the gated `token_transfer` submodule.
#[cfg(feature = "token_economics")]
fn key_add_payload(
    alg_id: AlgId,
    pk_bytes: Vec<u8>,
    key_version: u32,
    valid_from_height: u64,
    allowed_tx_types: u32,
) -> Vec<u8> {
    cbor_map(vec![
        (1, CborVal::Int(alg_id.as_u16() as u64)),
        (2, CborVal::Bytes(pk_bytes)),
        (3, CborVal::Int(key_version as u64)),
        (4, CborVal::Int(valid_from_height)),
        (5, CborVal::Int(allowed_tx_types as u64)),
    ])
}

#[cfg(feature = "token_economics")]
fn key_rotate_payload(
    new_alg_id: AlgId,
    new_pk_bytes: Vec<u8>,
    new_key_version: u32,
    new_valid_from_height: u64,
    new_allowed_tx_types: u32,
    revoke_key_version: u32,
) -> Vec<u8> {
    cbor_map(vec![
        (1, CborVal::Int(new_alg_id.as_u16() as u64)),
        (2, CborVal::Bytes(new_pk_bytes)),
        (3, CborVal::Int(new_key_version as u64)),
        (4, CborVal::Int(new_valid_from_height)),
        (5, CborVal::Int(new_allowed_tx_types as u64)),
        (6, CborVal::Int(revoke_key_version as u64)),
    ])
}

#[cfg(feature = "token_economics")]
fn key_revoke_payload(target_key_version: u32) -> Vec<u8> {
    cbor_map(vec![(1, CborVal::Int(target_key_version as u64))])
}

#[cfg(feature = "token_economics")]
fn governance_registry_update_payload(
    alg_id: AlgId,
    target_lifecycle_status: Option<u8>,
    new_min_fee: Option<u64>,
    rationale_fill: u8,
) -> Vec<u8> {
    let mut pairs = vec![
        (
            1,
            CborVal::Int(GovernanceProposalType::RegistryUpdate.as_u8() as u64),
        ),
        (2, CborVal::Int(alg_id.as_u16() as u64)),
        (6, CborVal::Bytes(vec![rationale_fill; 32])),
        (100, CborVal::Int(1)),
        (101, CborVal::Int(1)),
        (102, CborVal::Int(1)),
    ];

    if let Some(target_lifecycle_status) = target_lifecycle_status {
        pairs.push((3, CborVal::Int(target_lifecycle_status as u64)));
    }
    if let Some(new_min_fee) = new_min_fee {
        pairs.push((4, CborVal::Int(new_min_fee)));
    }

    cbor_map(pairs)
}

// ── vault_create tests ────────────────────────────────────────────────────────

#[test]
fn vault_create_creates_account_with_genesis_key() {
    let creator_addr = Address([0xCC; 32]);
    let genesis_pk = vec![0u8; 1_952]; // ML-DSA-65 pk_size

    let payload = cbor_map(vec![
        (1, CborVal::Int(AlgId::MlDsa65.as_u16() as u64)),
        (2, CborVal::Bytes(genesis_pk.clone())),
        (3, CborVal::Int(allowed_tx::ALL as u64)),
        (4, CborVal::Int(0)), // valid_from_height=0: key is Active immediately
    ]);

    let tx = Transaction {
        tx_version: 1,
        chain_id: CHAIN_ID.to_vec(),
        msg_type: MsgType::VaultCreate,
        sender: creator_addr.clone(),
        nonce: 0,
        fee: 0,
        fee_tip: 0,
        gas_limit: 500_000,
        payload,
        sig_alg_id: AlgId::MlDsa65,
        sig_key_version: 1,
        signature: vec![0u8; 3_309],
    };

    let mut store = StateStore::new();
    store.set_chain_id(CHAIN_ID.to_vec());
    store.insert_account(creator_account(creator_addr.clone(), 0));

    let creator = store.get_account(&creator_addr).unwrap().clone();
    let raw = encode_tx(&tx).unwrap();
    let verifier = StubVerifier;
    let ctx = ValidationContext {
        chain_id: CHAIN_ID,
        fork_digest: &TEST_FORK_DIGEST,
        current_height: CURRENT_HEIGHT,
        sender_account: Some(&creator),
        fee_params: FeeParams::default(),
        verifier: &verifier,
        alg_lifecycle: &active_lifecycle,
        alg_min_fee: &zero_min_fee,
    };

    validate_tx(&tx, &raw, &ctx).expect("validation must pass");
    let result = apply_tx(&mut store, &tx, exec_ctx(&tx)).expect("apply must succeed");
    assert_eq!(result.status, ExecutionStatus::Applied);

    let new_address = Address(pqc_crypto::derive_address(
        CHAIN_ID,
        AlgId::MlDsa65,
        &genesis_pk,
    ));
    let new_account = store
        .get_account(&new_address)
        .expect("new account must exist after vault_create");

    assert_eq!(new_account.balance, 0);
    assert_eq!(new_account.nonce, 0);
    assert_eq!(new_account.keys.0.len(), 1);
    assert_eq!(new_account.keys.0[0].alg_id, AlgId::MlDsa65);
    assert_eq!(new_account.keys.0[0].key_version, 1);
    assert_eq!(new_account.keys.0[0].allowed_tx_types, allowed_tx::ALL);
}

#[test]
fn vault_create_rejects_duplicate_address() {
    let creator_addr = Address([0xCC; 32]);
    let genesis_pk = vec![0u8; 1_952];

    let payload = cbor_map(vec![
        (1, CborVal::Int(AlgId::MlDsa65.as_u16() as u64)),
        (2, CborVal::Bytes(genesis_pk.clone())),
        (3, CborVal::Int(allowed_tx::ALL as u64)),
        (4, CborVal::Int(0)), // valid_from_height=0: key is Active immediately
    ]);

    let tx = Transaction {
        tx_version: 1,
        chain_id: CHAIN_ID.to_vec(),
        msg_type: MsgType::VaultCreate,
        sender: creator_addr.clone(),
        nonce: 0,
        fee: 0,
        fee_tip: 0,
        gas_limit: 500_000,
        payload,
        sig_alg_id: AlgId::MlDsa65,
        sig_key_version: 1,
        signature: vec![0u8; 3_309],
    };

    let mut store = StateStore::new();
    store.insert_account(creator_account(creator_addr.clone(), 0));

    apply_tx(&mut store, &tx, exec_ctx(&tx)).expect("first apply must succeed");

    // Second apply must fail: address already exists
    let err = apply_tx(&mut store, &tx, exec_ctx(&tx)).unwrap_err();
    assert!(
        matches!(err, crate::error::ApplyError::AccountExists),
        "got: {err}"
    );
}

#[cfg(feature = "token_economics")]
mod token_transfer;

#[cfg(not(feature = "token_economics"))]
mod tokenless_invariants;

// ── Fee distribution accounting tests ────────────────────────────────────────

#[test]
fn distribute_block_fees_credits_existing_proposer() {
    use crate::apply::distribute_block_fees;

    let proposer_addr = Address([0xEE; 32]);
    let mut store = StateStore::new();
    let mut proposer = creator_account(proposer_addr.clone(), 0);
    proposer.balance = 1_000;
    store.insert_account(proposer);

    distribute_block_fees(
        &mut store,
        &proposer_addr,
        500,
        &[],
        &FeeDistributionParams::default(),
    );

    let acc = store.get_account(&proposer_addr).unwrap();
    assert_eq!(acc.balance, 1_500);
    assert_eq!(acc.nonce, 0, "distribute_block_fees must not touch nonce");
}

#[test]
fn distribute_block_fees_creates_proposer_account_when_absent() {
    use crate::apply::distribute_block_fees;

    let proposer_addr = Address([0xEE; 32]);
    let mut store = StateStore::new();

    assert!(store.get_account(&proposer_addr).is_none());
    distribute_block_fees(
        &mut store,
        &proposer_addr,
        14_215,
        &[],
        &FeeDistributionParams::default(),
    );

    let acc = store.get_account(&proposer_addr).unwrap();
    assert_eq!(acc.balance, 14_215);
    assert_eq!(acc.nonce, 0);
    assert!(
        acc.keys.0.is_empty(),
        "implicitly created proposer account has empty KeySet"
    );
}

#[test]
fn distribute_block_fees_is_noop_for_zero_fees() {
    use crate::apply::distribute_block_fees;

    let proposer_addr = Address([0xEE; 32]);
    let mut store = StateStore::new();

    // No account, zero fees — must not create account
    distribute_block_fees(
        &mut store,
        &proposer_addr,
        0,
        &[],
        &FeeDistributionParams::default(),
    );
    assert!(
        store.get_account(&proposer_addr).is_none(),
        "zero-fee distribute must not create account"
    );

    // Existing account, zero fees — balance unchanged
    let mut proposer = creator_account(proposer_addr.clone(), 0);
    proposer.balance = 100;
    store.insert_account(proposer);
    distribute_block_fees(
        &mut store,
        &proposer_addr,
        0,
        &[],
        &FeeDistributionParams::default(),
    );
    assert_eq!(store.get_account(&proposer_addr).unwrap().balance, 100);
}

#[cfg(feature = "token_economics")]
#[test]
fn fee_distribution_accounting_invariant_sender_debit_equals_proposer_credit() {
    // For a single token_transfer: total deducted from sender = fee_charged + fee_tip
    // must equal the credit received by proposer.
    use crate::apply::distribute_block_fees;

    let sender_addr = Address([0xAA; 32]);
    let recipient_addr = Address([0xBB; 32]);
    let proposer_addr = Address([0xCC; 32]);

    let payload = transfer_payload(&recipient_addr, 100);
    let fee = 500u64;
    let tip = 50u64;
    let tx = Transaction {
        tx_version: 1,
        chain_id: CHAIN_ID.to_vec(),
        msg_type: MsgType::TokenTransfer,
        sender: sender_addr.clone(),
        nonce: 0,
        fee,
        fee_tip: tip,
        gas_limit: GAS_TOKEN_TRANSFER,
        payload,
        sig_alg_id: AlgId::MlDsa65,
        sig_key_version: 1,
        signature: vec![0u8; 3_309],
    };

    let mut store = StateStore::new();
    let mut sender = creator_account(sender_addr.clone(), 0);
    sender.balance = 10_000;
    store.insert_account(sender);
    let sender_balance_before = store.get_account(&sender_addr).unwrap().balance;

    let raw = encode_tx(&tx).unwrap();
    let result = apply_tx(
        &mut store,
        &tx,
        ExecutionContext {
            tx_bytes_len: raw.len(),
            fee_params: FeeParams {
                base_fee: 100,
                ..FeeParams::default()
            },
        },
    )
    .unwrap();

    let total_deducted = u128::from(result.fee_charged) + u128::from(tip);
    distribute_block_fees(
        &mut store,
        &proposer_addr,
        total_deducted,
        &[],
        &FeeDistributionParams::default(),
    );

    let sender_balance_after = store.get_account(&sender_addr).unwrap().balance;
    let proposer_balance = store.get_account(&proposer_addr).unwrap().balance;

    // Sender debit = fee_charged + fee_tip
    let sender_debit = sender_balance_before - sender_balance_after - 100u128; // subtract the 100 transferred to recipient
    assert_eq!(
        sender_debit, total_deducted,
        "sender_debit must equal proposer_credit"
    );
    assert_eq!(
        proposer_balance, total_deducted,
        "proposer received exactly the collected fees"
    );
}

#[test]
fn out_of_gas_fees_go_to_proposer() {
    use crate::apply::distribute_block_fees;

    let sender_addr = Address([0xAA; 32]);
    let recipient_addr = Address([0xBB; 32]);
    let proposer_addr = Address([0xCC; 32]);

    let payload = transfer_payload(&recipient_addr, 100);
    let fee = 300u64;
    let tip = 7u64;
    let tx = Transaction {
        tx_version: 1,
        chain_id: CHAIN_ID.to_vec(),
        msg_type: MsgType::TokenTransfer,
        sender: sender_addr.clone(),
        nonce: 0,
        fee,
        fee_tip: tip,
        gas_limit: GAS_TOKEN_TRANSFER - 1, // below scheduled gas → RevertedOutOfGas
        payload,
        sig_alg_id: AlgId::MlDsa65,
        sig_key_version: 1,
        signature: vec![0u8; 3_309],
    };

    let mut store = StateStore::new();
    let mut sender = creator_account(sender_addr.clone(), 0);
    sender.balance = 10_000;
    store.insert_account(sender);

    let raw = encode_tx(&tx).unwrap();
    let result = apply_tx(
        &mut store,
        &tx,
        ExecutionContext {
            tx_bytes_len: raw.len(),
            fee_params: FeeParams {
                base_fee: 100,
                ..FeeParams::default()
            },
        },
    )
    .unwrap();

    assert_eq!(result.status, ExecutionStatus::RevertedOutOfGas);
    // Out-of-gas: fee_charged = full declared fee
    assert_eq!(result.fee_charged, fee);

    let proposer_fees = u128::from(result.fee_charged) + u128::from(tip);
    distribute_block_fees(
        &mut store,
        &proposer_addr,
        proposer_fees,
        &[],
        &FeeDistributionParams::default(),
    );

    assert_eq!(
        store.get_account(&proposer_addr).unwrap().balance,
        u128::from(fee) + u128::from(tip)
    );
    // Recipient account must NOT exist (payload was discarded)
    assert!(store.get_account(&recipient_addr).is_none());
}

// ── advance_height key activation tests ──────────────────────────────────────
//
// These tests use `insert_account` directly to bypass account invariant checks
// because an account with only a Pending key violates I-1. The goal is to test
// `advance_height` key lifecycle in isolation. In normal operation, an account
// with Pending keys always has at least one Active key alongside them.

fn pending_key_at(valid_from_height: u64) -> KeyEntry {
    KeyEntry {
        alg_id: AlgId::MlDsa65,
        pk_bytes: vec![0u8; 32].into(),
        key_version: 1,
        valid_from_height,
        status: KeyStatus::Pending,
        allowed_tx_types: allowed_tx::ALL,
    }
}

fn active_key(key_version: u32) -> KeyEntry {
    KeyEntry {
        alg_id: AlgId::MlDsa65,
        pk_bytes: vec![0u8; 32].into(),
        key_version,
        valid_from_height: 0,
        status: KeyStatus::Active,
        allowed_tx_types: allowed_tx::ALL,
    }
}

fn revoked_key(key_version: u32) -> KeyEntry {
    KeyEntry {
        alg_id: AlgId::MlDsa65,
        pk_bytes: vec![0u8; 32].into(),
        key_version,
        valid_from_height: 0,
        status: KeyStatus::Revoked,
        allowed_tx_types: allowed_tx::ALL,
    }
}

#[test]
fn pending_key_activates_at_exact_valid_from_height() {
    let addr = Address([0xAA; 32]);
    let mut store = StateStore::new();
    // height=0; key activates at height=3
    store.insert_account(Account {
        address: addr.clone(),
        balance: 0,
        nonce: 0,
        keys: KeySet(vec![pending_key_at(3)]),
        policy_version: 0,
        policy_hash: None,
        verifier_template_id: pqc_types::account::VERIFIER_TEMPLATE_ID_EOA,
        auth_data: Vec::new(),
    });

    store.advance_height(); // height=1
    assert_eq!(
        store.get_account(&addr).unwrap().keys.0[0].status,
        KeyStatus::Pending
    );

    store.advance_height(); // height=2
    assert_eq!(
        store.get_account(&addr).unwrap().keys.0[0].status,
        KeyStatus::Pending
    );

    store.advance_height(); // height=3 — activation point
    assert_eq!(
        store.get_account(&addr).unwrap().keys.0[0].status,
        KeyStatus::Active,
        "key must activate when block_height reaches valid_from_height"
    );
}

#[test]
fn pending_key_stays_pending_before_valid_from_height() {
    let addr = Address([0xAA; 32]);
    let mut store = StateStore::new();
    store.insert_account(Account {
        address: addr.clone(),
        balance: 0,
        nonce: 0,
        keys: KeySet(vec![pending_key_at(5)]),
        policy_version: 0,
        policy_hash: None,
        verifier_template_id: pqc_types::account::VERIFIER_TEMPLATE_ID_EOA,
        auth_data: Vec::new(),
    });

    for _ in 0..4 {
        store.advance_height();
    }
    assert_eq!(store.block_height(), 4);
    assert_eq!(
        store.get_account(&addr).unwrap().keys.0[0].status,
        KeyStatus::Pending,
        "key must not activate before valid_from_height"
    );
}

#[test]
fn active_and_revoked_keys_are_unchanged_by_advance_height() {
    let addr = Address([0xAA; 32]);
    let mut store = StateStore::new();
    store.insert_account(Account {
        address: addr.clone(),
        balance: 0,
        nonce: 0,
        keys: KeySet(vec![active_key(1), revoked_key(2)]),
        policy_version: 0,
        policy_hash: None,
        verifier_template_id: pqc_types::account::VERIFIER_TEMPLATE_ID_EOA,
        auth_data: Vec::new(),
    });

    for _ in 0..10 {
        store.advance_height();
    }

    let keys = &store.get_account(&addr).unwrap().keys.0;
    assert_eq!(
        keys[0].status,
        KeyStatus::Active,
        "Active key must remain Active"
    );
    assert_eq!(
        keys[1].status,
        KeyStatus::Revoked,
        "Revoked key must remain Revoked"
    );
}

#[test]
fn multiple_pending_keys_activate_independently_at_their_heights() {
    let addr = Address([0xAA; 32]);
    let mut key_a = pending_key_at(2);
    key_a.key_version = 1;
    let mut key_b = pending_key_at(4);
    key_b.key_version = 2;

    let mut store = StateStore::new();
    store.insert_account(Account {
        address: addr.clone(),
        balance: 0,
        nonce: 0,
        keys: KeySet(vec![key_a, key_b]),
        policy_version: 0,
        policy_hash: None,
        verifier_template_id: pqc_types::account::VERIFIER_TEMPLATE_ID_EOA,
        auth_data: Vec::new(),
    });

    store.advance_height(); // height=1
    store.advance_height(); // height=2 — key_a activates
    let keys = &store.get_account(&addr).unwrap().keys.0;
    assert_eq!(
        keys[0].status,
        KeyStatus::Active,
        "key_a must activate at height 2"
    );
    assert_eq!(
        keys[1].status,
        KeyStatus::Pending,
        "key_b must still be Pending at height 2"
    );

    store.advance_height(); // height=3
    store.advance_height(); // height=4 — key_b activates
    let keys = &store.get_account(&addr).unwrap().keys.0;
    assert_eq!(
        keys[0].status,
        KeyStatus::Active,
        "key_a must remain Active"
    );
    assert_eq!(
        keys[1].status,
        KeyStatus::Active,
        "key_b must activate at height 4"
    );
}

#[test]
fn past_due_pending_key_activates_on_next_advance() {
    // Robustness: a Pending key whose valid_from_height is in the past
    // (e.g., due to a checkpoint restore) must still activate on the next
    // advance_height call. The `>=` condition in advance_height covers this.
    let addr = Address([0xAA; 32]);
    // Simulate a store that jumped to height 5 via checkpoint restore,
    // with a Pending key that should have activated at height 2.
    let mut store = StateStore::from_snapshot_accounts(
        vec![Account {
            address: addr.clone(),
            balance: 0,
            nonce: 0,
            keys: KeySet(vec![pending_key_at(2)]),
            policy_version: 0,
            policy_hash: None,
            verifier_template_id: pqc_types::account::VERIFIER_TEMPLATE_ID_EOA,
            auth_data: Vec::new(),
        }],
        5, // block_height already past valid_from_height
        Vec::new(),
    );

    assert_eq!(
        store.get_account(&addr).unwrap().keys.0[0].status,
        KeyStatus::Pending,
        "key must start as Pending in the restored snapshot"
    );

    store.advance_height(); // height=6 >= valid_from_height(2) → activates
    assert_eq!(
        store.get_account(&addr).unwrap().keys.0[0].status,
        KeyStatus::Active,
        "past-due Pending key must activate on the next advance_height call"
    );
}

// ── Fee distribution tests (TASK-049) ────────────────────────────────────────

use crate::apply::{distribute_block_fees, FeeDistributionParams};

/// Helper: apply `distribute_block_fees` and return the resulting balance of `addr`.
#[allow(dead_code)]
fn balance_after_distribution(
    store: &StateStore,
    proposer: &Address,
    fees: u128,
    pool: &[Address],
    bps: u16,
) -> (StateStore, u128) {
    let mut s = store.clone();
    distribute_block_fees(
        &mut s,
        proposer,
        fees,
        pool,
        &FeeDistributionParams {
            proposer_share_bps: bps,
        },
    );
    let balance = s.get_account(proposer).map(|a| a.balance).unwrap_or(0);
    (s, balance)
}

#[test]
fn fee_distribution_empty_pool_credits_full_amount_to_proposer() {
    let proposer = Address([0x99; 32]);
    let mut store = StateStore::new();
    store.insert_account(Account {
        address: proposer.clone(),
        balance: 0,
        nonce: 0,
        keys: KeySet::default(),
        policy_version: 0,
        policy_hash: None,
        verifier_template_id: pqc_types::account::VERIFIER_TEMPLATE_ID_EOA,
        auth_data: Vec::new(),
    });

    distribute_block_fees(
        &mut store,
        &proposer,
        1_000,
        &[],
        &FeeDistributionParams::default(),
    );

    assert_eq!(
        store.get_account(&proposer).unwrap().balance,
        1_000,
        "empty pool: all fees must go to proposer"
    );
}

#[test]
fn fee_distribution_zero_fees_is_a_no_op() {
    let proposer = Address([0x99; 32]);
    let mut store = StateStore::new();
    store.insert_account(Account {
        address: proposer.clone(),
        balance: 500,
        nonce: 0,
        keys: KeySet::default(),
        policy_version: 0,
        policy_hash: None,
        verifier_template_id: pqc_types::account::VERIFIER_TEMPLATE_ID_EOA,
        auth_data: Vec::new(),
    });

    distribute_block_fees(
        &mut store,
        &proposer,
        0,
        &[Address([0xAA; 32])],
        &FeeDistributionParams::default(),
    );

    assert_eq!(
        store.get_account(&proposer).unwrap().balance,
        500,
        "zero fees: no balance must change"
    );
}

#[test]
fn fee_distribution_splits_between_proposer_and_pool() {
    let proposer = Address([0x99; 32]);
    let validator_a = Address([0xA1; 32]);
    let validator_b = Address([0xB2; 32]);
    let validator_c = Address([0xC3; 32]);
    let pool = vec![
        validator_a.clone(),
        validator_b.clone(),
        validator_c.clone(),
    ];

    let mut store = StateStore::new();
    // Give existing balance to confirm credit is additive.
    store.insert_account(Account {
        address: proposer.clone(),
        balance: 0,
        nonce: 0,
        keys: KeySet::default(),
        policy_version: 0,
        policy_hash: None,
        verifier_template_id: pqc_types::account::VERIFIER_TEMPLATE_ID_EOA,
        auth_data: Vec::new(),
    });

    // 5000 bps = 50 % to proposer priority, 50 % pool split across 3 validators.
    // fees_collected = 1_000: proposer_priority = 500, pool_total = 500.
    // per_validator = 500 / 3 = 166 (remainder 2 → proposer).
    distribute_block_fees(
        &mut store,
        &proposer,
        1_000,
        &pool,
        &FeeDistributionParams {
            proposer_share_bps: 5_000,
        },
    );

    let proposer_balance = store.get_account(&proposer).unwrap().balance;
    let va_balance = store.get_account(&validator_a).unwrap().balance;
    let vb_balance = store.get_account(&validator_b).unwrap().balance;
    let vc_balance = store.get_account(&validator_c).unwrap().balance;

    // Total must equal fees_collected (accounting invariant: no tokens created or destroyed).
    assert_eq!(
        proposer_balance + va_balance + vb_balance + vc_balance,
        1_000,
        "total credited must equal fees_collected"
    );
    // Pool validators receive equal shares.
    assert_eq!(
        va_balance, vb_balance,
        "pool validators must receive equal shares"
    );
    assert_eq!(
        vb_balance, vc_balance,
        "pool validators must receive equal shares"
    );
    // Proposer gets at least the priority share.
    assert!(
        proposer_balance >= 500,
        "proposer must receive at least the priority share"
    );
}

#[test]
fn fee_distribution_100_pct_bps_with_pool_all_to_proposer_plus_pool_zero() {
    let proposer = Address([0x99; 32]);
    let validator = Address([0xA1; 32]);
    let pool = vec![validator.clone()];

    let mut store = StateStore::new();
    store.insert_account(Account {
        address: proposer.clone(),
        balance: 0,
        nonce: 0,
        keys: KeySet::default(),
        policy_version: 0,
        policy_hash: None,
        verifier_template_id: pqc_types::account::VERIFIER_TEMPLATE_ID_EOA,
        auth_data: Vec::new(),
    });

    // proposer_share_bps = 10_000 (100 %): pool total = 0, so validator gets 0.
    distribute_block_fees(
        &mut store,
        &proposer,
        1_000,
        &pool,
        &FeeDistributionParams {
            proposer_share_bps: 10_000,
        },
    );

    assert_eq!(store.get_account(&proposer).unwrap().balance, 1_000);
    // validator gets 0 (per_validator = 0 / 1 = 0).
    assert!(
        store.get_account(&validator).is_none()
            || store.get_account(&validator).unwrap().balance == 0
    );
}

#[test]
fn fee_distribution_accounting_invariant_holds_with_rounding() {
    // Verify that proposer_priority + pool_distributed + remainder == fees_collected
    // for a case where integer division creates a remainder.
    let proposer = Address([0x99; 32]);
    let pool: Vec<Address> = (0..7u8).map(|i| Address([i; 32])).collect();

    let mut store = StateStore::new();
    store.insert_account(Account {
        address: proposer.clone(),
        balance: 0,
        nonce: 0,
        keys: KeySet::default(),
        policy_version: 0,
        policy_hash: None,
        verifier_template_id: pqc_types::account::VERIFIER_TEMPLATE_ID_EOA,
        auth_data: Vec::new(),
    });

    let fees: u128 = 10_007; // odd amount to exercise rounding
    distribute_block_fees(
        &mut store,
        &proposer,
        fees,
        &pool,
        &FeeDistributionParams {
            proposer_share_bps: 3_000,
        }, // 30 % proposer
    );

    let mut total: u128 = store.get_account(&proposer).unwrap().balance;
    for addr in &pool {
        total += store.get_account(addr).map(|a| a.balance).unwrap_or(0);
    }

    assert_eq!(
        total, fees,
        "accounting invariant: total credited must equal fees_collected exactly"
    );
}

#[test]
fn fee_distribution_creates_new_accounts_for_validators_without_existing_accounts() {
    let proposer = Address([0x99; 32]);
    let new_validator = Address([0xDD; 32]); // no pre-existing account
    let pool = vec![new_validator.clone()];

    let mut store = StateStore::new();
    assert!(
        store.get_account(&new_validator).is_none(),
        "validator must not have an account before distribution"
    );

    distribute_block_fees(
        &mut store,
        &proposer,
        1_000,
        &pool,
        &FeeDistributionParams {
            proposer_share_bps: 5_000,
        },
    );

    assert!(
        store.get_account(&new_validator).is_some(),
        "validator must have an implicit account after receiving pool share"
    );
    let val_balance = store.get_account(&new_validator).unwrap().balance;
    assert_eq!(
        val_balance, 500,
        "validator must receive pool share = 50% of 1000"
    );
}

#[test]
fn fee_distribution_proposer_in_pool_receives_both_shares() {
    // The proposer is also a member of the validator pool.
    // They should receive: proposer_priority + pool_share.
    let proposer = Address([0x99; 32]);
    let other = Address([0xAA; 32]);
    // Pool includes proposer as one of the validators.
    let pool = vec![proposer.clone(), other.clone()];

    let mut store = StateStore::new();
    store.insert_account(Account {
        address: proposer.clone(),
        balance: 0,
        nonce: 0,
        keys: KeySet::default(),
        policy_version: 0,
        policy_hash: None,
        verifier_template_id: pqc_types::account::VERIFIER_TEMPLATE_ID_EOA,
        auth_data: Vec::new(),
    });

    // 5000 bps, pool size 2, fees = 1000:
    // proposer_priority = 500, pool_total = 500, per_validator = 250
    // proposer gets: 500 (priority) + 250 (pool) = 750
    // other gets: 250
    distribute_block_fees(
        &mut store,
        &proposer,
        1_000,
        &pool,
        &FeeDistributionParams {
            proposer_share_bps: 5_000,
        },
    );

    let proposer_balance = store.get_account(&proposer).unwrap().balance;
    let other_balance = store.get_account(&other).unwrap().balance;

    assert_eq!(
        proposer_balance + other_balance,
        1_000,
        "accounting invariant"
    );
    assert!(
        proposer_balance > other_balance,
        "proposer must receive more than a plain validator when also in pool"
    );
    assert_eq!(
        other_balance, 250,
        "plain validator must receive their pool share only"
    );
    assert_eq!(
        proposer_balance, 750,
        "proposer must receive priority share + pool share"
    );
}

// ── attestation_revoke tests ──────────────────────────────────────────────────

/// Helper: create an attestation in state and return its id.
fn create_attestation(store: &mut StateStore, attester: Address, nonce: u64) -> AttestationId {
    let payload = attestation_payload([0xAB; 32], 0x0001, [0xCD; 32], [0xEF; 32], None, None);
    let tx = Transaction {
        tx_version: 1,
        chain_id: CHAIN_ID.to_vec(),
        msg_type: MsgType::AttestationCreate,
        sender: attester,
        nonce,
        fee: 0,
        fee_tip: 0,
        gas_limit: GAS_ATTESTATION_CREATE,
        payload,
        sig_alg_id: AlgId::MlDsa65,
        sig_key_version: 1,
        signature: vec![0u8; 3_309],
    };
    apply_tx(store, &tx, exec_ctx(&tx)).expect("create must succeed");
    let raw = encode_tx(&tx).unwrap();
    AttestationId(compute_tx_hash(&raw))
}

#[test]
fn attestation_revoke_transitions_to_revoked_and_records_revocation() {
    let attester_addr = Address([0xAA; 32]);
    let mut store = StateStore::new();
    store.insert_account(creator_account(attester_addr.clone(), 0));

    let attestation_id = create_attestation(&mut store, attester_addr.clone(), 0);

    // Verify it's Active before revoke.
    assert_eq!(
        store.get_attestation(&attestation_id).unwrap().status,
        AttestationStatus::Active
    );

    let reason_hash = [0x99u8; 32];
    let revoke_payload = attestation_revoke_payload(&attestation_id, Some(reason_hash));
    let tx = Transaction {
        tx_version: 1,
        chain_id: CHAIN_ID.to_vec(),
        msg_type: MsgType::AttestationRevoke,
        sender: attester_addr.clone(),
        nonce: 1,
        fee: 0,
        fee_tip: 0,
        gas_limit: GAS_ATTESTATION_REVOKE,
        payload: revoke_payload,
        sig_alg_id: AlgId::MlDsa65,
        sig_key_version: 1,
        signature: vec![0u8; 3_309],
    };

    let result = apply_tx(&mut store, &tx, exec_ctx(&tx)).expect("revoke must succeed");
    assert_eq!(result.status, ExecutionStatus::Applied);
    assert_eq!(result.gas_used, GAS_ATTESTATION_REVOKE);

    let attestation = store
        .get_attestation(&attestation_id)
        .expect("attestation must exist");
    assert_eq!(attestation.status, AttestationStatus::Revoked);
    let revocation = attestation
        .revocation
        .as_ref()
        .expect("revocation must be set");
    assert_eq!(revocation.revoker, attester_addr);
    assert_eq!(revocation.revocation_reason_hash, Some(reason_hash));
    assert_eq!(revocation.revoked_at_height, 1); // block_height 0 + 1
}

#[test]
fn attestation_revoke_without_reason_hash_is_valid() {
    let attester_addr = Address([0xBB; 32]);
    let mut store = StateStore::new();
    store.insert_account(creator_account(attester_addr.clone(), 0));

    let attestation_id = create_attestation(&mut store, attester_addr.clone(), 0);

    let revoke_payload = attestation_revoke_payload(&attestation_id, None);
    let tx = Transaction {
        tx_version: 1,
        chain_id: CHAIN_ID.to_vec(),
        msg_type: MsgType::AttestationRevoke,
        sender: attester_addr,
        nonce: 1,
        fee: 0,
        fee_tip: 0,
        gas_limit: GAS_ATTESTATION_REVOKE,
        payload: revoke_payload,
        sig_alg_id: AlgId::MlDsa65,
        sig_key_version: 1,
        signature: vec![0u8; 3_309],
    };

    let result =
        apply_tx(&mut store, &tx, exec_ctx(&tx)).expect("revoke without reason must succeed");
    assert_eq!(result.status, ExecutionStatus::Applied);

    let attestation = store.get_attestation(&attestation_id).unwrap();
    assert_eq!(attestation.status, AttestationStatus::Revoked);
    let revocation = attestation.revocation.as_ref().unwrap();
    assert!(revocation.revocation_reason_hash.is_none());
}

#[test]
fn attestation_revoke_rejects_already_revoked() {
    let attester_addr = Address([0xCC; 32]);
    let mut store = StateStore::new();
    store.insert_account(creator_account(attester_addr.clone(), 0));

    let attestation_id = create_attestation(&mut store, attester_addr.clone(), 0);

    let revoke_payload = attestation_revoke_payload(&attestation_id, None);
    let revoke_tx = |nonce: u64| Transaction {
        tx_version: 1,
        chain_id: CHAIN_ID.to_vec(),
        msg_type: MsgType::AttestationRevoke,
        sender: attester_addr.clone(),
        nonce,
        fee: 0,
        fee_tip: 0,
        gas_limit: GAS_ATTESTATION_REVOKE,
        payload: revoke_payload.clone(),
        sig_alg_id: AlgId::MlDsa65,
        sig_key_version: 1,
        signature: vec![0u8; 3_309],
    };

    // First revoke succeeds.
    apply_tx(&mut store, &revoke_tx(1), exec_ctx(&revoke_tx(1)))
        .expect("first revoke must succeed");

    // Second revoke on already-Revoked attestation must fail.
    let err = apply_tx(&mut store, &revoke_tx(2), exec_ctx(&revoke_tx(2))).unwrap_err();
    assert!(
        matches!(err, crate::error::ApplyError::AttestationAlreadyRevoked),
        "got: {err}"
    );
}

#[test]
fn attestation_revoke_rejects_unauthorized_revoker() {
    let attester_addr = Address([0xDD; 32]);
    let other_addr = Address([0xEE; 32]);
    let mut store = StateStore::new();
    store.insert_account(creator_account(attester_addr.clone(), 0));
    store.insert_account(creator_account(other_addr.clone(), 0));

    let attestation_id = create_attestation(&mut store, attester_addr.clone(), 0);

    let revoke_payload = attestation_revoke_payload(&attestation_id, None);
    let tx = Transaction {
        tx_version: 1,
        chain_id: CHAIN_ID.to_vec(),
        msg_type: MsgType::AttestationRevoke,
        sender: other_addr, // NOT the original attester
        nonce: 0,
        fee: 0,
        fee_tip: 0,
        gas_limit: GAS_ATTESTATION_REVOKE,
        payload: revoke_payload,
        sig_alg_id: AlgId::MlDsa65,
        sig_key_version: 1,
        signature: vec![0u8; 3_309],
    };

    let err = apply_tx(&mut store, &tx, exec_ctx(&tx)).unwrap_err();
    assert!(
        matches!(err, crate::error::ApplyError::UnauthorizedRevoker),
        "got: {err}"
    );
}

#[test]
fn attestation_revoke_rejects_nonexistent_attestation() {
    let sender_addr = Address([0xFF; 32]);
    let mut store = StateStore::new();
    store.insert_account(creator_account(sender_addr.clone(), 0));

    let phantom_id = AttestationId([0x00u8; 32]);
    let revoke_payload = attestation_revoke_payload(&phantom_id, None);
    let tx = Transaction {
        tx_version: 1,
        chain_id: CHAIN_ID.to_vec(),
        msg_type: MsgType::AttestationRevoke,
        sender: sender_addr,
        nonce: 0,
        fee: 0,
        fee_tip: 0,
        gas_limit: GAS_ATTESTATION_REVOKE,
        payload: revoke_payload,
        sig_alg_id: AlgId::MlDsa65,
        sig_key_version: 1,
        signature: vec![0u8; 3_309],
    };

    let err = apply_tx(&mut store, &tx, exec_ctx(&tx)).unwrap_err();
    assert!(
        matches!(err, crate::error::ApplyError::AttestationNotFound),
        "got: {err}"
    );
}

// ── proof_anchor ──────────────────────────────────────────────────────────────

fn proof_anchor_payload(
    claim_type: u16,
    asset_id_hash: [u8; 32],
    proof_hash: [u8; 32],
    schema_id: Option<[u8; 32]>,
) -> Vec<u8> {
    let mut pairs = vec![
        (1, CborVal::Int(claim_type as u64)),
        (2, CborVal::Bytes(asset_id_hash.to_vec())),
        (3, CborVal::Bytes(proof_hash.to_vec())),
    ];
    if let Some(sid) = schema_id {
        pairs.push((4, CborVal::Bytes(sid.to_vec())));
    }
    cbor_map(pairs)
}

#[test]
fn proof_anchor_stores_record_and_is_retrievable() {
    use pqc_tx::{codec::encode_tx, compute_tx_hash};

    let claimer = Address([0xAA; 32]);
    let mut store = StateStore::new();
    store.insert_account(creator_account(claimer.clone(), 0));

    let asset_id_hash = [0x10u8; 32];
    let proof_hash = [0x20u8; 32];
    let payload = proof_anchor_payload(0x0001, asset_id_hash, proof_hash, None);
    let tx = Transaction {
        tx_version: 1,
        chain_id: CHAIN_ID.to_vec(),
        msg_type: MsgType::ProofAnchor,
        sender: claimer.clone(),
        nonce: 0,
        fee: 0,
        fee_tip: 0,
        gas_limit: GAS_PROOF_ANCHOR,
        payload,
        sig_alg_id: AlgId::MlDsa65,
        sig_key_version: 1,
        signature: vec![0u8; 3_309],
    };

    let result = apply_tx(&mut store, &tx, exec_ctx(&tx)).unwrap();
    assert_eq!(result.status, ExecutionStatus::Applied);

    // Derive anchor_id the same way the apply layer does.
    let raw = encode_tx(&tx).unwrap();
    let anchor_id = AnchorId(compute_tx_hash(&raw));

    let anchor = store
        .get_proof_anchor(&anchor_id)
        .expect("anchor must be in state");
    assert_eq!(anchor.claimer, claimer);
    assert_eq!(anchor.claim_type, 0x0001);
    assert_eq!(anchor.asset_id_hash, asset_id_hash);
    assert_eq!(anchor.proof_hash, proof_hash);
    assert!(anchor.schema_id.is_none());

    // Also verify via proof_anchors_in_order.
    assert_eq!(store.proof_anchors_in_order().len(), 1);
}

#[test]
fn proof_anchor_with_schema_id_is_valid() {
    let claimer = Address([0xBB; 32]);
    let mut store = StateStore::new();
    store.insert_account(creator_account(claimer.clone(), 0));

    let schema_id = [0x30u8; 32];
    let payload = proof_anchor_payload(0x0002, [0x11u8; 32], [0x22u8; 32], Some(schema_id));
    let tx = Transaction {
        tx_version: 1,
        chain_id: CHAIN_ID.to_vec(),
        msg_type: MsgType::ProofAnchor,
        sender: claimer,
        nonce: 0,
        fee: 0,
        fee_tip: 0,
        gas_limit: GAS_PROOF_ANCHOR,
        payload,
        sig_alg_id: AlgId::MlDsa65,
        sig_key_version: 1,
        signature: vec![0u8; 3_309],
    };

    let result = apply_tx(&mut store, &tx, exec_ctx(&tx)).unwrap();
    assert_eq!(result.status, ExecutionStatus::Applied);
    let anchors = store.proof_anchors_in_order();
    assert_eq!(anchors.len(), 1);
    assert_eq!(anchors[0].schema_id, Some(schema_id));
}

#[test]
fn proof_anchor_rejects_unknown_claim_type() {
    let claimer = Address([0xCC; 32]);
    let mut store = StateStore::new();
    store.insert_account(creator_account(claimer.clone(), 0));

    // 0x0000 is reserved / unrecognized
    let payload = proof_anchor_payload(0x0000, [0x10u8; 32], [0x20u8; 32], None);
    let tx = Transaction {
        tx_version: 1,
        chain_id: CHAIN_ID.to_vec(),
        msg_type: MsgType::ProofAnchor,
        sender: claimer,
        nonce: 0,
        fee: 0,
        fee_tip: 0,
        gas_limit: GAS_PROOF_ANCHOR,
        payload,
        sig_alg_id: AlgId::MlDsa65,
        sig_key_version: 1,
        signature: vec![0u8; 3_309],
    };

    let err = apply_tx(&mut store, &tx, exec_ctx(&tx)).unwrap_err();
    assert!(
        matches!(err, crate::error::ApplyError::InvalidClaimType),
        "got: {err}"
    );
}

#[test]
fn proof_anchor_rejects_reserved_high_claim_type() {
    let claimer = Address([0xDD; 32]);
    let mut store = StateStore::new();
    store.insert_account(creator_account(claimer.clone(), 0));

    // 0x8000 and above are reserved
    let payload = proof_anchor_payload(0x8000, [0x10u8; 32], [0x20u8; 32], None);
    let tx = Transaction {
        tx_version: 1,
        chain_id: CHAIN_ID.to_vec(),
        msg_type: MsgType::ProofAnchor,
        sender: claimer,
        nonce: 0,
        fee: 0,
        fee_tip: 0,
        gas_limit: GAS_PROOF_ANCHOR,
        payload,
        sig_alg_id: AlgId::MlDsa65,
        sig_key_version: 1,
        signature: vec![0u8; 3_309],
    };

    let err = apply_tx(&mut store, &tx, exec_ctx(&tx)).unwrap_err();
    assert!(
        matches!(err, crate::error::ApplyError::InvalidClaimType),
        "got: {err}"
    );
}

// ── vault_policy_update ───────────────────────────────────────────────────────

fn vault_policy_update_payload(policy_version: u32, policy_hash: [u8; 32]) -> Vec<u8> {
    cbor_map(vec![
        (1, CborVal::Int(policy_version as u64)),
        (2, CborVal::Bytes(policy_hash.to_vec())),
    ])
}

#[test]
fn vault_policy_update_sets_policy_version_and_hash() {
    let addr = Address([0xAA; 32]);
    let mut store = StateStore::new();
    store.insert_account(creator_account(addr.clone(), 0));

    let policy_hash = [0x42u8; 32];
    let payload = vault_policy_update_payload(1, policy_hash);
    let tx = Transaction {
        tx_version: 1,
        chain_id: CHAIN_ID.to_vec(),
        msg_type: MsgType::VaultPolicyUpdate,
        sender: addr.clone(),
        nonce: 0,
        fee: 0,
        fee_tip: 0,
        gas_limit: GAS_VAULT_POLICY_UPDATE,
        payload,
        sig_alg_id: AlgId::MlDsa65,
        sig_key_version: 1,
        signature: vec![0u8; 3_309],
    };

    let result = apply_tx(&mut store, &tx, exec_ctx(&tx)).unwrap();
    assert_eq!(result.status, ExecutionStatus::Applied);

    let account = store.get_account(&addr).unwrap();
    assert_eq!(account.policy_version, 1);
    assert_eq!(account.policy_hash, Some(policy_hash));
}

#[test]
fn vault_policy_update_rejects_version_conflict() {
    let addr = Address([0xBB; 32]);
    let mut store = StateStore::new();
    store.insert_account(creator_account(addr.clone(), 0));

    // First update: version 2
    let payload1 = vault_policy_update_payload(2, [0x01u8; 32]);
    let tx1 = Transaction {
        tx_version: 1,
        chain_id: CHAIN_ID.to_vec(),
        msg_type: MsgType::VaultPolicyUpdate,
        sender: addr.clone(),
        nonce: 0,
        fee: 0,
        fee_tip: 0,
        gas_limit: GAS_VAULT_POLICY_UPDATE,
        payload: payload1,
        sig_alg_id: AlgId::MlDsa65,
        sig_key_version: 1,
        signature: vec![0u8; 3_309],
    };
    apply_tx(&mut store, &tx1, exec_ctx(&tx1)).unwrap();

    // Second update: same version (replay attempt) — must be rejected
    let payload2 = vault_policy_update_payload(2, [0x02u8; 32]);
    let tx2 = Transaction {
        tx_version: 1,
        chain_id: CHAIN_ID.to_vec(),
        msg_type: MsgType::VaultPolicyUpdate,
        sender: addr.clone(),
        nonce: 1,
        fee: 0,
        fee_tip: 0,
        gas_limit: GAS_VAULT_POLICY_UPDATE,
        payload: payload2,
        sig_alg_id: AlgId::MlDsa65,
        sig_key_version: 1,
        signature: vec![0u8; 3_309],
    };
    let err = apply_tx(&mut store, &tx2, exec_ctx(&tx2)).unwrap_err();
    assert!(
        matches!(err, crate::error::ApplyError::PolicyVersionConflict),
        "got: {err}"
    );
}

#[test]
fn vault_policy_update_monotonic_version_increments() {
    let addr = Address([0xCC; 32]);
    let mut store = StateStore::new();
    store.insert_account(creator_account(addr.clone(), 0));

    for (nonce, version, hash_fill) in [(0u64, 1u32, 0x10u8), (1, 5, 0x20), (2, 6, 0x30)] {
        let payload = vault_policy_update_payload(version, [hash_fill; 32]);
        let tx = Transaction {
            tx_version: 1,
            chain_id: CHAIN_ID.to_vec(),
            msg_type: MsgType::VaultPolicyUpdate,
            sender: addr.clone(),
            nonce,
            fee: 0,
            fee_tip: 0,
            gas_limit: GAS_VAULT_POLICY_UPDATE,
            payload,
            sig_alg_id: AlgId::MlDsa65,
            sig_key_version: 1,
            signature: vec![0u8; 3_309],
        };
        apply_tx(&mut store, &tx, exec_ctx(&tx)).unwrap();
    }

    let account = store.get_account(&addr).unwrap();
    assert_eq!(account.policy_version, 6);
    assert_eq!(account.policy_hash, Some([0x30u8; 32]));
}

// ── consensus_key_rotate ──────────────────────────────────────────────────────

fn consensus_key_rotate_payload(
    alg_id: AlgId,
    pk_bytes: Vec<u8>,
    rotation_start_height: u64,
) -> Vec<u8> {
    cbor_map(vec![
        (1, CborVal::Int(alg_id.as_u16() as u64)),
        (2, CborVal::Bytes(pk_bytes)),
        (3, CborVal::Int(rotation_start_height)),
    ])
}

#[test]
fn consensus_key_rotate_stores_rotation_record() {
    let operator = Address([0xD0; 32]);
    let mut store = StateStore::new();
    store.insert_account(creator_account(operator.clone(), 0));

    // Use ML-DSA-65 pk size from registry (should be 1952 bytes).
    let entry = store.alg_entry(AlgId::MlDsa65).unwrap();
    let pk = vec![0x22u8; entry.pk_size];
    // Store starts at block_height=0; min valid start = 0 + ROTATION_WINDOW = 100.
    let rotation_start_height = ROTATION_WINDOW;

    let payload = consensus_key_rotate_payload(AlgId::MlDsa65, pk.clone(), rotation_start_height);
    let tx = Transaction {
        tx_version: 1,
        chain_id: CHAIN_ID.to_vec(),
        msg_type: MsgType::ConsensusKeyRotate,
        sender: operator.clone(),
        nonce: 0,
        fee: 0,
        fee_tip: 0,
        gas_limit: GAS_CONSENSUS_KEY_ROTATE,
        payload,
        sig_alg_id: AlgId::MlDsa65,
        sig_key_version: 1,
        signature: vec![0u8; 3_309],
    };
    apply_tx(&mut store, &tx, exec_ctx(&tx)).unwrap();

    let rotation = store
        .get_consensus_key_rotation(&operator)
        .expect("rotation record missing");
    assert_eq!(rotation.operator, operator);
    assert_eq!(rotation.new_alg_id, AlgId::MlDsa65);
    assert_eq!(rotation.new_pk_bytes, pk);
    assert_eq!(rotation.rotation_start_height, rotation_start_height);
}

#[test]
fn consensus_key_rotate_rejects_slh_dsa() {
    let operator = Address([0xD1; 32]);
    let mut store = StateStore::new();
    store.insert_account(creator_account(operator.clone(), 0));

    let entry = store.alg_entry(AlgId::SlhDsaSha2128s).unwrap();
    let pk = vec![0x22u8; entry.pk_size];
    let payload = consensus_key_rotate_payload(AlgId::SlhDsaSha2128s, pk, ROTATION_WINDOW);
    let tx = Transaction {
        tx_version: 1,
        chain_id: CHAIN_ID.to_vec(),
        msg_type: MsgType::ConsensusKeyRotate,
        sender: operator.clone(),
        nonce: 0,
        fee: 0,
        fee_tip: 0,
        gas_limit: GAS_CONSENSUS_KEY_ROTATE,
        payload,
        sig_alg_id: AlgId::MlDsa65,
        sig_key_version: 1,
        signature: vec![0u8; 3_309],
    };
    let err = apply_tx(&mut store, &tx, exec_ctx(&tx)).unwrap_err();
    assert!(
        matches!(
            err,
            crate::error::ApplyError::AlgorithmNotAllowedForConsensus
        ),
        "got: {err}"
    );
}

#[test]
fn consensus_key_rotate_rejects_insufficient_rotation_window() {
    let operator = Address([0xD2; 32]);
    let mut store = StateStore::new();
    store.insert_account(creator_account(operator.clone(), 0));

    let entry = store.alg_entry(AlgId::MlDsa65).unwrap();
    let pk = vec![0x22u8; entry.pk_size];
    // Store is at block_height=0; min valid start = ROTATION_WINDOW. Use ROTATION_WINDOW-1 (one too soon).
    let payload = consensus_key_rotate_payload(AlgId::MlDsa65, pk, ROTATION_WINDOW - 1);
    let tx = Transaction {
        tx_version: 1,
        chain_id: CHAIN_ID.to_vec(),
        msg_type: MsgType::ConsensusKeyRotate,
        sender: operator.clone(),
        nonce: 0,
        fee: 0,
        fee_tip: 0,
        gas_limit: GAS_CONSENSUS_KEY_ROTATE,
        payload,
        sig_alg_id: AlgId::MlDsa65,
        sig_key_version: 1,
        signature: vec![0u8; 3_309],
    };
    let err = apply_tx(&mut store, &tx, exec_ctx(&tx)).unwrap_err();
    assert!(
        matches!(err, crate::error::ApplyError::InvalidRotationHeight),
        "got: {err}"
    );
}

#[test]
fn consensus_key_rotate_rejects_wrong_pk_size() {
    let operator = Address([0xD3; 32]);
    let mut store = StateStore::new();
    store.insert_account(creator_account(operator.clone(), 0));

    // Deliberate wrong size: 64 bytes instead of the expected ML-DSA-65 size.
    let pk = vec![0x22u8; 64];
    let payload = consensus_key_rotate_payload(AlgId::MlDsa65, pk, ROTATION_WINDOW);
    let tx = Transaction {
        tx_version: 1,
        chain_id: CHAIN_ID.to_vec(),
        msg_type: MsgType::ConsensusKeyRotate,
        sender: operator.clone(),
        nonce: 0,
        fee: 0,
        fee_tip: 0,
        gas_limit: GAS_CONSENSUS_KEY_ROTATE,
        payload,
        sig_alg_id: AlgId::MlDsa65,
        sig_key_version: 1,
        signature: vec![0u8; 3_309],
    };
    let err = apply_tx(&mut store, &tx, exec_ctx(&tx)).unwrap_err();
    assert!(
        matches!(err, crate::error::ApplyError::InvalidKeySize),
        "got: {err}"
    );
}

#[test]
fn consensus_key_rotate_second_rotation_overwrites_first() {
    let operator = Address([0xD4; 32]);
    let mut store = StateStore::new();
    store.insert_account(creator_account(operator.clone(), 0));

    let entry = store.alg_entry(AlgId::MlDsa65).unwrap();
    let pk_size = entry.pk_size;

    // First rotation.
    let pk1 = vec![0x11u8; pk_size];
    let payload1 = consensus_key_rotate_payload(AlgId::MlDsa65, pk1, ROTATION_WINDOW);
    let tx1 = Transaction {
        tx_version: 1,
        chain_id: CHAIN_ID.to_vec(),
        msg_type: MsgType::ConsensusKeyRotate,
        sender: operator.clone(),
        nonce: 0,
        fee: 0,
        fee_tip: 0,
        gas_limit: GAS_CONSENSUS_KEY_ROTATE,
        payload: payload1,
        sig_alg_id: AlgId::MlDsa65,
        sig_key_version: 1,
        signature: vec![0u8; 3_309],
    };
    apply_tx(&mut store, &tx1, exec_ctx(&tx1)).unwrap();

    // Second rotation — overwrites first.
    let pk2 = vec![0x22u8; pk_size];
    let payload2 = consensus_key_rotate_payload(AlgId::MlDsa65, pk2.clone(), ROTATION_WINDOW + 50);
    let tx2 = Transaction {
        tx_version: 1,
        chain_id: CHAIN_ID.to_vec(),
        msg_type: MsgType::ConsensusKeyRotate,
        sender: operator.clone(),
        nonce: 1,
        fee: 0,
        fee_tip: 0,
        gas_limit: GAS_CONSENSUS_KEY_ROTATE,
        payload: payload2,
        sig_alg_id: AlgId::MlDsa65,
        sig_key_version: 1,
        signature: vec![0u8; 3_309],
    };
    apply_tx(&mut store, &tx2, exec_ctx(&tx2)).unwrap();

    let rotation = store.get_consensus_key_rotation(&operator).unwrap();
    assert_eq!(
        rotation.new_pk_bytes, pk2,
        "second rotation should overwrite first"
    );
    assert_eq!(rotation.rotation_start_height, ROTATION_WINDOW + 50);
}

// ── TASK-223 — activate_pending_consensus_key_rotations ──────────────────────

/// Helper: build a registered validator with a known consensus pk.
fn make_registered_validator(
    operator: Address,
    consensus_pk: Vec<u8>,
    consensus_alg_id: pqc_crypto::AlgId,
) -> pqc_types::validator::ValidatorRecord {
    pqc_types::validator::ValidatorRecord {
        operator,
        node_id: "task-223-validator".to_owned(),
        consensus_alg_id,
        consensus_pk,
        self_bond: 1_000,
        status: pqc_types::validator::ValidatorStatus::Active,
        registered_height: 0,
        tombstoned: false,
    }
}

/// Helper: insert a pending rotation directly (skips the apply path so
/// the test scope stays focused on the activation logic).
fn insert_rotation(
    store: &mut StateStore,
    operator: Address,
    new_alg_id: pqc_crypto::AlgId,
    new_pk: Vec<u8>,
    rotation_start_height: u64,
) {
    store.insert_consensus_key_rotation(pqc_types::consensus_rotation::ConsensusKeyRotation {
        operator,
        new_alg_id,
        new_pk_bytes: new_pk,
        rotation_start_height,
        recorded_at_height: 0,
    });
}

#[test]
fn activate_no_rotations_pending_returns_empty() {
    let mut store = StateStore::new();
    let activations = store.activate_pending_consensus_key_rotations(100);
    assert!(activations.is_empty());
}

#[test]
fn activate_below_threshold_height_does_not_fire() {
    // rotation_start_height = 100, current = 99 → no activation.
    let operator = Address([0xE0; 32]);
    let pk_size = StateStore::new().alg_entry(AlgId::MlDsa65).unwrap().pk_size;
    let old_pk = vec![0x11u8; pk_size];
    let new_pk = vec![0x22u8; pk_size];

    let mut store = StateStore::new();
    store.insert_validator(make_registered_validator(
        operator.clone(),
        old_pk.clone(),
        AlgId::MlDsa65,
    ));
    insert_rotation(
        &mut store,
        operator.clone(),
        AlgId::MlDsa65,
        new_pk.clone(),
        100,
    );

    let activations = store.activate_pending_consensus_key_rotations(99);
    assert!(activations.is_empty(), "must not activate below threshold");

    // Validator record retains the old pk, rotation record still pending.
    assert_eq!(store.get_validator(&operator).unwrap().consensus_pk, old_pk);
    assert!(store.get_consensus_key_rotation(&operator).is_some());
}

#[test]
fn activate_at_threshold_height_replaces_validator_pk() {
    let operator = Address([0xE1; 32]);
    let pk_size = StateStore::new().alg_entry(AlgId::MlDsa65).unwrap().pk_size;
    let old_pk = vec![0x11u8; pk_size];
    let new_pk = vec![0x22u8; pk_size];

    let mut store = StateStore::new();
    store.insert_validator(make_registered_validator(
        operator.clone(),
        old_pk.clone(),
        AlgId::MlDsa65,
    ));
    insert_rotation(
        &mut store,
        operator.clone(),
        AlgId::MlDsa65,
        new_pk.clone(),
        100,
    );

    let activations = store.activate_pending_consensus_key_rotations(100);
    assert_eq!(activations.len(), 1);
    assert_eq!(activations[0].0, operator);
    assert_eq!(activations[0].1, AlgId::MlDsa65);

    // Validator record now carries the new pk; rotation record removed.
    assert_eq!(store.get_validator(&operator).unwrap().consensus_pk, new_pk);
    assert!(store.get_consensus_key_rotation(&operator).is_none());
}

#[test]
fn activate_replaces_alg_id_when_changed() {
    // Rotate from ML-DSA-65 to ML-DSA-87 — both are allowed for consensus.
    let operator = Address([0xE2; 32]);
    let pk_size_65 = StateStore::new().alg_entry(AlgId::MlDsa65).unwrap().pk_size;
    let pk_size_87 = StateStore::new().alg_entry(AlgId::MlDsa87).unwrap().pk_size;
    let old_pk = vec![0x11u8; pk_size_65];
    let new_pk = vec![0x33u8; pk_size_87];

    let mut store = StateStore::new();
    store.insert_validator(make_registered_validator(
        operator.clone(),
        old_pk.clone(),
        AlgId::MlDsa65,
    ));
    insert_rotation(
        &mut store,
        operator.clone(),
        AlgId::MlDsa87,
        new_pk.clone(),
        200,
    );

    let activations = store.activate_pending_consensus_key_rotations(200);
    assert_eq!(activations.len(), 1);
    assert_eq!(activations[0].1, AlgId::MlDsa87);
    let record = store.get_validator(&operator).unwrap();
    assert_eq!(record.consensus_alg_id, AlgId::MlDsa87);
    assert_eq!(record.consensus_pk, new_pk);
}

#[test]
fn activate_multiple_rotations_at_same_height_in_address_order() {
    // Two rotations both due at the same height — activation order is
    // address-ascending (pinned by sort_by_key in the impl; pinned here
    // for the audit trail).
    let pk_size = StateStore::new().alg_entry(AlgId::MlDsa65).unwrap().pk_size;
    let op_low = Address([0x10; 32]);
    let op_high = Address([0x20; 32]);

    let mut store = StateStore::new();
    store.insert_validator(make_registered_validator(
        op_low.clone(),
        vec![0xAA; pk_size],
        AlgId::MlDsa65,
    ));
    store.insert_validator(make_registered_validator(
        op_high.clone(),
        vec![0xBB; pk_size],
        AlgId::MlDsa65,
    ));
    insert_rotation(
        &mut store,
        op_high.clone(),
        AlgId::MlDsa65,
        vec![0x44; pk_size],
        50,
    );
    insert_rotation(
        &mut store,
        op_low.clone(),
        AlgId::MlDsa65,
        vec![0x55; pk_size],
        50,
    );

    let activations = store.activate_pending_consensus_key_rotations(50);
    assert_eq!(activations.len(), 2);
    assert_eq!(activations[0].0, op_low, "low address activates first");
    assert_eq!(activations[1].0, op_high);
}

#[test]
fn activate_skipped_for_non_validator_operator_drops_rotation() {
    // Operator submitted a rotation but is not a registered validator.
    // The rotation record is dropped at activation time (no-op apply)
    // and a WARN is logged. State-root reflects the removal.
    let operator = Address([0xE3; 32]);
    let pk = vec![0x77u8; 1952];

    let mut store = StateStore::new();
    insert_rotation(&mut store, operator.clone(), AlgId::MlDsa65, pk, 100);

    let activations = store.activate_pending_consensus_key_rotations(100);
    assert!(
        activations.is_empty(),
        "no validator → no activation reported"
    );
    assert!(
        store.get_consensus_key_rotation(&operator).is_none(),
        "rotation record should be removed even for non-validator"
    );
}

#[test]
fn activate_changes_state_root() {
    // The state-root MUST change at activation: the validator-record
    // leaf hash includes consensus_pk, and the rotation leaf is removed
    // from the rotation-leaf table. Both fold into state_root.
    let operator = Address([0xE4; 32]);
    let pk_size = StateStore::new().alg_entry(AlgId::MlDsa65).unwrap().pk_size;
    let old_pk = vec![0x11u8; pk_size];
    let new_pk = vec![0x22u8; pk_size];

    let mut store = StateStore::new();
    store.insert_validator(make_registered_validator(
        operator.clone(),
        old_pk,
        AlgId::MlDsa65,
    ));
    insert_rotation(&mut store, operator.clone(), AlgId::MlDsa65, new_pk, 100);

    let pre_root = store.state_root();
    let _ = store.activate_pending_consensus_key_rotations(100);
    let post_root = store.state_root();

    assert_ne!(pre_root, post_root, "state_root must move at activation");
}

// ── Validator staking lifecycle (TASK-064, SPEC-VAL-001) ──────────────────────

use crate::apply::validator::{
    apply_validator_exit, apply_validator_register, apply_validator_unjail,
    encode_empty_validator_payload, encode_register_payload,
};
use pqc_types::validator::{
    ValidatorRecord, ValidatorRegisterPayload, ValidatorStatus, VALIDATOR_UNBONDING_PERIOD,
};

fn validator_register_tx(
    operator: Address,
    nonce: u64,
    node_id: &str,
    consensus_pk: Vec<u8>,
    self_bond: u128,
) -> Transaction {
    let payload_struct = ValidatorRegisterPayload {
        node_id: node_id.to_owned(),
        consensus_alg_id: AlgId::MlDsa65.as_u16(),
        consensus_pk,
        self_bond,
        peer_id: vec![],
    };
    Transaction {
        tx_version: 1,
        chain_id: CHAIN_ID.to_vec(),
        msg_type: MsgType::ValidatorRegister,
        sender: operator,
        nonce,
        fee: 0,
        fee_tip: 0,
        gas_limit: 1_000_000,
        payload: encode_register_payload(&payload_struct),
        sig_alg_id: AlgId::MlDsa65,
        sig_key_version: 1,
        signature: vec![0u8; 3_309],
    }
}

fn validator_exit_tx(operator: Address, nonce: u64) -> Transaction {
    Transaction {
        tx_version: 1,
        chain_id: CHAIN_ID.to_vec(),
        msg_type: MsgType::ValidatorExit,
        sender: operator,
        nonce,
        fee: 0,
        fee_tip: 0,
        gas_limit: 1_000_000,
        payload: encode_empty_validator_payload(),
        sig_alg_id: AlgId::MlDsa65,
        sig_key_version: 1,
        signature: vec![0u8; 3_309],
    }
}

fn validator_unjail_tx(operator: Address, nonce: u64) -> Transaction {
    Transaction {
        tx_version: 1,
        chain_id: CHAIN_ID.to_vec(),
        msg_type: MsgType::ValidatorUnjail,
        sender: operator,
        nonce,
        fee: 0,
        fee_tip: 0,
        gas_limit: 1_000_000,
        payload: encode_empty_validator_payload(),
        sig_alg_id: AlgId::MlDsa65,
        sig_key_version: 1,
        signature: vec![0u8; 3_309],
    }
}

fn store_with_operator(operator_addr: Address, balance: u128) -> StateStore {
    let mut store = StateStore::new();
    store.insert_account(Account {
        address: operator_addr.clone(),
        balance,
        nonce: 0,
        keys: KeySet(vec![KeyEntry {
            alg_id: AlgId::MlDsa65,
            pk_bytes: vec![0xABu8; 32].into(),
            key_version: 1,
            valid_from_height: 0,
            status: KeyStatus::Active,
            allowed_tx_types: allowed_tx::ALL,
        }]),
        policy_version: 0,
        policy_hash: None,
        verifier_template_id: pqc_types::account::VERIFIER_TEMPLATE_ID_EOA,
        auth_data: Vec::new(),
    });
    store
}

// ML-DSA-65 public key is 1952 bytes in the registry; use the right size.
fn ml_dsa65_pk() -> Vec<u8> {
    // The registry pk_size for MlDsa65 is 1952 bytes.
    vec![0x42u8; 1952]
}

#[test]
fn validator_register_creates_active_record() {
    let operator = Address([0x55u8; 32]);
    let mut store = store_with_operator(operator.clone(), 100_000);

    let pk = ml_dsa65_pk();
    let tx = validator_register_tx(operator.clone(), 0, "node-1", pk.clone(), 1_000);
    apply_validator_register(&mut store, &tx).expect("register must succeed");

    let record = store
        .get_validator(&operator)
        .expect("validator must exist");
    assert_eq!(
        record.status,
        ValidatorStatus::Active,
        "first validator is promoted to Active"
    );
    assert_eq!(record.consensus_pk, pk);
    assert_eq!(record.self_bond, 1_000);
    assert_eq!(record.node_id, "node-1");

    // Bond must be deducted from operator balance.
    let account = store.get_account(&operator).unwrap();
    assert_eq!(
        account.balance, 99_000,
        "self_bond must be locked from operator balance"
    );
}

#[test]
fn validator_register_sets_candidate_when_set_full() {
    let mut store = StateStore::new();
    // Fill the active set with 24 validators.
    for i in 0u8..24 {
        let addr = Address([i; 32]);
        store.insert_account(Account {
            address: addr.clone(),
            balance: 100_000,
            nonce: 0,
            keys: KeySet(vec![]),
            policy_version: 0,
            policy_hash: None,
            verifier_template_id: pqc_types::account::VERIFIER_TEMPLATE_ID_EOA,
            auth_data: Vec::new(),
        });
        store.insert_validator(ValidatorRecord {
            operator: addr.clone(),
            node_id: format!("node-{i}"),
            consensus_alg_id: AlgId::MlDsa65,
            consensus_pk: vec![i; 1952],
            self_bond: 0,
            status: ValidatorStatus::Active,
            registered_height: 0,
            tombstoned: false,
        });
    }

    // 25th validator should be Candidate.
    let operator = Address([0xFF; 32]);
    store.insert_account(Account {
        address: operator.clone(),
        balance: 100_000,
        nonce: 0,
        keys: KeySet(vec![]),
        policy_version: 0,
        policy_hash: None,
        verifier_template_id: pqc_types::account::VERIFIER_TEMPLATE_ID_EOA,
        auth_data: Vec::new(),
    });
    let pk = vec![0xEEu8; 1952];
    let tx = validator_register_tx(operator.clone(), 0, "node-25", pk, 500);
    apply_validator_register(&mut store, &tx).expect("register must succeed");

    let record = store.get_validator(&operator).unwrap();
    assert_eq!(
        record.status,
        ValidatorStatus::Candidate,
        "set full: 25th must be Candidate"
    );
}

#[test]
fn validator_register_rejects_duplicate_consensus_key() {
    let op1 = Address([0x11u8; 32]);
    let op2 = Address([0x22u8; 32]);
    let pk = ml_dsa65_pk();
    let mut store = StateStore::new();
    for addr in [op1.clone(), op2.clone()] {
        store.insert_account(Account {
            address: addr,
            balance: 100_000,
            nonce: 0,
            keys: KeySet(vec![]),
            policy_version: 0,
            policy_hash: None,
            verifier_template_id: pqc_types::account::VERIFIER_TEMPLATE_ID_EOA,
            auth_data: Vec::new(),
        });
    }

    let tx1 = validator_register_tx(op1.clone(), 0, "node-1", pk.clone(), 100);
    apply_validator_register(&mut store, &tx1).expect("first registration must succeed");

    let tx2 = validator_register_tx(op2.clone(), 0, "node-2", pk.clone(), 100);
    let err = apply_validator_register(&mut store, &tx2).unwrap_err();
    assert!(matches!(
        err,
        crate::ApplyError::ValidatorConsensusKeyConflict
    ));
}

#[test]
fn validator_register_rejects_non_mldsa_consensus_key() {
    let operator = Address([0x33u8; 32]);
    let mut store = store_with_operator(operator.clone(), 100_000);

    // Use SlhDsaSha2128s pk size (32 bytes) with the wrong alg_id.
    let payload_struct = ValidatorRegisterPayload {
        node_id: "node-slh".to_owned(),
        consensus_alg_id: AlgId::SlhDsaSha2128s.as_u16(),
        consensus_pk: vec![0xAAu8; 32],
        self_bond: 100,
        peer_id: vec![],
    };
    let tx = Transaction {
        tx_version: 1,
        chain_id: CHAIN_ID.to_vec(),
        msg_type: MsgType::ValidatorRegister,
        sender: operator.clone(),
        nonce: 0,
        fee: 0,
        fee_tip: 0,
        gas_limit: 1_000_000,
        payload: encode_register_payload(&payload_struct),
        sig_alg_id: AlgId::MlDsa65,
        sig_key_version: 1,
        signature: vec![0u8; 3_309],
    };
    let err = apply_validator_register(&mut store, &tx).unwrap_err();
    assert!(matches!(
        err,
        crate::ApplyError::AlgorithmNotAllowedForConsensusKey
    ));
}

/// ADR-046: ML-DSA-44 (NIST Category 2) must be rejected for validator
/// consensus keys. Lattice-family but below the minimum Category 3 floor.
/// The registry entry for MlDsa44 stays Active — this only gates consensus
/// keys; account keys and non-consensus signatures remain permitted.
#[test]
fn validator_register_rejects_ml_dsa_44_consensus_key_adr_046() {
    let operator = Address([0x77u8; 32]);
    let mut store = store_with_operator(operator.clone(), 100_000);

    // ML-DSA-44 pk size = 1312 bytes per FIPS 204. Supply real-size bytes so
    // we only trip on the allowed_for_consensus() check and not the size
    // check that runs later.
    let payload_struct = ValidatorRegisterPayload {
        node_id: "node-mldsa44".to_owned(),
        consensus_alg_id: AlgId::MlDsa44.as_u16(),
        consensus_pk: vec![0xAAu8; 1_312],
        self_bond: 100,
        peer_id: vec![],
    };
    let tx = Transaction {
        tx_version: 1,
        chain_id: CHAIN_ID.to_vec(),
        msg_type: MsgType::ValidatorRegister,
        sender: operator.clone(),
        nonce: 0,
        fee: 0,
        fee_tip: 0,
        gas_limit: 1_000_000,
        payload: encode_register_payload(&payload_struct),
        sig_alg_id: AlgId::MlDsa65,
        sig_key_version: 1,
        signature: vec![0u8; 3_309],
    };
    let err = apply_validator_register(&mut store, &tx).unwrap_err();
    assert!(
        matches!(err, crate::ApplyError::AlgorithmNotAllowedForConsensusKey),
        "ADR-046: ML-DSA-44 consensus keys must be rejected; got {err:?}"
    );
}

/// ADR-046 corollary: ML-DSA-65 MUST remain allowed for consensus.
/// Pins the positive side of the floor so a future over-tightening (e.g.
/// bumping the floor to Category 5) is caught by CI before it breaks live
/// validator registration.
#[test]
fn allowed_for_consensus_accepts_ml_dsa_65_adr_046() {
    use pqc_crypto::AlgId;
    assert!(AlgId::MlDsa65.allowed_for_consensus());
    assert!(AlgId::MlDsa87.allowed_for_consensus());
    assert!(AlgId::SlhDsaShake192s.allowed_for_consensus());
    assert!(!AlgId::MlDsa44.allowed_for_consensus(), "ADR-046 floor");
}

#[test]
fn validator_exit_transitions_to_unbonding() {
    let operator = Address([0x44u8; 32]);
    let mut store = store_with_operator(operator.clone(), 100_000);
    // Register first (creates Active).
    let tx_reg = validator_register_tx(operator.clone(), 0, "node-exit", ml_dsa65_pk(), 500);
    apply_validator_register(&mut store, &tx_reg).unwrap();

    // Add a second validator so the set isn't left empty.
    let op2 = Address([0x45u8; 32]);
    store.insert_validator(ValidatorRecord {
        operator: op2,
        node_id: "node-2".into(),
        consensus_alg_id: AlgId::MlDsa65,
        consensus_pk: vec![0xBBu8; 1952],
        self_bond: 0,
        status: ValidatorStatus::Active,
        registered_height: 0,
        tombstoned: false,
    });

    let tx_exit = validator_exit_tx(operator.clone(), 1);
    apply_validator_exit(&mut store, &tx_exit).expect("exit must succeed");

    let record = store.get_validator(&operator).unwrap();
    assert!(
        matches!(
            record.status,
            ValidatorStatus::Unbonding { start_height: 0 }
        ),
        "after exit: status must be Unbonding at height 0"
    );
}

#[test]
fn validator_exit_rejected_when_last_active() {
    let operator = Address([0x55u8; 32]);
    let mut store = store_with_operator(operator.clone(), 100_000);
    let tx_reg = validator_register_tx(operator.clone(), 0, "node-last", ml_dsa65_pk(), 100);
    apply_validator_register(&mut store, &tx_reg).unwrap();
    // Only one active validator — exit must be rejected.
    let tx_exit = validator_exit_tx(operator.clone(), 1);
    let err = apply_validator_exit(&mut store, &tx_exit).unwrap_err();
    assert!(matches!(err, crate::ApplyError::ValidatorExitWouldEmptySet));
}

#[test]
fn validator_unbonding_expiration_returns_bond() {
    let operator = Address([0x66u8; 32]);
    let bond = 5_000u128;
    let mut store = store_with_operator(operator.clone(), bond + 10_000);
    // Insert a second validator so we can exit without emptying the set.
    store.insert_validator(ValidatorRecord {
        operator: Address([0x67u8; 32]),
        node_id: "node-2".into(),
        consensus_alg_id: AlgId::MlDsa65,
        consensus_pk: vec![0xCCu8; 1952],
        self_bond: 0,
        status: ValidatorStatus::Active,
        registered_height: 0,
        tombstoned: false,
    });

    let tx_reg = validator_register_tx(operator.clone(), 0, "node-exp", ml_dsa65_pk(), bond);
    apply_validator_register(&mut store, &tx_reg).unwrap();
    let balance_after_bond = store.get_account(&operator).unwrap().balance;

    let tx_exit = validator_exit_tx(operator.clone(), 1);
    apply_validator_exit(&mut store, &tx_exit).unwrap();

    // Advance height past the unbonding period.
    let expiration_height = VALIDATOR_UNBONDING_PERIOD + 1;
    let exited = store.process_validator_unbonding_expirations(expiration_height);
    assert_eq!(exited.len(), 1);
    assert_eq!(exited[0].1, bond, "returned bond must equal locked amount");

    // Credit balance (mimics what engine does).
    let account = store.get_account_mut(&operator).unwrap();
    account.balance = account.balance.saturating_add(bond);

    assert_eq!(
        store.get_account(&operator).unwrap().balance,
        balance_after_bond.saturating_add(bond),
        "bond must be returned to operator after unbonding"
    );
    assert_eq!(
        store.get_validator(&operator).unwrap().status,
        ValidatorStatus::Exited
    );
}

#[test]
fn validator_unjail_returns_to_candidate() {
    let operator = Address([0x77u8; 32]);
    let mut store = store_with_operator(operator.clone(), 50_000);
    // Insert with Jailed status directly (slashing is Phase 2; jailing is admin-set in Phase 4).
    store.insert_validator(ValidatorRecord {
        operator: operator.clone(),
        node_id: "node-jailed".into(),
        consensus_alg_id: AlgId::MlDsa65,
        consensus_pk: ml_dsa65_pk(),
        self_bond: 0,
        status: ValidatorStatus::Jailed,
        registered_height: 0,
        tombstoned: false,
    });

    let tx_unjail = validator_unjail_tx(operator.clone(), 0);
    apply_validator_unjail(&mut store, &tx_unjail).expect("unjail must succeed");

    // Active set is empty (only this validator), so it should be promoted to Active.
    let record = store.get_validator(&operator).unwrap();
    assert_eq!(
        record.status,
        ValidatorStatus::Active,
        "unjailed + capacity: promoted to Active"
    );
}

#[test]
fn validator_state_root_changes_on_register() {
    let operator = Address([0x88u8; 32]);
    let mut store = store_with_operator(operator.clone(), 50_000);
    let root_before = store.state_root();

    let tx = validator_register_tx(operator.clone(), 0, "node-root", ml_dsa65_pk(), 100);
    apply_validator_register(&mut store, &tx).unwrap();
    let root_after = store.state_root();

    assert_ne!(
        root_before, root_after,
        "state root must change when validator is added"
    );
}

#[test]
fn validator_register_rejects_zero_bond() {
    let operator = Address([0x99u8; 32]);
    let mut store = store_with_operator(operator.clone(), 50_000);

    let payload_struct = ValidatorRegisterPayload {
        node_id: "node-zero".to_owned(),
        consensus_alg_id: AlgId::MlDsa65.as_u16(),
        consensus_pk: ml_dsa65_pk(),
        self_bond: 0,
        peer_id: vec![],
    };
    let tx = Transaction {
        tx_version: 1,
        chain_id: CHAIN_ID.to_vec(),
        msg_type: MsgType::ValidatorRegister,
        sender: operator.clone(),
        nonce: 0,
        fee: 0,
        fee_tip: 0,
        gas_limit: 1_000_000,
        payload: encode_register_payload(&payload_struct),
        sig_alg_id: AlgId::MlDsa65,
        sig_key_version: 1,
        signature: vec![0u8; 3_309],
    };
    let err = apply_validator_register(&mut store, &tx).unwrap_err();
    assert!(matches!(err, crate::ApplyError::ValidatorBondZero));
}

// ── AIMD adaptive fee market tests (SPEC-FEE-002 §6) ─────────────────────────

/// A fully-packed block (100% utilization) MUST increase the adaptive base fee.
///
/// At 100% utilization:
///   utilization_bips = 10_000
///   delta_bips = ALPHA(1000) × (10000 − 5000) / 10000 = 500
///   factor_num = 10000 + 500 = 10500
///   new_base_fee = current × 10500 / 10000 = current × 1.05
/// EIP-4844 (ADR-053 §T2.1): a full block MUST grow compute excess and
/// push the base fee above the reserve floor.
#[test]
fn fee_market_full_block_increases_base_fee() {
    let mut store = StateStore::new();
    let initial_fee = store.fee_market.compute.base_fee;
    let block_gas_limit = store.fee_market.compute.limit;

    store.apply_fee_market_step(block_gas_limit, 0, 0, 0);

    assert!(
        store.fee_market.compute.excess > 0,
        "full block MUST grow excess above zero"
    );
    assert!(
        store.fee_market.compute.base_fee >= initial_fee
            && store.fee_market.compute.base_fee >= crate::store::COMPUTE_RESERVE_FLOOR,
        "full block MUST not drop the base fee below the reserve floor"
    );
}

/// EIP-4844: a block at or below target utilisation MUST NOT grow
/// excess; the base fee stays at the reserve floor when starting from
/// zero excess.
#[test]
fn fee_market_empty_block_holds_base_fee_at_floor() {
    let mut store = StateStore::new();

    store.apply_fee_market_step(0, 0, 0, 0);

    assert_eq!(store.fee_market.compute.excess, 0);
    assert_eq!(
        store.fee_market.compute.base_fee,
        crate::store::COMPUTE_RESERVE_FLOOR,
        "empty block from zero excess leaves fee at the reserve floor"
    );
}

// ── Multi-step governance (TASK-100) ─────────────────────────────────────────

use crate::apply::governance::{apply_governance_vote, process_governance_tallies};
use pqc_types::governance::ProposalStatus;

/// Build a minimal GovernanceProposal transaction payload for RegistryUpdate.
fn make_governance_proposal_payload(
    proposal_type: u8,
    alg_id: Option<u16>,
    target_lifecycle: Option<u8>,
    new_min_fee: Option<u64>,
    new_burn_rate_bps: Option<u16>,
    new_block_gas_limit: Option<u64>,
) -> Vec<u8> {
    let rationale: Vec<u8> = vec![0xABu8; 32];
    let mut pairs: Vec<(u64, CborVal)> = vec![(1, CborVal::Int(proposal_type as u64))];
    if let Some(aid) = alg_id {
        pairs.push((2, CborVal::Int(aid as u64)));
    }
    if let Some(lc) = target_lifecycle {
        pairs.push((3, CborVal::Int(lc as u64)));
    }
    if let Some(fee) = new_min_fee {
        pairs.push((4, CborVal::Int(fee)));
    }
    pairs.push((6, CborVal::Bytes(rationale)));
    if let Some(bps) = new_burn_rate_bps {
        pairs.push((7, CborVal::Int(bps as u64)));
    }
    if let Some(lim) = new_block_gas_limit {
        pairs.push((8, CborVal::Int(lim)));
    }
    cbor_map(pairs)
}

/// Build a GovernanceVote transaction payload.
fn make_governance_vote_payload(proposal_id: [u8; 32], yes: bool) -> Vec<u8> {
    cbor_map(vec![
        (1, CborVal::Bytes(proposal_id.to_vec())),
        (2, CborVal::Int(if yes { 1 } else { 0 })),
    ])
}

/// Create a minimal sender account with one Active ML-DSA-65 key.
fn governance_sender(addr: Address, nonce: u64) -> Account {
    Account {
        address: addr.clone(),
        balance: 10_000_000,
        nonce,
        keys: KeySet(vec![KeyEntry {
            alg_id: AlgId::MlDsa65,
            pk_bytes: vec![0xFFu8; 32].into(),
            key_version: 1,
            valid_from_height: 0,
            status: KeyStatus::Active,
            allowed_tx_types: pqc_types::keyset::allowed_tx::ALL,
        }]),
        policy_version: 0,
        policy_hash: None,
        verifier_template_id: pqc_types::account::VERIFIER_TEMPLATE_ID_EOA,
        auth_data: Vec::new(),
    }
}

fn make_gov_tx(sender: Address, nonce: u64, msg_type: MsgType, payload: Vec<u8>) -> Transaction {
    Transaction {
        tx_version: 1,
        chain_id: Vec::new(),
        nonce,
        sender,
        msg_type,
        payload,
        gas_limit: 1_000_000,
        fee: 0,
        fee_tip: 0,
        sig_alg_id: AlgId::MlDsa65,
        sig_key_version: 1,
        signature: vec![],
    }
}

fn insert_active_validator(store: &mut StateStore, i: u8) -> Address {
    let addr = Address([i; 32]);
    store.insert_account(governance_sender(addr.clone(), 0));
    store.insert_validator(pqc_types::validator::ValidatorRecord {
        operator: addr.clone(),
        node_id: format!("val-{i}"),
        consensus_alg_id: AlgId::MlDsa65,
        consensus_pk: vec![i; 1952],
        self_bond: 0,
        status: pqc_types::validator::ValidatorStatus::Active,
        registered_height: 0,
        tombstoned: false,
    });
    addr
}

/// GovernanceProposal now creates a PendingProposal rather than executing immediately.
#[test]
fn governance_proposal_creates_pending_not_immediate() {
    let mut store = StateStore::new();
    let sender = Address([0x01u8; 32]);
    store.insert_account(governance_sender(sender.clone(), 0));

    let payload = make_governance_proposal_payload(
        0x01, // RegistryUpdate
        Some(AlgId::MlDsa65.as_u16()),
        None,
        Some(999),
        None,
        None,
    );
    let tx = make_gov_tx(sender.clone(), 0, MsgType::GovernanceProposal, payload);
    apply_tx(&mut store, &tx, exec_ctx(&tx)).expect("proposal tx must succeed");

    // The alg registry must NOT have changed yet (no immediate execution).
    let entry = store.alg_entry(AlgId::MlDsa65).expect("MlDsa65 must exist");
    assert_ne!(
        entry.min_fee, 999,
        "registry must not change on proposal submission"
    );

    // A pending proposal must now exist.
    let proposals = store.pending_proposals_in_order();
    assert_eq!(proposals.len(), 1, "one pending proposal must exist");
    assert_eq!(proposals[0].status, ProposalStatus::Voting);
}

/// An active validator can cast a yes or no vote on a pending proposal.
#[test]
fn governance_vote_by_active_validator_accepted() {
    let mut store = StateStore::new();
    let sender = Address([0x01u8; 32]);
    store.insert_account(governance_sender(sender.clone(), 0));
    let val_addr = insert_active_validator(&mut store, 0x02);

    let payload = make_governance_proposal_payload(
        0x01,
        Some(AlgId::MlDsa65.as_u16()),
        None,
        Some(42),
        None,
        None,
    );
    let proposal_tx = make_gov_tx(sender.clone(), 0, MsgType::GovernanceProposal, payload);
    apply_tx(&mut store, &proposal_tx, exec_ctx(&proposal_tx)).unwrap();

    let proposal_id = store.pending_proposals_in_order()[0].proposal_id.0;
    let vote_payload = make_governance_vote_payload(proposal_id, true);
    let vote_tx = make_gov_tx(val_addr.clone(), 0, MsgType::GovernanceVote, vote_payload);
    apply_tx(&mut store, &vote_tx, exec_ctx(&vote_tx)).expect("validator vote must be accepted");

    let proposal = &store.pending_proposals_in_order()[0];
    let recorded_vote = proposal.votes.get(&val_addr).copied();
    assert_eq!(recorded_vote, Some(true), "vote must be recorded as yes");
}

/// A non-validator sender is rejected with NotAnActiveValidatorForVote.
#[test]
fn governance_vote_by_non_validator_rejected() {
    let mut store = StateStore::new();
    let sender = Address([0x01u8; 32]);
    store.insert_account(governance_sender(sender.clone(), 0));
    let non_val = Address([0x99u8; 32]);
    store.insert_account(governance_sender(non_val.clone(), 0));

    let payload = make_governance_proposal_payload(
        0x01,
        Some(AlgId::MlDsa65.as_u16()),
        None,
        Some(1),
        None,
        None,
    );
    let proposal_tx = make_gov_tx(sender.clone(), 0, MsgType::GovernanceProposal, payload);
    apply_tx(&mut store, &proposal_tx, exec_ctx(&proposal_tx)).unwrap();

    let proposal_id = store.pending_proposals_in_order()[0].proposal_id.0;
    let vote_payload = make_governance_vote_payload(proposal_id, true);
    let vote_tx = make_gov_tx(non_val.clone(), 0, MsgType::GovernanceVote, vote_payload);
    let result = apply_governance_vote(&mut store, &vote_tx);
    assert!(
        matches!(
            result,
            Err(crate::error::ApplyError::NotAnActiveValidatorForVote)
        ),
        "non-validator must be rejected: {result:?}"
    );
}

/// When quorum passes with majority yes, the proposal is executed.
#[test]
fn governance_tally_executes_on_quorum() {
    let mut store = StateStore::new();
    let sender = Address([0x01u8; 32]);
    store.insert_account(governance_sender(sender.clone(), 0));
    let val1 = insert_active_validator(&mut store, 0x10);
    let val2 = insert_active_validator(&mut store, 0x11);
    let val3 = insert_active_validator(&mut store, 0x12);

    // Submit a RegistryUpdate proposal — change MlDsa65 min_fee to 7777.
    let payload = make_governance_proposal_payload(
        0x01,
        Some(AlgId::MlDsa65.as_u16()),
        None,
        Some(7777),
        None,
        None,
    );
    let proposal_tx = make_gov_tx(sender.clone(), 0, MsgType::GovernanceProposal, payload);
    apply_tx(&mut store, &proposal_tx, exec_ctx(&proposal_tx)).unwrap();

    let proposal_id = store.pending_proposals_in_order()[0].proposal_id.0;

    // Three active validators; quorum = ceil(2/3 * 3) = 2.
    for (val, yes) in [(&val1, true), (&val2, true), (&val3, false)] {
        let vote_payload = make_governance_vote_payload(proposal_id, yes);
        let vote_tx = make_gov_tx(val.clone(), 0, MsgType::GovernanceVote, vote_payload);
        apply_governance_vote(&mut store, &vote_tx).expect("vote must succeed");
    }

    // Tally at a height past the deadline.
    let deadline = store.pending_proposals_in_order()[0].voting_deadline;
    process_governance_tallies(&mut store, deadline + 1);

    let proposal = store.pending_proposals_in_order()[0];
    assert_eq!(
        proposal.status,
        ProposalStatus::Executed,
        "proposal must be executed"
    );
    // Registry must be updated.
    assert_eq!(
        store.alg_entry(AlgId::MlDsa65).unwrap().min_fee,
        7777,
        "min_fee must have been updated"
    );
}

/// When quorum is not reached, the proposal expires.
#[test]
fn governance_tally_expires_on_low_turnout() {
    let mut store = StateStore::new();
    let sender = Address([0x01u8; 32]);
    store.insert_account(governance_sender(sender.clone(), 0));
    insert_active_validator(&mut store, 0x20);
    insert_active_validator(&mut store, 0x21);
    insert_active_validator(&mut store, 0x22);

    let payload = make_governance_proposal_payload(
        0x01,
        Some(AlgId::MlDsa65.as_u16()),
        None,
        Some(9999),
        None,
        None,
    );
    let proposal_tx = make_gov_tx(sender.clone(), 0, MsgType::GovernanceProposal, payload);
    apply_tx(&mut store, &proposal_tx, exec_ctx(&proposal_tx)).unwrap();

    // No votes cast — quorum (2) is not reached.
    let deadline = store.pending_proposals_in_order()[0].voting_deadline;
    process_governance_tallies(&mut store, deadline + 1);

    let proposal = store.pending_proposals_in_order()[0];
    assert_eq!(
        proposal.status,
        ProposalStatus::Expired,
        "proposal must expire when quorum not met"
    );
    // Registry must not change.
    assert_ne!(
        store.alg_entry(AlgId::MlDsa65).unwrap().min_fee,
        9999,
        "min_fee must not change when proposal expires"
    );
}

/// A BurnRateUpdate proposal changes fee_market.burn_rate_bps on execution.
#[test]
fn governance_burn_rate_update_applies_on_execute() {
    let mut store = StateStore::new();
    let sender = Address([0x01u8; 32]);
    store.insert_account(governance_sender(sender.clone(), 0));
    let val1 = insert_active_validator(&mut store, 0x30);
    let val2 = insert_active_validator(&mut store, 0x31);

    assert_eq!(
        store.fee_market.burn_rate_bps, 0,
        "initial burn_rate_bps must be 0"
    );

    let payload = make_governance_proposal_payload(
        0x02,
        None,
        None,
        None,
        Some(500),
        None, // BurnRateUpdate: 500 bps = 5%
    );
    let proposal_tx = make_gov_tx(sender.clone(), 0, MsgType::GovernanceProposal, payload);
    apply_tx(&mut store, &proposal_tx, exec_ctx(&proposal_tx)).unwrap();

    let proposal_id = store.pending_proposals_in_order()[0].proposal_id.0;

    // Two active validators; quorum = ceil(2/3 * 2) = 2.
    for val in [&val1, &val2] {
        let vote_payload = make_governance_vote_payload(proposal_id, true);
        let vote_tx = make_gov_tx(val.clone(), 0, MsgType::GovernanceVote, vote_payload);
        apply_governance_vote(&mut store, &vote_tx).expect("vote must succeed");
    }

    let deadline = store.pending_proposals_in_order()[0].voting_deadline;
    process_governance_tallies(&mut store, deadline + 1);

    assert_eq!(
        store.pending_proposals_in_order()[0].status,
        ProposalStatus::Executed,
        "proposal must be executed"
    );
    assert_eq!(
        store.fee_market.burn_rate_bps, 500,
        "burn_rate_bps must have been updated to 500"
    );
}

/// ADR-053 §T2.1: the compute base fee MUST NOT drop below
/// `COMPUTE_RESERVE_FLOOR` even when excess collapses to zero.
#[test]
fn fee_market_respects_reserve_floor() {
    let mut store = StateStore::new();
    store.fee_market.compute.excess = 0;
    store.fee_market.compute.base_fee = crate::store::COMPUTE_RESERVE_FLOOR;

    // Under-utilised block on zero excess → fake_exponential returns
    // the reserve floor exactly.
    store.apply_fee_market_step(0, 0, 0, 0);

    assert_eq!(
        store.fee_market.compute.base_fee,
        crate::store::COMPUTE_RESERVE_FLOOR,
        "base_fee must pin at COMPUTE_RESERVE_FLOOR when excess is zero"
    );
}

/// At exactly the compute target, excess stays at zero and the base
/// fee remains at the reserve floor.
#[test]
fn fee_market_stable_at_target_utilisation() {
    let mut store = StateStore::new();
    let target = store.fee_market.compute.target;

    store.apply_fee_market_step(target, 0, 0, 0);

    assert_eq!(store.fee_market.compute.excess, 0);
    assert_eq!(
        store.fee_market.compute.base_fee,
        crate::store::COMPUTE_RESERVE_FLOOR,
        "at target usage the base fee stays at the reserve floor"
    );
}

// ── Phase 8 M2 (TASK-113) — epoch churn-limit enforcement ─────────────────────

/// Build an Active/Candidate record directly without going through
/// `apply_validator_register`. The register path has a capacity
/// shortcut that promotes straight to Active when `active_count <
/// VALIDATOR_MAX_ACTIVE_SET_SIZE`, which is the opposite of what we
/// want to exercise here — we need the Candidate queue to hold more
/// than the per-epoch churn limit so the limit is observable.
fn mk_churn_validator(op_byte: u8, status: ValidatorStatus) -> ValidatorRecord {
    ValidatorRecord {
        operator: Address([op_byte; 32]),
        node_id: format!("churn-{op_byte:02x}"),
        consensus_alg_id: AlgId::MlDsa65,
        consensus_pk: vec![op_byte; 1952],
        self_bond: 1_000,
        status,
        // registered_height staggered so `validator_candidates_ordered`
        // (sorts by registered_height asc, then operator) is
        // deterministic and observable.
        registered_height: op_byte as u64,
        tombstoned: false,
    }
}

/// Churn config used by the activation tests below: a 4_000-venom floor
/// combined with candidates whose `self_bond = 1_000` produces a
/// predictable per-epoch cap of 4 activations, matching the semantics
/// the original count-based `max(4, active/256)` tests exercised while
/// routing through the new stake-weighted path (ADR-053 §T1.5).
fn test_churn_floor_4k() -> ChurnConfig {
    ChurnConfig {
        activation_target_bps: 0,
        activation_min_stake: 4_000,
        exit_target_bps: 0,
        exit_min_stake: 0,
    }
}

#[test]
fn epoch_transition_activates_at_most_churn_limit_candidates() {
    //! The core churn-limit invariant (ADR-053 §T1.5). M2 Step 6-lite:
    //! submit 7 candidates into a state with 0 active — under a 4_000-
    //! venom activation floor and `self_bond = 1_000` per candidate,
    //! exactly the first 4 (sorted by `registered_height` asc) become
    //! Active; the other 3 stay Candidate and wait for the next epoch.
    let mut store = StateStore::new();
    for i in 1u8..=7 {
        store.insert_validator(mk_churn_validator(i, ValidatorStatus::Candidate));
    }
    assert_eq!(store.active_validator_count(), 0, "baseline: no Actives");

    // Epoch boundary at height 60 (devnet default epoch_duration).
    store.process_epoch_transitions(60, 60, 120, &test_churn_floor_4k());

    assert_eq!(
        store.active_validator_count(),
        4,
        "stake-weighted limit floor 4_000 / self_bond 1_000 = 4 activations"
    );
    let remaining_candidates: Vec<u8> = store
        .validator_candidates_ordered()
        .iter()
        .map(|addr| addr.0[0])
        .collect();
    assert_eq!(
        remaining_candidates,
        vec![5, 6, 7],
        "candidates 5..=7 stay in the queue — sorted by \
         registered_height ascending, so the earliest 4 activated"
    );
}

#[test]
fn epoch_transition_is_idempotent_when_queue_empty() {
    //! Calling `process_epoch_transitions` on a state with no
    //! candidates must be a no-op — no spurious state mutations
    //! that would shift the state_root between nodes.
    let mut store = StateStore::new();
    for i in 1u8..=3 {
        store.insert_validator(mk_churn_validator(i, ValidatorStatus::Active));
    }
    let root_before = store.state_root();

    store.process_epoch_transitions(60, 60, 120, &test_churn_floor_4k());

    let root_after = store.state_root();
    assert_eq!(
        root_before, root_after,
        "empty-queue epoch transitions MUST NOT mutate state_root"
    );
    assert_eq!(store.active_validator_count(), 3);
}

#[test]
fn epoch_transition_second_run_drains_remaining_queue() {
    //! Sanity check that the next epoch boundary picks up what the
    //! previous one left behind. Submit 6 candidates, run the
    //! transition twice — first activates 4, second activates the
    //! remaining 2.
    let mut store = StateStore::new();
    for i in 1u8..=6 {
        store.insert_validator(mk_churn_validator(i, ValidatorStatus::Candidate));
    }

    store.process_epoch_transitions(60, 60, 120, &test_churn_floor_4k());
    assert_eq!(store.active_validator_count(), 4);
    assert_eq!(store.validator_candidates_ordered().len(), 2);

    // Second epoch boundary — the 4 Actives now contribute 4_000 of
    // self-bond, which combined with the 4_000-venom floor still
    // permits draining the remaining 2 candidates (2_000 total).
    store.process_epoch_transitions(120, 60, 120, &test_churn_floor_4k());
    assert_eq!(store.active_validator_count(), 6);
    assert!(
        store.validator_candidates_ordered().is_empty(),
        "all candidates should have activated across two boundaries"
    );
}

#[test]
fn epoch_transition_progress_guarantee_activates_one_with_zero_stake() {
    //! ADR-053 §T1.5 progress guarantee: even when `active_stake = 0`
    //! and the config has no `activation_min_stake` floor, the first
    //! candidate in FIFO order MUST still activate. Otherwise a
    //! freshly-bootstrapped network would deadlock at zero
    //! activations forever.
    let mut store = StateStore::new();
    for i in 1u8..=3 {
        store.insert_validator(mk_churn_validator(i, ValidatorStatus::Candidate));
    }

    store.process_epoch_transitions(60, 60, 120, &ChurnConfig::viper_pq_1());

    assert_eq!(
        store.active_validator_count(),
        1,
        "progress guarantee: at least one candidate activates even \
         with limit = 0"
    );
    let remaining: Vec<u8> = store
        .validator_candidates_ordered()
        .iter()
        .map(|addr| addr.0[0])
        .collect();
    assert_eq!(remaining, vec![2, 3], "FIFO: operator 0x01 activated first");
}

// ── ADR-049 AddAlgorithm + ADR-050 SlashingRegistry (D-05 + D-01) ─────────────

/// Build an AddAlgorithm CBOR payload. `None` fields are omitted so the
/// decode path exercises its "missing required field" branch when they are
/// required.
#[allow(clippy::too_many_arguments)]
fn make_add_algorithm_payload(
    alg_id: u16,
    spec_ref: Option<&str>,
    pk_size: Option<u32>,
    sig_size: Option<u32>,
    sig_class: Option<u8>,
    min_fee: Option<u64>,
    benchmark_verify_per_sec: Option<u32>,
    initial_lifecycle: Option<u8>,
) -> Vec<u8> {
    use ciborium::value::Value;
    let rationale = vec![0xAAu8; 32];
    let mut entries: Vec<(Value, Value)> = vec![
        // proposal_type = 0x05 (AddAlgorithm)
        (Value::Integer(1u32.into()), Value::Integer(5u32.into())),
        (
            Value::Integer(2u32.into()),
            Value::Integer((alg_id as u32).into()),
        ),
        (Value::Integer(6u32.into()), Value::Bytes(rationale)),
    ];
    if let Some(s) = spec_ref {
        entries.push((Value::Integer(11u32.into()), Value::Text(s.to_string())));
    }
    if let Some(v) = pk_size {
        entries.push((Value::Integer(12u32.into()), Value::Integer(v.into())));
    }
    if let Some(v) = sig_size {
        entries.push((Value::Integer(13u32.into()), Value::Integer(v.into())));
    }
    if let Some(v) = sig_class {
        entries.push((
            Value::Integer(14u32.into()),
            Value::Integer((v as u32).into()),
        ));
    }
    if let Some(v) = initial_lifecycle {
        entries.push((
            Value::Integer(15u32.into()),
            Value::Integer((v as u32).into()),
        ));
    }
    if let Some(v) = benchmark_verify_per_sec {
        entries.push((Value::Integer(16u32.into()), Value::Integer(v.into())));
    }
    if let Some(v) = min_fee {
        entries.push((Value::Integer(4u32.into()), Value::Integer(v.into())));
    }
    let mut out = Vec::new();
    ciborium::into_writer(&Value::Map(entries), &mut out).unwrap();
    out
}

/// Build an AddSlashingVerifier CBOR payload.
#[allow(clippy::too_many_arguments)]
fn make_add_slashing_verifier_payload(
    evidence_type: u8,
    spec_ref: &str,
    slash_fraction_bps: u16,
    jail_duration_blocks: u64,
    tombstone: bool,
    lifecycle: u8,
) -> Vec<u8> {
    use ciborium::value::Value;
    let rationale = vec![0xBBu8; 32];
    let entries: Vec<(Value, Value)> = vec![
        (Value::Integer(1u32.into()), Value::Integer(6u32.into())), // proposal_type=0x06
        (Value::Integer(6u32.into()), Value::Bytes(rationale)),
        (
            Value::Integer(30u32.into()),
            Value::Integer((evidence_type as u32).into()),
        ),
        (
            Value::Integer(31u32.into()),
            Value::Text(spec_ref.to_string()),
        ),
        (
            Value::Integer(32u32.into()),
            Value::Integer((slash_fraction_bps as u32).into()),
        ),
        (
            Value::Integer(33u32.into()),
            Value::Integer(jail_duration_blocks.into()),
        ),
        (
            Value::Integer(34u32.into()),
            Value::Integer(if tombstone { 1u32.into() } else { 0u32.into() }),
        ),
        (
            Value::Integer(35u32.into()),
            Value::Integer((lifecycle as u32).into()),
        ),
    ];
    let mut out = Vec::new();
    ciborium::into_writer(&Value::Map(entries), &mut out).unwrap();
    out
}

/// Shared setup: sender account, N active validators, submit a proposal and
/// collect enough yes votes to pass quorum.  Returns the proposal_id.
fn land_proposal_pass_quorum(
    store: &mut StateStore,
    sender: &Address,
    payload: Vec<u8>,
    num_validators: u8,
) -> [u8; 32] {
    let proposal_tx = make_gov_tx(sender.clone(), 0, MsgType::GovernanceProposal, payload);
    apply_tx(store, &proposal_tx, exec_ctx(&proposal_tx)).expect("proposal tx must apply");
    let proposal_id = store.pending_proposals_in_order()[0].proposal_id.0;

    let mut validators: Vec<Address> = Vec::new();
    for i in 0..num_validators {
        validators.push(insert_active_validator(store, 0x90 + i));
    }

    for val in &validators {
        let vote_payload = make_governance_vote_payload(proposal_id, true);
        let vote_tx = make_gov_tx(val.clone(), 0, MsgType::GovernanceVote, vote_payload);
        apply_governance_vote(store, &vote_tx).expect("vote must succeed");
    }

    proposal_id
}

/// AddAlgorithm proposal with an alg_id that already exists must end up in
/// ExecutionFailed at tally (registry unchanged).  We exercise the
/// tally path because CBOR-level accept still admits the proposal; the
/// duplicate check happens at state-apply time.
#[test]
fn add_algorithm_proposal_rejects_duplicate_alg_id() {
    let mut store = StateStore::new();
    let sender = Address([0x01u8; 32]);
    store.insert_account(governance_sender(sender.clone(), 0));

    // MlDsa65 (0x0002) is already in the phase1 registry — proposing it
    // again must fail at tally-time.  BUT alg_id 0x0002 is in the reserved
    // range (<=0x000F), so it would be rejected at the CBOR decode stage.
    // Use 0x0020 (SlhDsaSha2128s) which is already registered AND outside
    // the reserved range, so the decoder accepts it and the duplicate check
    // happens at tally.
    let payload = make_add_algorithm_payload(
        AlgId::SlhDsaSha2128s.as_u16(),
        Some("FIPS 205 duplicate"),
        Some(32),
        Some(7_856),
        Some(3),
        Some(0),
        Some(951),
        Some(0),
    );
    land_proposal_pass_quorum(&mut store, &sender, payload, 2);

    let deadline = store.pending_proposals_in_order()[0].voting_deadline;
    crate::apply::governance::process_governance_tallies(&mut store, deadline + 1);

    let proposal = store.pending_proposals_in_order()[0];
    assert_eq!(
        proposal.status,
        ProposalStatus::ExecutionFailed,
        "duplicate alg_id proposal must end in ExecutionFailed"
    );
}

/// AddAlgorithm proposal with an alg_id in the reserved range must be
/// rejected at submission time (CBOR decode + validate).
#[test]
fn add_algorithm_proposal_rejects_reserved_range() {
    let mut store = StateStore::new();
    let sender = Address([0x01u8; 32]);
    store.insert_account(governance_sender(sender.clone(), 0));

    // alg_id 0x0005 is inside 0x0000..=0x000F reserved core range.
    let payload = make_add_algorithm_payload(
        0x0005,
        Some("FIPS future"),
        Some(2_048),
        Some(3_500),
        Some(2),
        Some(0),
        Some(50_000),
        Some(0),
    );
    let tx = make_gov_tx(sender.clone(), 0, MsgType::GovernanceProposal, payload);
    let res = apply_tx(&mut store, &tx, exec_ctx(&tx));
    assert!(
        matches!(
            res,
            Err(crate::error::ApplyError::ReservedAlgIdRange(0x0005))
        ),
        "reserved-range alg_id proposal must be rejected at submission: {res:?}"
    );
    assert!(
        store.pending_proposals_in_order().is_empty(),
        "no pending proposal must be created"
    );
}

/// AddAlgorithm proposal with sig_size >= 256 KB must be rejected at submission.
#[test]
fn add_algorithm_proposal_rejects_oversized_sig() {
    let mut store = StateStore::new();
    let sender = Address([0x01u8; 32]);
    store.insert_account(governance_sender(sender.clone(), 0));

    // sig_size = 300 KB — beyond the 256 KB envelope.
    let payload = make_add_algorithm_payload(
        0x0500,
        Some("mega-alg"),
        Some(2_048),
        Some(300 * 1024),
        Some(2),
        Some(0),
        Some(100),
        Some(0),
    );
    let tx = make_gov_tx(sender.clone(), 0, MsgType::GovernanceProposal, payload);
    let res = apply_tx(&mut store, &tx, exec_ctx(&tx));
    assert!(
        matches!(res, Err(crate::error::ApplyError::InvalidSize)),
        "oversized-sig proposal must be rejected at submission: {res:?}"
    );
}

/// AddAlgorithm proposal with a well-formed payload targets an alg_id that
/// the COMPILED binary does not yet know.  After timelock, the registry is
/// unchanged (ExecutionFailed) because `AlgId::from_u16` returns None —
/// this is the two-phase rollout documented in ADR-049: metadata proposal
/// first, binary upgrade (SoftwareUpgrade) second.
#[test]
fn add_algorithm_proposal_active_after_timelock() {
    let mut store = StateStore::new();
    let sender = Address([0x01u8; 32]);
    store.insert_account(governance_sender(sender.clone(), 0));

    // 0x0500 is outside reserved, outside registered — decoder accepts.
    let payload = make_add_algorithm_payload(
        0x0500,
        Some("FIPS-future"),
        Some(2_048),
        Some(3_500),
        Some(2),
        Some(0),
        Some(50_000),
        Some(0),
    );
    land_proposal_pass_quorum(&mut store, &sender, payload, 2);
    let deadline = store.pending_proposals_in_order()[0].voting_deadline;
    crate::apply::governance::process_governance_tallies(&mut store, deadline + 1);

    // Status reflects that tally decided to apply (quorum met), but the
    // effect could not materialize because the binary doesn't know 0x0500.
    let proposal = store.pending_proposals_in_order()[0];
    assert_eq!(
        proposal.status,
        ProposalStatus::ExecutionFailed,
        "unknown alg_id proposal ends in ExecutionFailed, documenting the two-phase rollout"
    );
    assert!(
        !store.alg_entry_registered(0x0500),
        "registry must not contain an unknown-to-binary alg_id"
    );
}

/// AddSlashingVerifier proposal duplicating an existing evidence_type is
/// rejected at tally (post-decode, duplicate check needs state access).
#[test]
fn add_slashing_verifier_proposal_rejects_duplicate_type() {
    let mut store = StateStore::new();
    let sender = Address([0x01u8; 32]);
    store.insert_account(governance_sender(sender.clone(), 0));

    // First seed a non-core entry at 0x20 via the insert helper so the
    // AddSlashingVerifier path hits a duplicate on the same discriminant.
    store.insert_slashing_verifier_entry(pqc_types::governance::SlashingVerifierEntry {
        evidence_type: 0x20,
        spec_ref: "seeded-dupe".into(),
        slash_fraction_bps: 100,
        jail_duration_blocks: 0,
        tombstone: false,
        lifecycle: Lifecycle::Active,
    });

    let payload = make_add_slashing_verifier_payload(
        0x20, "second", 500, 10_000, false, 0, // Active
    );
    land_proposal_pass_quorum(&mut store, &sender, payload, 2);
    let deadline = store.pending_proposals_in_order()[0].voting_deadline;
    crate::apply::governance::process_governance_tallies(&mut store, deadline + 1);

    let proposal = store.pending_proposals_in_order()[0];
    assert_eq!(
        proposal.status,
        ProposalStatus::ExecutionFailed,
        "duplicate evidence_type must end in ExecutionFailed"
    );
    // Registry still has the ORIGINAL entry (spec_ref unchanged).
    let entry = store.slashing_verifier_entry(0x20).unwrap();
    assert_eq!(entry.spec_ref, "seeded-dupe");
}

/// AddSlashingVerifier proposal with a fresh non-reserved evidence_type
/// lands in the registry after the voting period closes.
#[test]
fn add_slashing_verifier_proposal_lands_after_timelock() {
    let mut store = StateStore::new();
    let sender = Address([0x01u8; 32]);
    store.insert_account(governance_sender(sender.clone(), 0));

    // 0x10 is the first non-reserved evidence_type (0x00 sentinel +
    // 0x01..=0x0F core types reserved).
    let payload = make_add_slashing_verifier_payload(
        0x10,
        "data-withholding (ADR-050 example)",
        250, // 2.5%
        50_000,
        false,
        0, // Active
    );
    land_proposal_pass_quorum(&mut store, &sender, payload, 2);
    let deadline = store.pending_proposals_in_order()[0].voting_deadline;
    crate::apply::governance::process_governance_tallies(&mut store, deadline + 1);

    let proposal = store.pending_proposals_in_order()[0];
    assert_eq!(
        proposal.status,
        ProposalStatus::Executed,
        "well-formed AddSlashingVerifier must execute"
    );
    let entry = store
        .slashing_verifier_entry(0x10)
        .expect("new slashing verifier must be registered");
    assert_eq!(entry.slash_fraction_bps, 250);
    assert_eq!(entry.jail_duration_blocks, 50_000);
    assert!(!entry.tombstone);
    assert_eq!(entry.lifecycle, Lifecycle::Active);
}

/// The seeded 0x01 equivocation entry drives the effective slash fraction.
/// Changing it via the `commit_slashing_verifier_mutation` path makes
/// `effective_slash_fraction_bps(0x01)` return the new value — the helper
/// that `apply_submit_equivocation_evidence` will read under ADR-050's
/// Phase-2 wiring.
#[test]
fn equivocation_applies_registry_driven_slash_fraction() {
    let mut store = StateStore::new();

    // Seed at genesis = 500 bps (matches SPEC-SLASH-001 §10 constant).
    assert_eq!(
        store.effective_slash_fraction_bps(0x01),
        500,
        "genesis-seeded equivocation fraction must match the hardcoded 5%"
    );

    // Deletion-and-reinsert at a new fraction (simulating governance
    // RegistryUpdate-style mutation — the actual RegistryUpdate wiring for
    // slashing entries is out of scope for the present commit; this is the
    // shape the Phase-2 wiring will take).
    store.insert_slashing_verifier_entry(pqc_types::governance::SlashingVerifierEntry {
        evidence_type: 0x01,
        spec_ref: "post-gov-update".into(),
        slash_fraction_bps: 700, // 7% — hypothetical post-governance tuning
        jail_duration_blocks: 0,
        tombstone: true,
        lifecycle: Lifecycle::Active,
    });

    assert_eq!(
        store.effective_slash_fraction_bps(0x01),
        700,
        "registry-driven fraction must override the seed"
    );

    // And for unregistered types the default const applies.  This keeps
    // snapshot restores from pre-ADR-050 checkpoints byte-stable.
    assert_eq!(
        store.effective_slash_fraction_bps(0xFF),
        crate::store::DEFAULT_EQUIVOCATION_SLASH_FRACTION_BPS,
        "unregistered type falls back to default"
    );
}

// ── ADR-053 §T1.4 AddHash governance + hash registry seeding ──────────────────

/// Build an AddHash CBOR payload (fields 40..=43).
fn make_add_hash_payload(
    hash_id_byte: u8,
    spec_ref: &str,
    output_size_bytes: u32,
    lifecycle: u8,
) -> Vec<u8> {
    use ciborium::value::Value;
    let rationale = vec![0xCCu8; 32];
    let entries: Vec<(Value, Value)> = vec![
        (Value::Integer(1u32.into()), Value::Integer(7u32.into())), // proposal_type=0x07
        (Value::Integer(6u32.into()), Value::Bytes(rationale)),
        (
            Value::Integer(40u32.into()),
            Value::Integer((hash_id_byte as u32).into()),
        ),
        (
            Value::Integer(41u32.into()),
            Value::Text(spec_ref.to_string()),
        ),
        (
            Value::Integer(42u32.into()),
            Value::Integer(output_size_bytes.into()),
        ),
        (
            Value::Integer(43u32.into()),
            Value::Integer((lifecycle as u32).into()),
        ),
    ];
    let mut out = Vec::new();
    ciborium::into_writer(&Value::Map(entries), &mut out).unwrap();
    out
}

/// Genesis hash registry is seeded with the single SHAKE-256 entry.
#[test]
fn hash_registry_seeded_at_genesis() {
    let store = StateStore::new();
    let entries = store.hash_registry_entries_in_order();
    assert_eq!(
        entries.len(),
        1,
        "genesis hash registry must have exactly one entry"
    );
    let entry = entries[0];
    assert_eq!(entry.hash_id, pqc_crypto::HashId::SHAKE_256);
    assert_eq!(entry.output_size_bytes, 32);
    assert_eq!(entry.lifecycle, Lifecycle::Active);
}

/// AddHash proposal in the reserved core range (0x00 sentinel or 0x01..=0x0F)
/// must be rejected at CBOR decode time.
#[test]
fn add_hash_proposal_rejects_reserved_range() {
    let mut store = StateStore::new();
    let sender = Address([0x01u8; 32]);
    store.insert_account(governance_sender(sender.clone(), 0));

    // hash_id 0x05 is inside 0x01..=0x0F reserved core range.
    let payload = make_add_hash_payload(0x05, "reserved", 32, 0);
    let tx = make_gov_tx(sender.clone(), 0, MsgType::GovernanceProposal, payload);
    let res = apply_tx(&mut store, &tx, exec_ctx(&tx));
    assert!(
        matches!(
            res,
            Err(crate::error::ApplyError::ReservedHashIdRange(0x05))
        ),
        "reserved-range hash_id proposal must be rejected at submission: {res:?}"
    );
    assert!(
        store.pending_proposals_in_order().is_empty(),
        "no pending proposal must be created"
    );
}

/// AddHash proposal duplicating an existing hash_id ends in ExecutionFailed
/// at tally (post-decode, duplicate check needs state access).
#[test]
fn add_hash_proposal_rejects_duplicate() {
    let mut store = StateStore::new();
    let sender = Address([0x01u8; 32]);
    store.insert_account(governance_sender(sender.clone(), 0));

    // Seed a non-core entry at 0x20 via the insert helper so the AddHash
    // path hits a duplicate on the same hash_id.
    store.insert_hash_entry(pqc_crypto::hash_registry::HashEntry::new_governance(
        pqc_crypto::HashId(0x20),
        "seeded-dupe".into(),
        32,
        Lifecycle::Active,
    ));

    let payload = make_add_hash_payload(0x20, "second", 32, 0);
    land_proposal_pass_quorum(&mut store, &sender, payload, 2);
    let deadline = store.pending_proposals_in_order()[0].voting_deadline;
    crate::apply::governance::process_governance_tallies(&mut store, deadline + 1);

    let proposal = store.pending_proposals_in_order()[0];
    assert_eq!(
        proposal.status,
        ProposalStatus::ExecutionFailed,
        "duplicate hash_id must end in ExecutionFailed"
    );
    // Registry still has the ORIGINAL entry (spec_ref unchanged).
    let entry = store.hash_entry(pqc_crypto::HashId(0x20)).unwrap();
    assert_eq!(entry.spec_ref, "seeded-dupe");
}

/// AddHash proposal with output_size_bytes == 0 must be rejected at submission.
#[test]
fn add_hash_proposal_rejects_zero_output_size() {
    let mut store = StateStore::new();
    let sender = Address([0x01u8; 32]);
    store.insert_account(governance_sender(sender.clone(), 0));

    let payload = make_add_hash_payload(0x10, "empty-out", 0, 0);
    let tx = make_gov_tx(sender.clone(), 0, MsgType::GovernanceProposal, payload);
    let res = apply_tx(&mut store, &tx, exec_ctx(&tx));
    assert!(
        matches!(res, Err(crate::error::ApplyError::InvalidSize)),
        "zero output_size_bytes proposal must be rejected at submission: {res:?}"
    );
}

/// AddHash proposal with a fresh non-reserved hash_id lands in the registry
/// after the voting period closes.
#[test]
fn add_hash_proposal_lands_after_timelock() {
    let mut store = StateStore::new();
    let sender = Address([0x01u8; 32]);
    store.insert_account(governance_sender(sender.clone(), 0));

    // 0x10 is the first non-reserved hash_id (0x00 sentinel + 0x01..=0x0F
    // core hashes reserved).
    let payload = make_add_hash_payload(0x10, "BLAKE3 (hypothetical)", 32, 0);
    land_proposal_pass_quorum(&mut store, &sender, payload, 2);
    let deadline = store.pending_proposals_in_order()[0].voting_deadline;
    crate::apply::governance::process_governance_tallies(&mut store, deadline + 1);

    let proposal = store.pending_proposals_in_order()[0];
    assert_eq!(
        proposal.status,
        ProposalStatus::Executed,
        "well-formed AddHash must execute"
    );
    let entry = store
        .hash_entry(pqc_crypto::HashId(0x10))
        .expect("new hash entry must be registered");
    assert_eq!(entry.output_size_bytes, 32);
    assert_eq!(entry.lifecycle, Lifecycle::Active);
    assert_eq!(entry.spec_ref, "BLAKE3 (hypothetical)");
    // Registry now contains the genesis SHAKE-256 + the freshly-added entry.
    let ordered = store.hash_registry_entries_in_order();
    assert_eq!(ordered.len(), 2);
    assert_eq!(ordered[0].hash_id, pqc_crypto::HashId::SHAKE_256);
    assert_eq!(ordered[1].hash_id, pqc_crypto::HashId(0x10));
}

// ── Archival overlay (SPEC-ARCHIVAL-001 §4.5–§4.7, TASK-161) ─────────────────

mod archival_tests {
    use super::*;
    use crate::apply::archival::{
        apply_archival_record_add_anchor, apply_archival_record_renew,
        apply_archival_record_submit, apply_validator_register_archival_key,
        encode_archival_record_add_anchor_payload, encode_archival_record_renew_payload,
        encode_archival_record_submit_payload, encode_register_archival_key_payload,
        ARCHIVAL_PK_SIZE,
    };
    use crate::ApplyError;
    use pqc_crypto::sign::StubVerifier;

    /// Build a store with `count` Active validators registered, each with an
    /// SLH-DSA-SHAKE-256s archival key. Returns the operator addresses in
    /// ascending order so tests can assemble signer sets deterministically.
    fn store_with_archival_validators(count: u8) -> (StateStore, Vec<Address>) {
        let mut store = StateStore::new();
        let mut operators: Vec<Address> = Vec::with_capacity(count as usize);
        for i in 0u8..count {
            let addr = Address([i + 1; 32]);
            // Account
            store.insert_account(Account {
                address: addr.clone(),
                balance: 1_000_000,
                nonce: 0,
                keys: KeySet(vec![]),
                policy_version: 0,
                policy_hash: None,
                verifier_template_id: pqc_types::account::VERIFIER_TEMPLATE_ID_EOA,
                auth_data: Vec::new(),
            });
            // Active validator
            store.insert_validator(ValidatorRecord {
                operator: addr.clone(),
                node_id: format!("node-{i}"),
                consensus_alg_id: AlgId::MlDsa65,
                consensus_pk: vec![i + 1; 1952],
                self_bond: 1_000,
                status: ValidatorStatus::Active,
                registered_height: 0,
                tombstoned: false,
            });
            // Archival key registration via direct insert (faster than the
            // apply path for test bootstrapping; the register tests exercise
            // the apply path explicitly).
            let pk = vec![(i + 1) ^ 0x5A; ARCHIVAL_PK_SIZE];
            let tx = Transaction {
                tx_version: 1,
                chain_id: CHAIN_ID.to_vec(),
                msg_type: MsgType::ValidatorRegisterArchivalKey,
                sender: addr.clone(),
                nonce: 0,
                fee: 0,
                fee_tip: 0,
                gas_limit: 1_000_000,
                payload: encode_register_archival_key_payload(AlgId::SlhDsaShake256s.as_u16(), &pk),
                sig_alg_id: AlgId::MlDsa65,
                sig_key_version: 1,
                signature: vec![0u8; 3_309],
            };
            apply_validator_register_archival_key(&mut store, &tx)
                .expect("archival key registration must succeed");
            operators.push(addr);
        }
        (store, operators)
    }

    fn register_archival_key_tx(sender: Address, alg_id: u16, pk: Vec<u8>) -> Transaction {
        Transaction {
            tx_version: 1,
            chain_id: CHAIN_ID.to_vec(),
            msg_type: MsgType::ValidatorRegisterArchivalKey,
            sender,
            nonce: 0,
            fee: 0,
            fee_tip: 0,
            gas_limit: 1_000_000,
            payload: encode_register_archival_key_payload(alg_id, &pk),
            sig_alg_id: AlgId::MlDsa65,
            sig_key_version: 1,
            signature: vec![0u8; 3_309],
        }
    }

    #[test]
    fn validator_register_archival_key_happy_path() {
        let operator = Address([0x77u8; 32]);
        let mut store = StateStore::new();
        store.insert_account(Account {
            address: operator.clone(),
            balance: 100_000,
            nonce: 0,
            keys: KeySet(vec![]),
            policy_version: 0,
            policy_hash: None,
            verifier_template_id: pqc_types::account::VERIFIER_TEMPLATE_ID_EOA,
            auth_data: Vec::new(),
        });
        store.insert_validator(ValidatorRecord {
            operator: operator.clone(),
            node_id: "node-active".into(),
            consensus_alg_id: AlgId::MlDsa65,
            consensus_pk: vec![0x77; 1952],
            self_bond: 1_000,
            status: ValidatorStatus::Active,
            registered_height: 0,
            tombstoned: false,
        });

        let pk = vec![0xABu8; ARCHIVAL_PK_SIZE];
        let tx = register_archival_key_tx(
            operator.clone(),
            AlgId::SlhDsaShake256s.as_u16(),
            pk.clone(),
        );
        apply_validator_register_archival_key(&mut store, &tx)
            .expect("registration must succeed for Active validator");

        let key = store
            .get_archival_key(&operator)
            .expect("archival key must be present after registration");
        assert_eq!(key.archival_alg_id, AlgId::SlhDsaShake256s.as_u16());
        assert_eq!(key.archival_pk, pk);
        assert_eq!(key.operator, operator.0);

        // Resubmission rotates the key (SPEC §4.5): same operator, fresh pk.
        let pk2 = vec![0xCDu8; ARCHIVAL_PK_SIZE];
        let tx2 = register_archival_key_tx(
            operator.clone(),
            AlgId::SlhDsaShake256s.as_u16(),
            pk2.clone(),
        );
        apply_validator_register_archival_key(&mut store, &tx2)
            .expect("resubmission must rotate the key");
        let key2 = store.get_archival_key(&operator).unwrap();
        assert_eq!(key2.archival_pk, pk2);
    }

    #[test]
    fn validator_register_archival_key_rejects_non_validator() {
        let stranger = Address([0xAAu8; 32]);
        let mut store = StateStore::new();
        store.insert_account(Account {
            address: stranger.clone(),
            balance: 100_000,
            nonce: 0,
            keys: KeySet(vec![]),
            policy_version: 0,
            policy_hash: None,
            verifier_template_id: pqc_types::account::VERIFIER_TEMPLATE_ID_EOA,
            auth_data: Vec::new(),
        });
        // Deliberately no validator record for `stranger`.

        let tx = register_archival_key_tx(
            stranger,
            AlgId::SlhDsaShake256s.as_u16(),
            vec![0x00; ARCHIVAL_PK_SIZE],
        );
        let err = apply_validator_register_archival_key(&mut store, &tx).unwrap_err();
        assert!(
            matches!(err, ApplyError::ArchivalValidatorNotEligible),
            "got: {err}"
        );
    }

    #[test]
    fn validator_register_archival_key_rejects_wrong_alg() {
        let operator = Address([0x55u8; 32]);
        let mut store = StateStore::new();
        store.insert_account(Account {
            address: operator.clone(),
            balance: 100_000,
            nonce: 0,
            keys: KeySet(vec![]),
            policy_version: 0,
            policy_hash: None,
            verifier_template_id: pqc_types::account::VERIFIER_TEMPLATE_ID_EOA,
            auth_data: Vec::new(),
        });
        store.insert_validator(ValidatorRecord {
            operator: operator.clone(),
            node_id: "node-wrong-alg".into(),
            consensus_alg_id: AlgId::MlDsa65,
            consensus_pk: vec![0x55; 1952],
            self_bond: 1_000,
            status: ValidatorStatus::Active,
            registered_height: 0,
            tombstoned: false,
        });

        // ML-DSA-65 is a valid signing algorithm but NOT admissible for the
        // archival overlay (SPEC §4.5 requires SLH-DSA-SHAKE-256s).
        let tx =
            register_archival_key_tx(operator.clone(), AlgId::MlDsa65.as_u16(), vec![0xEE; 1_952]);
        let err = apply_validator_register_archival_key(&mut store, &tx).unwrap_err();
        assert!(
            matches!(err, ApplyError::ArchivalAlgorithmNotAllowed),
            "got: {err}"
        );

        // SLH-DSA-SHAKE-192s (Cat 3) is also rejected — only Cat 5 for archival.
        let tx192 = register_archival_key_tx(
            operator.clone(),
            AlgId::SlhDsaShake192s.as_u16(),
            vec![0xEE; ARCHIVAL_PK_SIZE],
        );
        let err192 = apply_validator_register_archival_key(&mut store, &tx192).unwrap_err();
        assert!(
            matches!(err192, ApplyError::ArchivalAlgorithmNotAllowed),
            "got: {err192}"
        );

        // Correct alg but wrong pk size must be rejected as InvalidPkSize.
        let tx_short =
            register_archival_key_tx(operator, AlgId::SlhDsaShake256s.as_u16(), vec![0xEE; 32]);
        let err_short = apply_validator_register_archival_key(&mut store, &tx_short).unwrap_err();
        assert!(
            matches!(err_short, ApplyError::ArchivalInvalidPkSize),
            "got: {err_short}"
        );
    }

    fn submit_tx(
        sender: Address,
        epoch_number: u64,
        first_height: u64,
        last_height: u64,
        epoch_root: &[u8; 32],
        sig_set: &[(Address, Vec<u8>)],
    ) -> Transaction {
        Transaction {
            tx_version: 1,
            chain_id: CHAIN_ID.to_vec(),
            msg_type: MsgType::ArchivalRecordSubmit,
            sender,
            nonce: 0,
            fee: 0,
            fee_tip: 0,
            gas_limit: 2_000_000,
            payload: encode_archival_record_submit_payload(
                epoch_number,
                first_height,
                last_height,
                epoch_root,
                sig_set,
            ),
            sig_alg_id: AlgId::MlDsa65,
            sig_key_version: 1,
            signature: vec![0u8; 3_309],
        }
    }

    #[test]
    fn archival_record_submit_rejects_duplicate_epoch() {
        // 4 active validators → m = ceil(2×4/3) = 3.
        let (mut store, operators) = store_with_archival_validators(4);
        let epoch_root = [0x42u8; 32];
        // 3-of-4 signer set, sorted.
        let sig_set: Vec<(Address, Vec<u8>)> = operators
            .iter()
            .take(3)
            .map(|a| (a.clone(), vec![0x33; 29_792]))
            .collect();
        let verifier = StubVerifier;

        let tx = submit_tx(operators[0].clone(), 0, 0, 59, &epoch_root, &sig_set);
        apply_archival_record_submit(&mut store, &tx, 60, &verifier)
            .expect("first submit must succeed");
        assert!(
            store.get_archival_record(0).is_some(),
            "record must be stored after first submit"
        );

        // Duplicate submit for the same epoch — must be rejected.
        let err = apply_archival_record_submit(&mut store, &tx, 60, &verifier).unwrap_err();
        assert!(
            matches!(err, ApplyError::DuplicateArchivalRecord),
            "got: {err}"
        );
    }

    #[test]
    fn archival_record_submit_rejects_below_threshold() {
        // 4 active validators → m = 3. Submit with only 2 sigs.
        let (mut store, operators) = store_with_archival_validators(4);
        let epoch_root = [0x24u8; 32];
        let sig_set: Vec<(Address, Vec<u8>)> = operators
            .iter()
            .take(2)
            .map(|a| (a.clone(), vec![0x55; 29_792]))
            .collect();
        let verifier = StubVerifier;

        let tx = submit_tx(operators[0].clone(), 0, 0, 59, &epoch_root, &sig_set);
        let err = apply_archival_record_submit(&mut store, &tx, 60, &verifier).unwrap_err();
        assert!(
            matches!(err, ApplyError::ArchivalThresholdNotMet),
            "got: {err}"
        );
        // And no record was stored.
        assert!(store.get_archival_record(0).is_none());
    }

    #[test]
    fn archival_record_add_anchor_updates_record() {
        let (mut store, operators) = store_with_archival_validators(4);
        let epoch_root = [0x99u8; 32];
        let sig_set: Vec<(Address, Vec<u8>)> = operators
            .iter()
            .take(3)
            .map(|a| (a.clone(), vec![0x77; 29_792]))
            .collect();
        let verifier = StubVerifier;

        let submit = submit_tx(operators[0].clone(), 0, 0, 59, &epoch_root, &sig_set);
        apply_archival_record_submit(&mut store, &submit, 60, &verifier).unwrap();

        let state_root_before_anchor = store.state_root();

        // Any account can submit an anchor — use a non-validator address.
        let any_account = Address([0xF0u8; 32]);
        store.insert_account(Account {
            address: any_account.clone(),
            balance: 10_000,
            nonce: 0,
            keys: KeySet(vec![]),
            policy_version: 0,
            policy_hash: None,
            verifier_template_id: pqc_types::account::VERIFIER_TEMPLATE_ID_EOA,
            auth_data: Vec::new(),
        });
        let tst_bytes = vec![0xABu8; 256];
        let external_hash = vec![0x11u8; 32];
        let anchor_tx = Transaction {
            tx_version: 1,
            chain_id: CHAIN_ID.to_vec(),
            msg_type: MsgType::ArchivalRecordAddAnchor,
            sender: any_account.clone(),
            nonce: 0,
            fee: 0,
            fee_tip: 0,
            gas_limit: 1_000_000,
            payload: encode_archival_record_add_anchor_payload(
                0,
                0x01, // Rfc3161EuQualified
                &tst_bytes,
                &external_hash,
                1_700_000_000,
            ),
            sig_alg_id: AlgId::MlDsa65,
            sig_key_version: 1,
            signature: vec![0u8; 3_309],
        };
        apply_archival_record_add_anchor(&mut store, &anchor_tx, 70)
            .expect("anchor attach must succeed");

        let record = store.get_archival_record(0).unwrap();
        assert_eq!(record.timestamp_anchors.len(), 1);
        let anchor = &record.timestamp_anchors[0];
        // D1's TimestampAnchor holds external_hash (not tst_bytes/created_at),
        // plus kind + optional tsa_ref + posted_at_height.
        assert_eq!(anchor.external_hash, external_hash);
        assert_eq!(anchor.posted_at_height, 70);
        assert_eq!(
            anchor.kind,
            pqc_types::archival::AnchorKind::Rfc3161Tsa,
            "wire code 0x01 decodes to Rfc3161Tsa"
        );
        assert!(anchor.tsa_ref.is_none());
        // tst_bytes and created_at are not stored (M4.2 slice) — the wire
        // payload still carries them, but M4.5 sidecar will fill tsa_ref from
        // TST parsing.
        let _unused_until_m4_5 = (tst_bytes, 1_700_000_000u64);

        // State root must change after the anchor attach (the leaf hash folds
        // the timestamp_anchors array).
        let state_root_after_anchor = store.state_root();
        assert_ne!(
            state_root_before_anchor, state_root_after_anchor,
            "anchor attach must mutate state_root"
        );

        // Rejecting unknown anchor kind.
        let bad_tx = Transaction {
            tx_version: 1,
            chain_id: CHAIN_ID.to_vec(),
            msg_type: MsgType::ArchivalRecordAddAnchor,
            sender: any_account,
            nonce: 1,
            fee: 0,
            fee_tip: 0,
            gas_limit: 1_000_000,
            payload: encode_archival_record_add_anchor_payload(
                0,
                0xEE, // unknown
                &[],
                &[],
                0,
            ),
            sig_alg_id: AlgId::MlDsa65,
            sig_key_version: 1,
            signature: vec![0u8; 3_309],
        };
        let err = apply_archival_record_add_anchor(&mut store, &bad_tx, 71).unwrap_err();
        assert!(matches!(err, ApplyError::ArchivalUnknownAnchorKind));
    }

    #[test]
    fn archival_record_renew_increments_version() {
        let (mut store, operators) = store_with_archival_validators(4);
        let epoch_root = [0x11u8; 32];
        let sig_set: Vec<(Address, Vec<u8>)> = operators
            .iter()
            .take(3)
            .map(|a| (a.clone(), vec![0x22; 29_792]))
            .collect();
        let verifier = StubVerifier;
        let submit = submit_tx(operators[0].clone(), 0, 0, 59, &epoch_root, &sig_set);
        apply_archival_record_submit(&mut store, &submit, 60, &verifier).unwrap();

        // Sanity: version = 0 before first renewal.
        assert_eq!(
            store
                .get_archival_record(0)
                .unwrap()
                .evidence_record_version,
            0
        );

        // Renew: sender is Active validator `operators[0]` — admitted.
        let ers_hash = [0xBBu8; 32];
        let renew_tx = Transaction {
            tx_version: 1,
            chain_id: CHAIN_ID.to_vec(),
            msg_type: MsgType::ArchivalRecordRenew,
            sender: operators[0].clone(),
            nonce: 0,
            fee: 0,
            fee_tip: 0,
            gas_limit: 1_000_000,
            payload: encode_archival_record_renew_payload(0, &ers_hash),
            sig_alg_id: AlgId::MlDsa65,
            sig_key_version: 1,
            signature: vec![0u8; 3_309],
        };
        apply_archival_record_renew(&mut store, &renew_tx, 80).expect("renew must succeed");
        assert_eq!(
            store
                .get_archival_record(0)
                .unwrap()
                .evidence_record_version,
            1
        );

        // Second renew → version = 2.
        let renew_tx2 = Transaction {
            tx_version: 1,
            chain_id: CHAIN_ID.to_vec(),
            msg_type: MsgType::ArchivalRecordRenew,
            sender: operators[0].clone(),
            nonce: 1,
            fee: 0,
            fee_tip: 0,
            gas_limit: 1_000_000,
            payload: encode_archival_record_renew_payload(0, &[0xCC; 32]),
            sig_alg_id: AlgId::MlDsa65,
            sig_key_version: 1,
            signature: vec![0u8; 3_309],
        };
        apply_archival_record_renew(&mut store, &renew_tx2, 90).expect("second renew must succeed");
        assert_eq!(
            store
                .get_archival_record(0)
                .unwrap()
                .evidence_record_version,
            2
        );

        // Non-validator, non-renewer address must be rejected.
        let stranger = Address([0xEEu8; 32]);
        let renew_bad = Transaction {
            tx_version: 1,
            chain_id: CHAIN_ID.to_vec(),
            msg_type: MsgType::ArchivalRecordRenew,
            sender: stranger.clone(),
            nonce: 0,
            fee: 0,
            fee_tip: 0,
            gas_limit: 1_000_000,
            payload: encode_archival_record_renew_payload(0, &[0x00; 32]),
            sig_alg_id: AlgId::MlDsa65,
            sig_key_version: 1,
            signature: vec![0u8; 3_309],
        };
        let err = apply_archival_record_renew(&mut store, &renew_bad, 100).unwrap_err();
        assert!(matches!(err, ApplyError::ArchivalNotRenewer));

        // But once governance registers the address as an archival_renewer, it succeeds.
        store.add_archival_renewer(&stranger);
        apply_archival_record_renew(&mut store, &renew_bad, 101)
            .expect("renewer-registered address must succeed");
        assert_eq!(
            store
                .get_archival_record(0)
                .unwrap()
                .evidence_record_version,
            3
        );
    }

    /// Nonexistent epoch on AddAnchor → ArchivalRecordNotFound.
    #[test]
    fn archival_record_add_anchor_rejects_missing_record() {
        let mut store = StateStore::new();
        let sender = Address([0xA0u8; 32]);
        store.insert_account(Account {
            address: sender.clone(),
            balance: 1_000,
            nonce: 0,
            keys: KeySet(vec![]),
            policy_version: 0,
            policy_hash: None,
            verifier_template_id: pqc_types::account::VERIFIER_TEMPLATE_ID_EOA,
            auth_data: Vec::new(),
        });
        let tx = Transaction {
            tx_version: 1,
            chain_id: CHAIN_ID.to_vec(),
            msg_type: MsgType::ArchivalRecordAddAnchor,
            sender,
            nonce: 0,
            fee: 0,
            fee_tip: 0,
            gas_limit: 1_000_000,
            payload: encode_archival_record_add_anchor_payload(
                5,
                0x01,
                &[0x00; 64],
                &[0x11; 32],
                0,
            ),
            sig_alg_id: AlgId::MlDsa65,
            sig_key_version: 1,
            signature: vec![0u8; 3_309],
        };
        let err = apply_archival_record_add_anchor(&mut store, &tx, 10).unwrap_err();
        assert!(matches!(err, ApplyError::ArchivalRecordNotFound));
    }
}

fn transfer_payload(recipient: &Address, amount: u128) -> Vec<u8> {
    cbor_map(vec![
        (1, CborVal::Bytes(recipient.0.to_vec())),
        (2, CborVal::Int(amount as u64)), // u128 fits u64 for test values
    ])
}

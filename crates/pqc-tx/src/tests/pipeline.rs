// SPDX-License-Identifier: Apache-2.0
//! Validation pipeline rejection tests — SPEC-TX-001 §8.
//!
//! Table-driven: one valid base case + one mutation per rejection path.
//! Each test asserts on the exact TxError variant to pin the spec contract.

use crate::{
    codec::encode_tx,
    error::TxError,
    validate::{validate_tx, FeeParams, ValidationContext, MAX_TX_BYTES},
};
use pqc_crypto::sign::StubVerifier;
use pqc_crypto::{AlgId, Lifecycle};
use pqc_types::{
    account::{Account, Address},
    keyset::{allowed_tx, KeyEntry, KeySet, KeyStatus},
    transaction::{MsgType, Transaction},
    ForkDigest,
};

// ── Test fixtures ─────────────────────────────────────────────────────────────

const CHAIN_ID: &[u8] = &[0xDE, 0xAD, 0xBE, 0xEF];
const CURRENT_HEIGHT: u64 = 100;

static TEST_FORK_DIGEST: std::sync::LazyLock<ForkDigest> =
    std::sync::LazyLock::new(ForkDigest::viper_research_1);

fn base_tx() -> Transaction {
    Transaction {
        tx_version: 1,
        chain_id: CHAIN_ID.to_vec(),
        msg_type: MsgType::TokenTransfer,
        sender: Address([0x11u8; 32]),
        nonce: 5,
        fee: 0, // zero fee — FeeParams are all-zero, so this is always sufficient
        fee_tip: 0,
        gas_limit: 100_000,
        payload: vec![],
        sig_alg_id: AlgId::MlDsa65,
        sig_key_version: 1,
        signature: vec![0u8; 3_309],
    }
}

fn base_account(tx: &Transaction) -> Account {
    Account {
        address: tx.sender.clone(),
        balance: u128::MAX,
        nonce: tx.nonce,
        keys: KeySet(vec![KeyEntry {
            alg_id: tx.sig_alg_id,
            pk_bytes: vec![0u8; 32].into(), // placeholder — StubVerifier ignores content
            key_version: tx.sig_key_version,
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

fn active_lifecycle(alg_id: AlgId) -> Option<Lifecycle> {
    match alg_id {
        AlgId::MlDsa44
        | AlgId::MlDsa65
        | AlgId::MlDsa87
        | AlgId::FnDsaPadded512
        | AlgId::SlhDsaSha2128s => Some(Lifecycle::Active),
        _ => None,
    }
}

fn zero_min_fee(alg_id: AlgId) -> Option<u64> {
    active_lifecycle(alg_id).map(|_| 0)
}

fn run(
    tx: &Transaction,
    account: Option<&Account>,
    alg_lifecycle: &dyn Fn(AlgId) -> Option<Lifecycle>,
) -> Result<(), TxError> {
    let raw = encode_tx(tx).expect("encode must succeed in test setup");
    run_with_raw(tx, &raw, account, alg_lifecycle)
}

fn run_with_raw(
    tx: &Transaction,
    raw: &[u8],
    account: Option<&Account>,
    alg_lifecycle: &dyn Fn(AlgId) -> Option<Lifecycle>,
) -> Result<(), TxError> {
    let verifier = StubVerifier;
    let ctx = ValidationContext {
        chain_id: CHAIN_ID,
        fork_digest: &TEST_FORK_DIGEST,
        current_height: CURRENT_HEIGHT,
        sender_account: account,
        fee_params: FeeParams::default(),
        verifier: &verifier,
        alg_lifecycle,
        alg_min_fee: &|alg_id| {
            if alg_lifecycle(alg_id).is_some() {
                Some(0)
            } else {
                None
            }
        },
    };
    validate_tx(tx, raw, &ctx)
}

// ── Base case ─────────────────────────────────────────────────────────────────

#[test]
fn valid_tx_passes_all_steps() {
    let tx = base_tx();
    let account = base_account(&tx);
    assert!(run(&tx, Some(&account), &active_lifecycle).is_ok());
}

// ── Step 1: size cap — SPEC-TX-001 §5.9 ──────────────────────────────────────

/// A transaction whose encoded form exceeds MAX_TX_BYTES must be rejected before
/// any crypto work is done — prevents CPU-exhaustion via oversized payloads.
#[test]
fn reject_tx_exceeding_size_cap() {
    let tx = base_tx();
    let account = base_account(&tx);
    // Synthesize raw bytes just over the 1 MiB cap. The bytes do not need to be
    // valid CBOR for this check — size is tested before CBOR structure.
    let oversized_raw = vec![0u8; MAX_TX_BYTES + 1];
    let result = run_with_raw(&tx, &oversized_raw, Some(&account), &active_lifecycle);
    assert_eq!(result, Err(TxError::TxTooLarge(MAX_TX_BYTES + 1)));
}

/// Exactly MAX_TX_BYTES must not trigger the size cap.
/// (The tx itself won't pass all steps, but it won't fail with TxTooLarge.)
#[test]
fn size_cap_is_exclusive_boundary() {
    let tx = base_tx();
    let account = base_account(&tx);
    let at_limit_raw = vec![0u8; MAX_TX_BYTES];
    let result = run_with_raw(&tx, &at_limit_raw, Some(&account), &active_lifecycle);
    // Must fail at a later step — but NOT TxTooLarge.
    assert_ne!(result, Err(TxError::TxTooLarge(MAX_TX_BYTES)));
}

// ── Step 2: tx_version ────────────────────────────────────────────────────────

#[test]
fn reject_unsupported_version() {
    let mut tx = base_tx();
    tx.tx_version = 99;
    let account = base_account(&tx);

    let err = run(&tx, Some(&account), &active_lifecycle).unwrap_err();
    assert!(matches!(err, TxError::VersionUnsupported(99)), "got: {err}");
}

// ── Step 3: chain_id ─────────────────────────────────────────────────────────

#[test]
fn reject_wrong_chain_id() {
    let mut tx = base_tx();
    tx.chain_id = vec![0xFF, 0xFF, 0xFF, 0xFF];
    let account = base_account(&tx);

    let err = run(&tx, Some(&account), &active_lifecycle).unwrap_err();
    assert!(matches!(err, TxError::ChainIdMismatch), "got: {err}");
}

// ── Step 5: alg_id not in registry ───────────────────────────────────────────

#[test]
fn reject_unknown_alg_id() {
    let mut tx = base_tx();
    // Use ML-KEM (key agreement only — not a signing alg, not in signing registry)
    tx.sig_alg_id = AlgId::MlKem768;
    let account = base_account(&tx);

    // Registry returns None for ML-KEM as a signing algorithm
    let lifecycle = |alg: AlgId| -> Option<Lifecycle> {
        if matches!(alg, AlgId::MlKem768) {
            None
        } else {
            active_lifecycle(alg)
        }
    };

    let err = run(&tx, Some(&account), &lifecycle).unwrap_err();
    assert!(matches!(err, TxError::AlgorithmNotFound(_)), "got: {err}");
}

// ── Step 6: alg_id banned ────────────────────────────────────────────────────

#[test]
fn reject_banned_algorithm() {
    let tx = base_tx();
    let account = base_account(&tx);

    // Registry reports ML-DSA-65 as Banned
    let lifecycle = |alg: AlgId| -> Option<Lifecycle> {
        if alg == AlgId::MlDsa65 {
            Some(Lifecycle::Banned)
        } else {
            active_lifecycle(alg)
        }
    };

    let err = run(&tx, Some(&account), &lifecycle).unwrap_err();
    assert!(matches!(err, TxError::AlgorithmBanned(_)), "got: {err}");
}

// ── Discouraged algorithm: admitted, but min_fee would need to be higher ──────
// (fee sufficiency check happens at step 12; Discouraged itself does not block)

#[test]
fn discouraged_algorithm_is_admitted_at_zero_fee_params() {
    let tx = base_tx();
    let account = base_account(&tx);

    let lifecycle = |alg: AlgId| -> Option<Lifecycle> {
        if alg == AlgId::MlDsa65 {
            Some(Lifecycle::Discouraged)
        } else {
            active_lifecycle(alg)
        }
    };

    // With all-zero FeeParams, fee sufficiency passes even for Discouraged
    assert!(run(&tx, Some(&account), &lifecycle).is_ok());
}

#[test]
fn discouraged_algorithm_enforces_registry_min_fee_floor() {
    let mut tx = base_tx();
    tx.fee = 100;
    let account = base_account(&tx);
    let raw = encode_tx(&tx).expect("encode");
    let verifier = StubVerifier;
    let lifecycle = |alg: AlgId| -> Option<Lifecycle> {
        if alg == AlgId::MlDsa65 {
            Some(Lifecycle::Discouraged)
        } else {
            active_lifecycle(alg)
        }
    };
    let ctx = ValidationContext {
        chain_id: CHAIN_ID,
        fork_digest: &TEST_FORK_DIGEST,
        current_height: CURRENT_HEIGHT,
        sender_account: Some(&account),
        fee_params: FeeParams {
            sigverify_fee_v_b: 50,
            ..FeeParams::default()
        },
        verifier: &verifier,
        alg_lifecycle: &lifecycle,
        alg_min_fee: &|alg_id| {
            if alg_id == AlgId::MlDsa65 {
                Some(500)
            } else {
                zero_min_fee(alg_id)
            }
        },
    };

    let err = validate_tx(&tx, &raw, &ctx).unwrap_err();
    assert!(
        matches!(
            err,
            TxError::FeeInsufficient {
                paid: 100,
                required: 500,
                sigverify: 500,
                ..
            }
        ),
        "got: {err}"
    );
}

#[test]
fn deprecated_algorithm_is_rejected_before_signature_verify() {
    let tx = base_tx();
    let account = base_account(&tx);
    let lifecycle = |alg: AlgId| -> Option<Lifecycle> {
        if alg == AlgId::MlDsa65 {
            Some(Lifecycle::Deprecated)
        } else {
            active_lifecycle(alg)
        }
    };

    let err = run(&tx, Some(&account), &lifecycle).unwrap_err();
    assert!(matches!(err, TxError::AlgorithmBanned(_)), "got: {err}");
}

// ── Step 7: sender not found ──────────────────────────────────────────────────

#[test]
fn reject_sender_not_found() {
    let tx = base_tx();

    let err = run(&tx, None, &active_lifecycle).unwrap_err();
    assert!(matches!(err, TxError::SenderNotFound), "got: {err}");
}

// ── Step 8: key_version not found ────────────────────────────────────────────

#[test]
fn reject_key_version_not_found() {
    let tx = base_tx();
    let mut account = base_account(&tx);
    // Remove the matching key from the KeySet
    account.keys.0.clear();

    let err = run(&tx, Some(&account), &active_lifecycle).unwrap_err();
    assert!(matches!(err, TxError::KeyLookupFailed(_)), "got: {err}");
}

// ── Step 8: revoked key ───────────────────────────────────────────────────────

#[test]
fn reject_revoked_key() {
    let tx = base_tx();
    let mut account = base_account(&tx);
    account.keys.0[0].status = KeyStatus::Revoked;

    let err = run(&tx, Some(&account), &active_lifecycle).unwrap_err();
    assert!(matches!(err, TxError::KeyLookupFailed(_)), "got: {err}");
}

// ── Step 8: key not yet active (valid_from_height in future) ─────────────────

#[test]
fn reject_key_not_yet_active() {
    let tx = base_tx();
    let mut account = base_account(&tx);
    // Key requires block 999, but current height is 100
    account.keys.0[0].valid_from_height = 999;

    let err = run(&tx, Some(&account), &active_lifecycle).unwrap_err();
    assert!(matches!(err, TxError::KeyLookupFailed(_)), "got: {err}");
}

// ── Step 8: allowed_tx_types mismatch ────────────────────────────────────────

#[test]
fn reject_key_permission_denied() {
    let mut tx = base_tx();
    tx.msg_type = MsgType::GovernanceProposal; // requires GOVERNANCE bit
    let mut account = base_account(&tx);
    // Key only allows VAULT operations
    account.keys.0[0].allowed_tx_types = allowed_tx::VAULT;

    let err = run(&tx, Some(&account), &active_lifecycle).unwrap_err();
    assert!(matches!(err, TxError::KeyLookupFailed(_)), "got: {err}");
}

// ── Step 9: signature invalid (StubVerifier rejects alg_id mismatch) ─────────

#[test]
fn reject_alg_id_mismatch_between_key_and_signature() {
    let tx = base_tx();
    // Envelope says ML-DSA-65 for signing, but account key is ML-DSA-44
    let mut account = base_account(&tx);
    account.keys.0[0].alg_id = AlgId::MlDsa44;

    // tx.sig_alg_id is MlDsa65 — key lookup will fail on alg mismatch
    let err = run(&tx, Some(&account), &active_lifecycle).unwrap_err();
    assert!(matches!(err, TxError::KeyLookupFailed(_)), "got: {err}");
}

// ── Step 10: nonce mismatch ───────────────────────────────────────────────────

#[test]
fn reject_wrong_nonce() {
    let mut tx = base_tx();
    tx.nonce = 999; // account.nonce is 5
    let account = base_account(&base_tx()); // account has nonce=5

    let err = run(&tx, Some(&account), &active_lifecycle).unwrap_err();
    assert!(
        matches!(
            err,
            TxError::NonceInvalid {
                expected: 5,
                got: 999
            }
        ),
        "got: {err}"
    );
}

// ── Step 12: fee insufficient ─────────────────────────────────────────────────

#[test]
fn reject_fee_insufficient() {
    let mut tx = base_tx();
    tx.fee = 0;
    let mut account = base_account(&tx);
    account.balance = u128::MAX;

    // Set non-zero fee params so min_fee > 0
    let raw = encode_tx(&tx).expect("encode");
    let verifier = StubVerifier;
    let ctx = ValidationContext {
        chain_id: CHAIN_ID,
        fork_digest: &TEST_FORK_DIGEST,
        current_height: CURRENT_HEIGHT,
        sender_account: Some(&account),
        fee_params: FeeParams {
            base_fee: 500, // requires fee >= 500
            ..FeeParams::default()
        },
        verifier: &verifier,
        alg_lifecycle: &active_lifecycle,
        alg_min_fee: &zero_min_fee,
    };

    let err = validate_tx(&tx, &raw, &ctx).unwrap_err();
    assert!(
        matches!(err, TxError::FeeInsufficient { paid: 0, .. }),
        "got: {err}"
    );
}

// ── Step 14: balance insufficient ────────────────────────────────────────────

#[test]
fn reject_balance_insufficient() {
    let mut tx = base_tx();
    tx.fee = 1_000;
    let mut account = base_account(&tx);
    account.balance = 500; // less than fee

    let err = run(&tx, Some(&account), &active_lifecycle).unwrap_err();
    assert!(
        matches!(
            err,
            TxError::BalanceInsufficient {
                balance: 500,
                fee: 1_000
            }
        ),
        "got: {err}"
    );
}

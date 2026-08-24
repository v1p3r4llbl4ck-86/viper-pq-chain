// SPDX-License-Identifier: BUSL-1.1
//! Mempool boundary tests — SPEC-FEE-001 §9, §10, §11.
//!
//! Test double implements StateView directly; no real StateStore needed.
//! Each test verifies a distinct admission or replacement behavior.

use crate::{admission::try_admit, error::MempoolError, pool::Mempool};
use pqc_crypto::sign::StubVerifier;
use pqc_crypto::{AlgId, Lifecycle, SigClass};
use pqc_tx::{codec::encode_tx, state_view::StateView, validate::FeeParams};
use pqc_types::{
    account::{Account, Address},
    keyset::{allowed_tx, KeyEntry, KeySet, KeyStatus},
    transaction::{MsgType, Transaction},
};

// ── Test double ───────────────────────────────────────────────────────────────

const CHAIN_ID: &[u8] = &[0xDE, 0xAD, 0xBE, 0xEF];
const CURRENT_HEIGHT: u64 = 50;

struct TestState {
    account: Option<Account>,
    banned_algs: Vec<AlgId>,
    discouraged_min_fees: Vec<(AlgId, u64)>,
    chain_id: &'static [u8],
}

impl TestState {
    fn with_account(balance: u128, nonce: u64, alg: AlgId) -> Self {
        let addr = Address([0xAA; 32]);
        let account = Account {
            address: addr,
            balance,
            nonce,
            keys: KeySet(vec![KeyEntry {
                alg_id: alg,
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
        };
        Self {
            account: Some(account),
            banned_algs: vec![],
            discouraged_min_fees: vec![],
            chain_id: CHAIN_ID,
        }
    }

    fn with_banned_alg(mut self, alg: AlgId) -> Self {
        self.banned_algs.push(alg);
        self
    }

    fn with_discouraged_min_fee(mut self, alg: AlgId, min_fee: u64) -> Self {
        self.discouraged_min_fees.push((alg, min_fee));
        self
    }
}

impl StateView for TestState {
    fn get_account(&self, addr: &Address) -> Option<&Account> {
        self.account.as_ref().filter(|a| a.address == *addr)
    }

    fn alg_lifecycle(&self, alg_id: AlgId) -> Option<Lifecycle> {
        if self.banned_algs.contains(&alg_id) {
            return Some(Lifecycle::Banned);
        }
        if self
            .discouraged_min_fees
            .iter()
            .any(|(candidate, _)| *candidate == alg_id)
        {
            return Some(Lifecycle::Discouraged);
        }
        match alg_id {
            AlgId::MlDsa44
            | AlgId::MlDsa65
            | AlgId::MlDsa87
            | AlgId::FnDsaPadded512
            | AlgId::SlhDsaSha2128s => Some(Lifecycle::Active),
            _ => None,
        }
    }

    fn alg_sig_class(&self, alg_id: AlgId) -> Option<SigClass> {
        match alg_id {
            AlgId::FnDsaPadded512 => Some(SigClass::Reduced),
            AlgId::MlDsa44 | AlgId::MlDsa65 | AlgId::MlDsa87 => Some(SigClass::Standard),
            AlgId::SlhDsaSha2128s => Some(SigClass::Premium),
            _ => None,
        }
    }

    fn alg_min_fee(&self, alg_id: AlgId) -> Option<u64> {
        self.discouraged_min_fees
            .iter()
            .find(|(candidate, _)| *candidate == alg_id)
            .map(|(_, min_fee)| *min_fee)
            .or_else(|| self.alg_lifecycle(alg_id).map(|_| 0))
    }

    fn chain_id(&self) -> &[u8] {
        self.chain_id
    }
    fn current_height(&self) -> u64 {
        CURRENT_HEIGHT
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn base_tx() -> Transaction {
    Transaction {
        tx_version: 1,
        chain_id: CHAIN_ID.to_vec(),
        msg_type: MsgType::TokenTransfer,
        sender: Address([0xAA; 32]),
        nonce: 0,
        fee: 0,
        fee_tip: 0,
        gas_limit: 100_000,
        payload: vec![],
        sig_alg_id: AlgId::MlDsa65,
        sig_key_version: 1,
        signature: vec![0u8; 3_309],
    }
}

fn admit(
    pool: &mut Mempool,
    tx: Transaction,
    state: &dyn StateView,
) -> Result<crate::admission::AdmissionResult, MempoolError> {
    let raw = encode_tx(&tx).expect("encode must succeed in tests");
    let verifier = StubVerifier;
    try_admit(pool, raw, state, &verifier, &FeeParams::default())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[test]
fn valid_tx_is_admitted() {
    let mut pool = Mempool::new();
    let state = TestState::with_account(u128::MAX, 0, AlgId::MlDsa65);

    let result = admit(&mut pool, base_tx(), &state);
    assert!(result.is_ok(), "got: {result:?}");
    assert_eq!(pool.len(), 1);
}

#[test]
fn duplicate_raw_bytes_rejected() {
    let mut pool = Mempool::new();
    let state = TestState::with_account(u128::MAX, 0, AlgId::MlDsa65);
    let tx = base_tx();

    admit(&mut pool, tx.clone(), &state).expect("first admit must succeed");

    // Same account now has nonce=0 again in the state — but the raw bytes are identical
    let raw = encode_tx(&tx).expect("encode");
    let verifier = StubVerifier;
    let err = try_admit(&mut pool, raw, &state, &verifier, &FeeParams::default()).unwrap_err();

    assert!(matches!(err, MempoolError::Duplicate), "got: {err}");
}

#[test]
fn banned_algorithm_rejected_before_signature_verify() {
    let mut pool = Mempool::new();
    // State reports ML-DSA-65 as Banned
    let state =
        TestState::with_account(u128::MAX, 0, AlgId::MlDsa65).with_banned_alg(AlgId::MlDsa65);

    let err = admit(&mut pool, base_tx(), &state).unwrap_err();
    assert!(
        matches!(
            err,
            MempoolError::ValidationFailed(pqc_tx::TxError::AlgorithmBanned(_))
        ),
        "got: {err}"
    );
    assert_eq!(pool.len(), 0, "pool must remain empty after rejection");
}

#[test]
fn sender_not_found_rejected() {
    let mut pool = Mempool::new();
    // State has no account
    let state = TestState {
        account: None,
        banned_algs: vec![],
        discouraged_min_fees: vec![],
        chain_id: CHAIN_ID,
    };

    let err = admit(&mut pool, base_tx(), &state).unwrap_err();
    assert!(
        matches!(
            err,
            MempoolError::ValidationFailed(pqc_tx::TxError::SenderNotFound)
        ),
        "got: {err}"
    );
}

#[test]
fn wrong_nonce_rejected() {
    let mut pool = Mempool::new();
    // Account has nonce=5, tx has nonce=0
    let state = TestState::with_account(u128::MAX, 5, AlgId::MlDsa65);

    let err = admit(&mut pool, base_tx(), &state).unwrap_err();
    assert!(
        matches!(
            err,
            MempoolError::ValidationFailed(pqc_tx::TxError::NonceInvalid {
                expected: 5,
                got: 0
            })
        ),
        "got: {err}"
    );
}

#[test]
fn insufficient_balance_rejected() {
    let mut pool = Mempool::new();
    let mut tx = base_tx();
    tx.fee = 1_000;

    // Account balance less than fee
    let state = TestState::with_account(500, 0, AlgId::MlDsa65);

    let err = admit(&mut pool, tx, &state).unwrap_err();
    assert!(
        matches!(
            err,
            MempoolError::ValidationFailed(pqc_tx::TxError::BalanceInsufficient { .. })
        ),
        "got: {err}"
    );
}

#[test]
fn insufficient_fee_rejected() {
    let mut pool = Mempool::new();
    let mut tx = base_tx();
    tx.fee = 0;

    let state = TestState::with_account(u128::MAX, 0, AlgId::MlDsa65);
    let raw = encode_tx(&tx).expect("encode");
    let verifier = StubVerifier;
    let fee_params = FeeParams {
        base_fee: 500,
        ..FeeParams::default()
    };

    let err = try_admit(&mut pool, raw, &state, &verifier, &fee_params).unwrap_err();
    assert!(
        matches!(
            err,
            MempoolError::ValidationFailed(pqc_tx::TxError::FeeInsufficient { .. })
        ),
        "got: {err}"
    );
}

#[test]
fn revoked_key_rejected() {
    let mut pool = Mempool::new();
    let addr = Address([0xAA; 32]);
    let account = Account {
        address: addr,
        balance: u128::MAX,
        nonce: 0,
        keys: KeySet(vec![KeyEntry {
            alg_id: AlgId::MlDsa65,
            pk_bytes: vec![0u8; 32].into(),
            key_version: 1,
            valid_from_height: 0,
            status: KeyStatus::Revoked, // <-- revoked
            allowed_tx_types: allowed_tx::ALL,
        }]),
        policy_version: 0,
        policy_hash: None,
        verifier_template_id: pqc_types::account::VERIFIER_TEMPLATE_ID_EOA,
        auth_data: Vec::new(),
    };
    let state = TestState {
        account: Some(account),
        banned_algs: vec![],
        discouraged_min_fees: vec![],
        chain_id: CHAIN_ID,
    };

    let err = admit(&mut pool, base_tx(), &state).unwrap_err();
    assert!(
        matches!(
            err,
            MempoolError::ValidationFailed(pqc_tx::TxError::KeyLookupFailed(_))
        ),
        "got: {err}"
    );
}

#[test]
fn discouraged_algorithm_with_registry_min_fee_is_rejected_when_fee_is_too_low() {
    let mut pool = Mempool::new();
    let state = TestState::with_account(u128::MAX, 0, AlgId::MlDsa65)
        .with_discouraged_min_fee(AlgId::MlDsa65, 500);

    let err = admit(&mut pool, base_tx(), &state).unwrap_err();
    assert!(
        matches!(
            err,
            MempoolError::ValidationFailed(pqc_tx::TxError::FeeInsufficient {
                required: 500,
                sigverify: 500,
                ..
            })
        ),
        "got: {err}"
    );
    assert_eq!(pool.len(), 0);
}

#[test]
fn replacement_with_higher_fee_succeeds() {
    let mut pool = Mempool::new();
    let state = TestState::with_account(u128::MAX, 0, AlgId::MlDsa65);

    // Admit original tx with fee=100
    let mut tx1 = base_tx();
    tx1.fee = 100;
    let result1 = admit(&mut pool, tx1, &state).expect("first admit must succeed");
    let original_hash = result1.tx_hash;

    assert_eq!(pool.len(), 1);

    // Admit replacement with fee=200 (≥ 100 × 1.10 = 110) — same sender, same nonce
    let mut tx2 = base_tx();
    tx2.fee = 200;
    tx2.signature = vec![0xBBu8; 3_309]; // different raw bytes → different tx_hash

    let result2 = admit(&mut pool, tx2, &state).expect("replacement must succeed");
    assert_eq!(
        result2.replaced,
        Some(original_hash),
        "original tx must be reported as replaced"
    );
    assert_eq!(pool.len(), 1, "pool size must remain 1 after replacement");

    // Original must be gone
    assert!(
        pool.get(&original_hash).is_none(),
        "evicted tx must not be retrievable"
    );
}

#[test]
fn replacement_with_lower_fee_rejected() {
    let mut pool = Mempool::new();
    let state = TestState::with_account(u128::MAX, 0, AlgId::MlDsa65);

    let mut tx1 = base_tx();
    tx1.fee = 1_000;
    admit(&mut pool, tx1, &state).expect("first admit must succeed");

    // Replacement with fee=500 — does not meet 10% bump rule (needs ≥ 1,100)
    let mut tx2 = base_tx();
    tx2.fee = 500;
    tx2.signature = vec![0xCCu8; 3_309];

    let err = admit(&mut pool, tx2, &state).unwrap_err();
    assert!(
        matches!(
            err,
            MempoolError::ReplacementUnderpriced {
                existing_fee: 1_000,
                min_required_fee: 1_100,
                ..
            }
        ),
        "got: {err}"
    );
    assert_eq!(
        pool.len(),
        1,
        "original tx must remain after failed replacement"
    );
}

#[test]
fn replacement_tip_downgrade_rejected() {
    let mut pool = Mempool::new();
    let state = TestState::with_account(u128::MAX, 0, AlgId::MlDsa65);

    let mut tx1 = base_tx();
    tx1.fee = 1_000;
    tx1.fee_tip = 200;
    admit(&mut pool, tx1, &state).expect("first admit must succeed");

    // Fee bump is sufficient (1,500 ≥ 1,100) but tip decreases (100 < 200)
    let mut tx2 = base_tx();
    tx2.fee = 1_500;
    tx2.fee_tip = 100; // lower than original tip
    tx2.signature = vec![0xDDu8; 3_309];

    let err = admit(&mut pool, tx2, &state).unwrap_err();
    assert!(
        matches!(
            err,
            MempoolError::ReplacementUnderpriced {
                existing_tip: 200,
                ..
            }
        ),
        "got: {err}"
    );
}

#[test]
fn vc_cap_rejects_excess_shlhdsa_transactions() {
    let mut pool = Mempool::new();
    pool.vc_per_block_cap = 2; // low cap for the test

    let _state = TestState::with_account(u128::MAX, 0, AlgId::SlhDsaSha2128s);

    // Admit two V-C transactions (using different nonces to avoid replacement path)
    for nonce in 0..2u64 {
        let state_n = TestState::with_account(u128::MAX, nonce, AlgId::SlhDsaSha2128s);
        let tx = Transaction {
            tx_version: 1,
            chain_id: CHAIN_ID.to_vec(),
            msg_type: MsgType::TokenTransfer,
            sender: Address([0xAA; 32]),
            nonce,
            fee: 0,
            fee_tip: 0,
            gas_limit: 100_000,
            payload: vec![],
            sig_alg_id: AlgId::SlhDsaSha2128s,
            sig_key_version: 1,
            signature: vec![nonce as u8; 7_856],
        };
        admit(&mut pool, tx, &state_n).expect("V-C tx under cap must be admitted");
    }

    assert_eq!(pool.vc_admitted_count(), 2);

    // Third V-C tx should be rejected by the cap
    let tx3 = Transaction {
        tx_version: 1,
        chain_id: CHAIN_ID.to_vec(),
        msg_type: MsgType::TokenTransfer,
        sender: Address([0xAA; 32]),
        nonce: 2,
        fee: 0,
        fee_tip: 0,
        gas_limit: 100_000,
        payload: vec![],
        sig_alg_id: AlgId::SlhDsaSha2128s,
        sig_key_version: 1,
        signature: vec![0xFFu8; 7_856],
    };
    let state3 = TestState::with_account(u128::MAX, 2, AlgId::SlhDsaSha2128s);
    let err = admit(&mut pool, tx3, &state3).unwrap_err();
    assert!(matches!(err, MempoolError::VcCapReached), "got: {err}");
}

#[test]
fn mempool_does_not_mutate_state() {
    // After admission, the original account balance and nonce must be unchanged.
    // apply_tx (in pqc-state) is the only thing that mutates state.
    let state = TestState::with_account(5_000, 0, AlgId::MlDsa65);
    let initial_balance = state.account.as_ref().unwrap().balance;
    let initial_nonce = state.account.as_ref().unwrap().nonce;

    let mut pool = Mempool::new();
    admit(&mut pool, base_tx(), &state).expect("admit must succeed");

    // State must be unchanged
    let account = state.account.as_ref().unwrap();
    assert_eq!(
        account.balance, initial_balance,
        "admission must not change balance"
    );
    assert_eq!(
        account.nonce, initial_nonce,
        "admission must not increment nonce"
    );
}

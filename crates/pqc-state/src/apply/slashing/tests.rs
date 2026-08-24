// SPDX-License-Identifier: BUSL-1.1
//! Tests for `slashing`.
//!
//! Extracted from `slashing.rs` 2026-05-10. `use super::*;`
//! brings every private item from the parent module into scope.

use crate::{error::ApplyError, store::StateStore};
use pqc_crypto::{sign::StubVerifier, AlgId};
use pqc_types::{
    account::{Account, Address},
    keyset::{allowed_tx, KeyEntry, KeySet, KeyStatus},
    slashing::{encode_equivocation_evidence, EquivocationEvidence, EquivocationVote},
    validator::{ValidatorRecord, ValidatorStatus},
};

use super::{
    apply_submit_equivocation_evidence, EVIDENCE_VALIDITY_WINDOW_BLOCKS, TREASURY_ADDRESS,
};

// ── Test helpers ──────────────────────────────────────────────────────────

fn make_address(byte: u8) -> Address {
    Address([byte; 32])
}

/// Insert a validator with the given self_bond and status into the store.
fn insert_validator(
    store: &mut StateStore,
    operator: Address,
    self_bond: u128,
    status: ValidatorStatus,
) -> Address {
    store.insert_validator(ValidatorRecord {
        operator: operator.clone(),
        node_id: "test-node".into(),
        consensus_alg_id: AlgId::MlDsa65,
        // Stub verifier accepts any pk with matching alg_id — no real key material needed.
        consensus_pk: vec![0x42u8; 32],
        self_bond,
        status,
        registered_height: 0,
        tombstoned: false,
    });
    operator
}

/// Make an operator account with enough balance to hold the bond.
fn insert_operator_account(store: &mut StateStore, addr: &Address, balance: u128) {
    store.insert_account(Account {
        address: addr.clone(),
        balance,
        nonce: 0,
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
    });
}

fn make_vote(height: u64, round: u32, step: u8, block_hash: [u8; 32]) -> EquivocationVote {
    EquivocationVote {
        height,
        round,
        step,
        block_hash,
        // Stub verifier does not inspect signature bytes; any non-empty vec works.
        signature: vec![0xAA; 16],
    }
}

fn make_evidence(
    validator_address: [u8; 32],
    height: u64,
    hash_a: [u8; 32],
    hash_b: [u8; 32],
) -> Vec<u8> {
    let ev = EquivocationEvidence {
        validator_address,
        height,
        vote_a: make_vote(height, 0, 0x01, hash_a),
        vote_b: make_vote(height, 0, 0x01, hash_b),
    };
    encode_equivocation_evidence(&ev)
}

fn fresh_store() -> StateStore {
    // Advance block height to a comfortable test value.
    // StateStore::new() sets block_height = 0; we set it via a test helper.
    // (StateStore does not expose set_block_height, so we use insert_validator
    // to avoid needing it; the height is set elsewhere in the real pipeline.)
    StateStore::new()
}

// ── Tests ─────────────────────────────────────────────────────────────────

/// A valid equivocation evidence record for an Active validator should slash
/// 5% of self_bond, jail, and tombstone the validator.
///
/// Test case from SPEC-SLASH-001 §10:
///   self_bond = 1_000_000 VPR (in venom units) → slash = 50_000 VPR
///
/// The test uses 1_000_000 venom (not full VPR denomination) for simplicity.
#[test]
fn slash_reduces_self_bond() {
    let mut store = fresh_store();

    let val_addr = make_address(0x10);
    let sender = make_address(0x20);
    insert_operator_account(&mut store, &val_addr, 1_000_000);
    insert_operator_account(&mut store, &sender, 500_000);
    insert_validator(
        &mut store,
        val_addr.clone(),
        1_000_000,
        ValidatorStatus::Active,
    );

    let payload = make_evidence(val_addr.0, 0, [0xAA; 32], [0xBB; 32]);

    apply_submit_equivocation_evidence(
        &mut store,
        &sender,
        &payload,
        0, // current_block_height = evidence_height (same-block is valid per §12)
        &StubVerifier,
    )
    .expect("valid evidence must succeed");

    let record = store
        .get_validator(&val_addr)
        .expect("validator must still be in store");
    // 5% of 1_000_000 = 50_000
    assert_eq!(record.self_bond, 950_000, "self_bond must be reduced by 5%");
    assert_eq!(
        record.status,
        ValidatorStatus::Jailed,
        "validator must be Jailed"
    );
    assert!(record.tombstoned, "validator must be tombstoned");

    // Treasury must receive the slashed amount.
    let treasury = Address(TREASURY_ADDRESS);
    let treasury_acc = store
        .get_account(&treasury)
        .expect("treasury account must exist");
    assert_eq!(
        treasury_acc.balance, 50_000,
        "treasury must receive slash_amount"
    );
}

/// Submitting evidence a second time for an already-tombstoned validator must
/// fail with `AlreadyTombstoned` without changing state.
#[test]
fn already_tombstoned_rejected() {
    let mut store = fresh_store();

    let val_addr = make_address(0x11);
    let sender = make_address(0x21);
    insert_operator_account(&mut store, &val_addr, 1_000_000);
    insert_operator_account(&mut store, &sender, 500_000);
    insert_validator(
        &mut store,
        val_addr.clone(),
        1_000_000,
        ValidatorStatus::Active,
    );

    let payload = make_evidence(val_addr.0, 0, [0xAA; 32], [0xBB; 32]);

    // First submission succeeds.
    apply_submit_equivocation_evidence(&mut store, &sender, &payload, 0, &StubVerifier)
        .expect("first submission must succeed");

    // Second submission with different hashes must still fail.
    let payload2 = make_evidence(val_addr.0, 0, [0xCC; 32], [0xDD; 32]);
    let err = apply_submit_equivocation_evidence(&mut store, &sender, &payload2, 0, &StubVerifier)
        .expect_err("second submission must fail");

    assert_eq!(
        err,
        ApplyError::AlreadyTombstoned,
        "must fail with AlreadyTombstoned"
    );
}

/// Evidence height older than `EVIDENCE_VALIDITY_WINDOW_BLOCKS` must be rejected.
#[test]
fn expired_evidence_rejected() {
    let mut store = fresh_store();

    let val_addr = make_address(0x12);
    let sender = make_address(0x22);
    insert_operator_account(&mut store, &val_addr, 1_000_000);
    insert_operator_account(&mut store, &sender, 500_000);
    insert_validator(
        &mut store,
        val_addr.clone(),
        1_000_000,
        ValidatorStatus::Active,
    );

    // evidence at height 0; current block height = window + 1 → expired
    let evidence_height: u64 = 0;
    let current_height = EVIDENCE_VALIDITY_WINDOW_BLOCKS + 1;
    let payload = make_evidence(val_addr.0, evidence_height, [0xAA; 32], [0xBB; 32]);

    let err = apply_submit_equivocation_evidence(
        &mut store,
        &sender,
        &payload,
        current_height,
        &StubVerifier,
    )
    .expect_err("expired evidence must fail");

    assert_eq!(
        err,
        ApplyError::EvidenceExpired,
        "must fail with EvidenceExpired"
    );
}

/// Evidence at exactly the boundary (age == EVIDENCE_VALIDITY_WINDOW_BLOCKS) is valid.
#[test]
fn evidence_at_exact_window_boundary_is_valid() {
    let mut store = fresh_store();

    let val_addr = make_address(0x13);
    let sender = make_address(0x23);
    insert_operator_account(&mut store, &val_addr, 1_000_000);
    insert_operator_account(&mut store, &sender, 500_000);
    insert_validator(
        &mut store,
        val_addr.clone(),
        1_000_000,
        ValidatorStatus::Active,
    );

    let evidence_height: u64 = 0;
    let current_height = EVIDENCE_VALIDITY_WINDOW_BLOCKS; // age == window → valid
    let payload = make_evidence(val_addr.0, evidence_height, [0xAA; 32], [0xBB; 32]);

    apply_submit_equivocation_evidence(
        &mut store,
        &sender,
        &payload,
        current_height,
        &StubVerifier,
    )
    .expect("evidence at exact boundary must succeed");
}

/// A future evidence height (evidence.height > current_block_height) must be rejected.
#[test]
fn future_evidence_rejected() {
    let mut store = fresh_store();

    let val_addr = make_address(0x14);
    let sender = make_address(0x24);
    insert_operator_account(&mut store, &val_addr, 1_000_000);
    insert_operator_account(&mut store, &sender, 500_000);
    insert_validator(
        &mut store,
        val_addr.clone(),
        1_000_000,
        ValidatorStatus::Active,
    );

    let evidence_height: u64 = 999;
    let current_height: u64 = 1; // evidence_height > current_height
    let payload = make_evidence(val_addr.0, evidence_height, [0xAA; 32], [0xBB; 32]);

    let err = apply_submit_equivocation_evidence(
        &mut store,
        &sender,
        &payload,
        current_height,
        &StubVerifier,
    )
    .expect_err("future evidence must fail");

    assert_eq!(err, ApplyError::EvidenceExpired);
}

/// Evidence for an unknown validator address must fail with `NotAValidator`.
#[test]
fn not_a_validator_rejected() {
    let mut store = fresh_store();

    let unknown_addr = make_address(0xDE);
    let sender = make_address(0xAA);
    insert_operator_account(&mut store, &sender, 500_000);

    let payload = make_evidence(unknown_addr.0, 0, [0xAA; 32], [0xBB; 32]);

    let err = apply_submit_equivocation_evidence(&mut store, &sender, &payload, 0, &StubVerifier)
        .expect_err("unknown validator must fail");

    assert_eq!(err, ApplyError::NotAValidator);
}

/// Votes with the same block_hash must fail with `EquivocationNotProven`.
#[test]
fn same_block_hash_not_equivocation() {
    let mut store = fresh_store();

    let val_addr = make_address(0x15);
    let sender = make_address(0x25);
    insert_operator_account(&mut store, &val_addr, 1_000_000);
    insert_operator_account(&mut store, &sender, 500_000);
    insert_validator(
        &mut store,
        val_addr.clone(),
        1_000_000,
        ValidatorStatus::Active,
    );

    // Same hash for both votes — not equivocation.
    let payload = make_evidence(val_addr.0, 0, [0xAA; 32], [0xAA; 32]);

    let err = apply_submit_equivocation_evidence(&mut store, &sender, &payload, 0, &StubVerifier)
        .expect_err("identical hashes must fail");

    assert_eq!(err, ApplyError::EquivocationNotProven);
}

/// Validator in `Unbonding` status can still be slashed and tombstoned.
#[test]
fn slash_applies_to_unbonding_validator() {
    let mut store = fresh_store();

    let val_addr = make_address(0x16);
    let sender = make_address(0x26);
    insert_operator_account(&mut store, &val_addr, 1_000_000);
    insert_operator_account(&mut store, &sender, 500_000);
    insert_validator(
        &mut store,
        val_addr.clone(),
        800_000,
        ValidatorStatus::Unbonding { start_height: 0 },
    );

    let payload = make_evidence(val_addr.0, 0, [0xAA; 32], [0xBB; 32]);

    apply_submit_equivocation_evidence(&mut store, &sender, &payload, 0, &StubVerifier)
        .expect("unbonding validator can be slashed");

    let record = store.get_validator(&val_addr).unwrap();
    // 5% of 800_000 = 40_000; remaining = 760_000
    assert_eq!(record.self_bond, 760_000);
    assert!(record.tombstoned);
    assert_eq!(record.status, ValidatorStatus::Jailed);
}

// ── Correlation penalty tests — ADR-048, SPEC-SLASH-001 §17, D-02 ─────────

use super::{
    compute_slash_amount, correlation_adjusted_slash_fraction_bps, CORRELATION_WINDOW_BLOCKS,
    SLASH_FRACTION_BPS,
};
use pqc_types::slashing::RecentSlashEntry;

/// Pure math — no correlation => base fraction unchanged.
#[test]
fn correlation_fraction_returns_base_when_window_is_empty() {
    let bps = correlation_adjusted_slash_fraction_bps(SLASH_FRACTION_BPS, 0, 10_000_000);
    assert_eq!(bps, SLASH_FRACTION_BPS, "empty window must not boost base");
}

/// Pure math — well above threshold caps at full 10_000 bps (100% slash).
#[test]
fn correlation_fraction_caps_above_threshold() {
    let bps = correlation_adjusted_slash_fraction_bps(SLASH_FRACTION_BPS, 50_000, 100_000);
    // ratio_bps = 5_000, multiplier = min(10_000, 15_000) = 10_000
    // boost = 10_000 + 10_000 × 19 = 200_000
    // effective = 500 × 200_000 / 10_000 = 10_000 bps
    assert_eq!(bps, 10_000, "beyond threshold must saturate at 100%");
}

/// Pure math — division-by-zero guarded.
#[test]
fn correlation_fraction_handles_zero_active_stake() {
    let bps = correlation_adjusted_slash_fraction_bps(SLASH_FRACTION_BPS, 1_000, 0);
    assert_eq!(bps, SLASH_FRACTION_BPS, "zero active stake returns base");
}

/// Single equivocation with no prior slashes: base 5% applies verbatim.
#[test]
fn single_equivocation_applies_base_5pct_no_correlation() {
    let mut store = fresh_store();

    let val_addr = make_address(0x40);
    let sender = make_address(0x50);
    insert_operator_account(&mut store, &val_addr, 1_000_000);
    insert_operator_account(&mut store, &sender, 500_000);
    insert_validator(
        &mut store,
        val_addr.clone(),
        1_000_000,
        ValidatorStatus::Active,
    );

    let payload = make_evidence(val_addr.0, 0, [0xAA; 32], [0xBB; 32]);
    apply_submit_equivocation_evidence(&mut store, &sender, &payload, 0, &StubVerifier)
        .expect("valid evidence must succeed");

    let record = store.get_validator(&val_addr).unwrap();
    assert_eq!(record.self_bond, 950_000, "single slash = base 5%");

    let ledger = store.recent_slashes_snapshot();
    assert_eq!(ledger.len(), 1, "ledger records the applied slash");
    assert_eq!(ledger[0].height, 0);
    assert_eq!(ledger[0].slashed_stake, 50_000);
}

/// Two equivocations at the same height — the first applies base 5%, the
/// second observes the first in the window and is boosted by correlation.
#[test]
fn two_simultaneous_equivocations_correlation_boosts_both() {
    let mut store = fresh_store();

    let a = make_address(0x60);
    let b = make_address(0x61);
    let c = make_address(0x62);
    let sender = make_address(0x70);
    insert_operator_account(&mut store, &a, 1_000_000);
    insert_operator_account(&mut store, &b, 1_000_000);
    insert_operator_account(&mut store, &c, 1_000_000);
    insert_operator_account(&mut store, &sender, 500_000);
    insert_validator(&mut store, a.clone(), 1_000_000, ValidatorStatus::Active);
    insert_validator(&mut store, b.clone(), 1_000_000, ValidatorStatus::Active);
    insert_validator(&mut store, c.clone(), 1_000_000, ValidatorStatus::Active);

    // Slash A: base 5% (window empty at compute-time).
    let payload_a = make_evidence(a.0, 0, [0xAA; 32], [0xBB; 32]);
    apply_submit_equivocation_evidence(&mut store, &sender, &payload_a, 0, &StubVerifier)
        .expect("first slash must succeed");
    assert_eq!(
        store.get_validator(&a).unwrap().self_bond,
        950_000,
        "first slash is unboosted"
    );

    // Slash B: window now contains A's 50_000. A has been jailed so
    // active_stake = 2_000_000. ratio = 50_000 × 10_000 / 2_000_000 = 250 bps.
    // multiplier_bps = 250 × 3 = 750; boost_bps = 10_000 + 750 × 19 = 24_250
    // effective = 500 × 24_250 / 10_000 = 1_212 bps → slash = 121_200.
    let payload_b = make_evidence(b.0, 0, [0xCC; 32], [0xDD; 32]);
    apply_submit_equivocation_evidence(&mut store, &sender, &payload_b, 0, &StubVerifier)
        .expect("second slash must succeed");

    let b_slash = 1_000_000 - store.get_validator(&b).unwrap().self_bond;
    assert!(b_slash > 50_000, "second slash exceeds base; got {b_slash}");
    assert_eq!(
        b_slash, 121_200,
        "exact correlation-boosted slash = 12.12% of bond"
    );
}

/// ≥1/3 stake slashed in window → multiplier saturates → 100% slash.
#[test]
fn third_of_stake_slashed_in_window_triggers_cap() {
    let mut store = fresh_store();

    let sender = make_address(0x80);
    let target = make_address(0x81);
    insert_operator_account(&mut store, &sender, 500_000);
    insert_operator_account(&mut store, &target, 1_000_000);
    insert_validator(
        &mut store,
        target.clone(),
        1_000_000,
        ValidatorStatus::Active,
    );
    // Seed window with a 50% slash (way above 1/3 threshold).
    store.record_recent_slash(RecentSlashEntry {
        height: 0,
        slashed_stake: 500_000,
    });

    let payload = make_evidence(target.0, 0, [0xAA; 32], [0xBB; 32]);
    apply_submit_equivocation_evidence(&mut store, &sender, &payload, 0, &StubVerifier)
        .expect("slash must succeed");

    // Effective fraction saturates at 10_000 bps → full bond slashed.
    assert_eq!(
        store.get_validator(&target).unwrap().self_bond,
        0,
        "saturated multiplier zeroes self_bond"
    );
}

/// Ledger entries outside the window are pruned and do not correlate.
#[test]
fn old_slashes_outside_window_do_not_correlate() {
    let mut store = fresh_store();

    let target = make_address(0x90);
    let sender = make_address(0x91);
    insert_operator_account(&mut store, &sender, 500_000);
    insert_operator_account(&mut store, &target, 1_000_000);
    insert_validator(
        &mut store,
        target.clone(),
        1_000_000,
        ValidatorStatus::Active,
    );
    store.record_recent_slash(RecentSlashEntry {
        height: 0,
        slashed_stake: 500_000,
    });

    // Fast-forward past the window.
    let current_height = CORRELATION_WINDOW_BLOCKS + 1;
    let payload = make_evidence(target.0, current_height, [0xAA; 32], [0xBB; 32]);
    apply_submit_equivocation_evidence(
        &mut store,
        &sender,
        &payload,
        current_height,
        &StubVerifier,
    )
    .expect("slash must succeed");

    assert_eq!(
        store.get_validator(&target).unwrap().self_bond,
        950_000,
        "out-of-window slashes must not boost"
    );
    let ledger = store.recent_slashes_snapshot();
    assert_eq!(ledger.len(), 1, "stale entry pruned");
    assert_eq!(ledger[0].height, current_height);
}

/// After window fully expires, multiplier resets to 1.0.
#[test]
fn correlation_resets_after_window_expires() {
    let mut store = fresh_store();

    let a = make_address(0xA0);
    let b = make_address(0xA1);
    let sender = make_address(0xA2);
    insert_operator_account(&mut store, &sender, 500_000);
    insert_operator_account(&mut store, &a, 1_000_000);
    insert_operator_account(&mut store, &b, 1_000_000);
    insert_validator(&mut store, a.clone(), 1_000_000, ValidatorStatus::Active);
    insert_validator(&mut store, b.clone(), 1_000_000, ValidatorStatus::Active);

    let payload_a = make_evidence(a.0, 0, [0xAA; 32], [0xBB; 32]);
    apply_submit_equivocation_evidence(&mut store, &sender, &payload_a, 0, &StubVerifier)
        .expect("first slash must succeed");
    assert_eq!(store.recent_slashes_snapshot().len(), 1);

    let later_height = CORRELATION_WINDOW_BLOCKS + 100;
    let payload_b = make_evidence(b.0, later_height, [0xCC; 32], [0xDD; 32]);
    apply_submit_equivocation_evidence(
        &mut store,
        &sender,
        &payload_b,
        later_height,
        &StubVerifier,
    )
    .expect("second slash must succeed");

    assert_eq!(
        store.get_validator(&b).unwrap().self_bond,
        950_000,
        "after window expiry, correlation resets to base 5%"
    );
    let ledger = store.recent_slashes_snapshot();
    assert_eq!(ledger.len(), 1, "only the fresh entry remains");
    assert_eq!(ledger[0].height, later_height);
}

/// Correlation ledger is consensus-critical state (folded into state_root).
#[test]
fn recent_slashes_ledger_is_consensus_critical_state() {
    let baseline = fresh_store();
    let baseline_root = baseline.state_root();

    let mut with_slash = fresh_store();
    with_slash.record_recent_slash(RecentSlashEntry {
        height: 0,
        slashed_stake: 42,
    });
    let with_slash_root = with_slash.state_root();
    assert_ne!(baseline_root, with_slash_root);

    let mut twin = fresh_store();
    twin.record_recent_slash(RecentSlashEntry {
        height: 0,
        slashed_stake: 42,
    });
    assert_eq!(twin.state_root(), with_slash_root);
}

/// `compute_slash_amount` floor-divides cleanly.
#[test]
fn compute_slash_amount_floor_divides() {
    assert_eq!(compute_slash_amount(1_000_000, 500), 50_000);
    assert_eq!(compute_slash_amount(1_000_000, 10_000), 1_000_000);
    assert_eq!(compute_slash_amount(1_000_000, 0), 0);
}

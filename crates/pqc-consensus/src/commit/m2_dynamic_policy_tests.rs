// SPDX-License-Identifier: BUSL-1.1
//! Tests for `commit`.
//!
//! Extracted from `commit.rs` 2026-05-10. `use super::*;`
//! brings every private item from the parent module into scope.

//! Phase 8 M2 (TASK-113) — pin the contract that
//! `CommitQuorumPolicy::from_state_store` is a pure function of
//! the current Active validator set. Every architectural change
//! in M2 Steps 1–3 rides on this contract:
//!   * Step 1 derives fee recipients from `active_validators()`
//!   * Step 2 rebuilds the quorum policy from state at each append
//!   * Step 3 refreshes the proposer-rotation source per block
//!
//! If any one of those paths ever re-introduces a frozen-config
//! shortcut, these tests catch it.
use super::*;
use pqc_crypto::AlgId;
use pqc_state::StateStore;
use pqc_types::account::Address;
use pqc_types::validator::{ValidatorRecord, ValidatorStatus};

fn mk_validator(op_byte: u8, status: ValidatorStatus) -> ValidatorRecord {
    ValidatorRecord {
        operator: Address([op_byte; 32]),
        node_id: format!("node-{op_byte:02x}"),
        consensus_alg_id: AlgId::MlDsa65,
        // Public key length is not inspected by `from_state_store`
        // — it just copies the Vec<u8> into the policy. A fixed
        // synthetic length keeps the test focused on the dynamic
        // derivation contract, not on key-format validation.
        consensus_pk: vec![op_byte; 1952],
        self_bond: 1_000,
        status,
        registered_height: 0,
        tombstoned: false,
    }
}

#[test]
fn from_state_store_returns_none_on_empty_active_set() {
    let store = StateStore::new();
    let policy =
        CommitQuorumPolicy::from_state_store(&store, None).expect("empty state is not an error");
    assert!(
        policy.is_none(),
        "empty Active set must return None so the caller can \
         fall through to the pre-genesis-seed bootstrap branch"
    );
}

#[test]
fn from_state_store_filters_non_active_validators() {
    let mut store = StateStore::new();
    store.insert_validator(mk_validator(0x01, ValidatorStatus::Active));
    store.insert_validator(mk_validator(0x02, ValidatorStatus::Candidate));
    store.insert_validator(mk_validator(0x03, ValidatorStatus::Active));
    store.insert_validator(mk_validator(
        0x04,
        ValidatorStatus::Unbonding { start_height: 100 },
    ));
    store.insert_validator(mk_validator(0x05, ValidatorStatus::Exited));
    let policy = CommitQuorumPolicy::from_state_store(&store, None)
        .expect("state yields a policy")
        .expect("two Active validators form a non-empty set");
    assert_eq!(
        policy.validators().len(),
        2,
        "only status=Active counts toward commit quorum — \
         Candidate / Unbonding / Exited must be filtered out"
    );
}

#[test]
fn from_state_store_grows_when_validator_registers() {
    //! Step-4-lite contract: a `ValidatorRegister`-equivalent state
    //! mutation (adding a new Active validator) must be visible in
    //! the *next* `from_state_store` call with zero cache
    //! invalidation. This is what M2 Step 2 (unfrozen policy) +
    //! Step 3 (per-iteration loop query) establish together.
    let mut store = StateStore::new();
    store.insert_validator(mk_validator(0x01, ValidatorStatus::Active));
    store.insert_validator(mk_validator(0x02, ValidatorStatus::Active));
    store.insert_validator(mk_validator(0x03, ValidatorStatus::Active));

    let before = CommitQuorumPolicy::from_state_store(&store, None)
        .expect("valid")
        .expect("non-empty");
    assert_eq!(before.validators().len(), 3);
    let quorum_before = before.quorum_threshold();

    // Simulate `apply_validator_register` inserting a new Active
    // record directly. (The full apply path also debits balance /
    // checks uniqueness — those gates are covered by the existing
    // `pqc-state::tests::validator_register_*` suite. This test
    // isolates the policy-derivation contract.)
    store.insert_validator(mk_validator(0x04, ValidatorStatus::Active));

    let after = CommitQuorumPolicy::from_state_store(&store, None)
        .expect("valid")
        .expect("non-empty");
    assert_eq!(
        after.validators().len(),
        4,
        "the newly-Active validator MUST appear in the policy the \
         very next time it is derived — proves M2 Step 2 (no \
         frozen-field cache) + Step 3 (caller queries per block)"
    );
    assert!(
        after.quorum_threshold() >= quorum_before,
        "quorum_threshold grows with the Active set under the \
         default 2f+1 rule — guard against a regression that \
         silently kept the old threshold"
    );
}

#[test]
fn from_state_store_shrinks_when_validator_exits() {
    //! Step-5-lite contract: when a validator transitions away from
    //! Active (via `ValidatorExit` → Unbonding), the policy
    //! rebuilds without them on the next derivation. Defends the
    //! opposite direction of the join test above.
    let mut store = StateStore::new();
    for i in 1u8..=4 {
        store.insert_validator(mk_validator(i, ValidatorStatus::Active));
    }
    let before = CommitQuorumPolicy::from_state_store(&store, None)
        .expect("valid")
        .expect("non-empty");
    assert_eq!(before.validators().len(), 4);

    // Move one validator to Unbonding.
    store.insert_validator(mk_validator(
        0x03,
        ValidatorStatus::Unbonding { start_height: 100 },
    ));

    let after = CommitQuorumPolicy::from_state_store(&store, None)
        .expect("valid")
        .expect("non-empty");
    assert_eq!(
        after.validators().len(),
        3,
        "Unbonding MUST drop out of the commit quorum policy \
         immediately — otherwise an exiting validator's signature \
         would still count toward quorum until their unbonding \
         period elapsed"
    );
}

#[test]
fn from_state_store_sort_order_is_stable_across_insert_order() {
    //! M2 plan §5.1: fee-distribution ordering MUST be
    //! byte-stable so every node arrives at the same state root.
    //! `StateStore::active_validators()` sorts by operator
    //! address; this test pins that invariant at the policy
    //! layer as well — the `CommitValidator` vector inside the
    //! policy is the same vector post-sort. A reorder would
    //! change the validator-index mapping the commit-verify
    //! loop relies on, so this is load-bearing.
    let mut store_forward = StateStore::new();
    for i in [1u8, 2, 3, 4, 5] {
        store_forward.insert_validator(mk_validator(i, ValidatorStatus::Active));
    }
    let mut store_reverse = StateStore::new();
    for i in [5u8, 4, 3, 2, 1] {
        store_reverse.insert_validator(mk_validator(i, ValidatorStatus::Active));
    }

    let policy_a = CommitQuorumPolicy::from_state_store(&store_forward, None)
        .expect("valid")
        .expect("non-empty");
    let policy_b = CommitQuorumPolicy::from_state_store(&store_reverse, None)
        .expect("valid")
        .expect("non-empty");

    let addrs_a: Vec<&[u8]> = policy_a
        .validators()
        .iter()
        .map(|v| v.address.as_slice())
        .collect();
    let addrs_b: Vec<&[u8]> = policy_b
        .validators()
        .iter()
        .map(|v| v.address.as_slice())
        .collect();
    assert_eq!(
        addrs_a, addrs_b,
        "insertion order MUST NOT change the policy's validator \
         vector — two nodes that insert the same set in different \
         orders must agree on commit-quorum membership and on \
         fee-distribution recipients byte-for-byte"
    );
}

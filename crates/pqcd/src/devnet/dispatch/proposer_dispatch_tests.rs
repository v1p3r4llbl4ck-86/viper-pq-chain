// SPDX-License-Identifier: BUSL-1.1
//! Tests for `dispatch`.
//!
//! Extracted from `dispatch.rs` 2026-05-10. `use super::*;`
//! brings every private item from the parent module into scope.

//! Pure unit tests for `should_build_as_proposer`.
//!
//! Exercises the gate logic that Step 2 wires into `consensus_loop`:
//! in distributed-signing mode, only the validator elected by
//! `select_proposer(h, r, set)` for this height+round should build
//! a block; every other validator stays quiescent.
//!
//! No I/O, no network, no tokio runtime — pure function under test.
//! If `cargo test` turns flaky for timing-related reasons elsewhere,
//! these tests still pin the dispatch contract deterministically.
use super::*;
use crate::keystore::{Keystore, KeystoreEntry};
use pqc_crypto::AlgId;

/// Two validators (A and B); node A's keystore holds only its own
/// seed; node B's holds only its own. Over a window of heights, each
/// node's `should_build_as_proposer` MUST return true on exactly the
/// heights where `select_proposer` elected its address, and false
/// everywhere else.
///
/// With 2 validators in legacy round-robin (round = 0), the elected
/// proposer alternates by `(height) % 2`. So half the heights each.
#[test]
fn distributed_dispatch_gates_non_proposer_validators() {
    // Addresses sort as ADDR_A < ADDR_B (lexicographic on bytes).
    const ADDR_A: [u8; 32] = [0x01; 32];
    const ADDR_B: [u8; 32] = [0x02; 32];

    let pk_a = pqc_crypto::ml_dsa_public_key_from_seed(AlgId::MlDsa65, &[0xAA; 32]).unwrap();
    let pk_b = pqc_crypto::ml_dsa_public_key_from_seed(AlgId::MlDsa65, &[0xBB; 32]).unwrap();

    let mut ks_a = Keystore::new();
    ks_a.upsert(
        ADDR_A,
        KeystoreEntry {
            sig_alg_id: AlgId::MlDsa65,
            commit_seed: [0xAA; 32],
            key_version: crate::keystore::DEFAULT_KEY_VERSION,
            public_key: pk_a,
            archival_sk: None,
        },
    );

    let mut ks_b = Keystore::new();
    ks_b.upsert(
        ADDR_B,
        KeystoreEntry {
            sig_alg_id: AlgId::MlDsa65,
            commit_seed: [0xBB; 32],
            key_version: crate::keystore::DEFAULT_KEY_VERSION,
            public_key: pk_b,
            archival_sk: None,
        },
    );

    let validators: Vec<[u8; 32]> = vec![ADDR_A, ADDR_B];

    // Walk a window of heights and check: exactly one of A/B may
    // build at each height, and which of them alternates.
    let mut a_builds = 0usize;
    let mut b_builds = 0usize;
    for h in 1..=10u64 {
        let a = should_build_as_proposer(true, &validators, h, 0, &ks_a);
        let b = should_build_as_proposer(true, &validators, h, 0, &ks_b);
        assert!(
            a ^ b,
            "at height {h}, exactly ONE of A/B must be proposer under \
             distributed_signing (select_proposer is a total function \
             over a 2-address set, round-robin by height)"
        );
        if a {
            a_builds += 1;
        }
        if b {
            b_builds += 1;
        }
    }
    // 10 heights with 2 proposers round-robin → 5 each.
    assert_eq!(a_builds, 5, "A must propose 5 of 10 heights");
    assert_eq!(b_builds, 5, "B must propose 5 of 10 heights");
}

/// Non-distributed (legacy) mode: the gate is a pass-through — every
/// tick builds regardless of address. Pins devnet-2 behavioural
/// invariance under ADR-051 N+1's feature-flag-off default.
#[test]
fn legacy_mode_never_gates() {
    const ADDR_A: [u8; 32] = [0x01; 32];
    let pk_a = pqc_crypto::ml_dsa_public_key_from_seed(AlgId::MlDsa65, &[0xAA; 32]).unwrap();
    let mut ks = Keystore::new();
    ks.upsert(
        ADDR_A,
        KeystoreEntry {
            sig_alg_id: AlgId::MlDsa65,
            commit_seed: [0xAA; 32],
            key_version: crate::keystore::DEFAULT_KEY_VERSION,
            public_key: pk_a,
            archival_sk: None,
        },
    );
    let validators: Vec<[u8; 32]> = vec![ADDR_A, [0x02; 32], [0x03; 32]];

    for h in 0..32u64 {
        for r in 0..4u32 {
            assert!(
                should_build_as_proposer(false, &validators, h, r, &ks),
                "legacy mode MUST always return true (distributed_signing = false \
                 is devnet-2's current behaviour — zero change)"
            );
        }
    }
}

/// An empty validator set under distributed_signing returns false —
/// `select_proposer` yields `None`, and a node cannot elect itself
/// out of thin air. Pins the bootstrap-path guard.
#[test]
fn distributed_dispatch_empty_validator_set_skips() {
    let ks = Keystore::new();
    let validators: Vec<[u8; 32]> = Vec::new();
    assert!(
        !should_build_as_proposer(true, &validators, 1, 0, &ks),
        "empty validator set under distributed_signing MUST skip — \
         nothing to elect"
    );
}

/// Keystore without the elected address's seed — even if this node
/// is registered as a validator on-chain, without the seed it cannot
/// sign commits, so the gate MUST skip this tick. Covers the
/// "validator registered on-chain but seed not yet loaded into
/// keystore" transient.
#[test]
fn distributed_dispatch_elected_without_seed_skips() {
    const ADDR_A: [u8; 32] = [0x01; 32];
    const ADDR_B: [u8; 32] = [0x02; 32];
    // Keystore holds B's seed; validator set is {A, B}; at height 1
    // (round 0), the elected proposer is sorted_validators[(1+0) % 2]
    // = sorted[1] = B. Wait — sorted is [[0x01;32], [0x02;32]]
    // so sorted[1] = [0x02;32] = ADDR_B, so B is elected and this
    // node (B) should build. Let's pick a height where A is elected
    // instead: height 0 → (0+0)%2 = 0 → sorted[0] = A.
    let pk_b = pqc_crypto::ml_dsa_public_key_from_seed(AlgId::MlDsa65, &[0xBB; 32]).unwrap();
    let mut ks = Keystore::new();
    ks.upsert(
        ADDR_B,
        KeystoreEntry {
            sig_alg_id: AlgId::MlDsa65,
            commit_seed: [0xBB; 32],
            key_version: crate::keystore::DEFAULT_KEY_VERSION,
            public_key: pk_b,
            archival_sk: None,
        },
    );
    let validators: Vec<[u8; 32]> = vec![ADDR_A, ADDR_B];
    // Height 2 → (2+0)%2 = 0 → A elected; our keystore has B → skip.
    assert!(
        !should_build_as_proposer(true, &validators, 2, 0, &ks),
        "elected=A, keystore has only B's seed → this node cannot \
         sign for A, so it MUST NOT attempt to build"
    );
    // Height 3 → (3+0)%2 = 1 → B elected; our keystore has B → build.
    assert!(
        should_build_as_proposer(true, &validators, 3, 0, &ks),
        "elected=B, keystore has B's seed → build"
    );
}

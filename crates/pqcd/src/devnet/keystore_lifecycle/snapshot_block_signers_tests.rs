// SPDX-License-Identifier: BUSL-1.1
//! Tests for `keystore_lifecycle`.

#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Phase 4 Gap A — pin tests for the producer-side rotation matching
//! point. `snapshot_block_signers` MUST pick the keystore entry whose
//! derived public key matches the on-chain
//! `ValidatorRecord.consensus_pk` for that operator.
//!
//! See the private design notes
//! ("Unit (in `devnet.rs::tests`)") for the test list.
//!
//! Coverage:
//! - `picks_v1_seed_pre_rotation` — ordinary case, pre-rotation:
//!   keystore has v1 entry, on-chain pk matches v1 → producer signs.
//! - `picks_v2_seed_after_activation` — post-rotation: keystore has
//!   v1 + v2 entries, on-chain pk has been flipped to v2 → producer
//!   selects v2 without operator file swap.
//! - `skips_validator_when_pk_unstaged` — rotation activates but
//!   operator never staged the v2 entry → returned signer list drops
//!   the validator (graceful quorum-loss, not panic).

use super::*;
use crate::keystore::{Keystore, KeystoreEntry, DEFAULT_KEY_VERSION};
use pqc_crypto::{ml_dsa_public_key_from_seed, AlgId};
use pqc_types::{
    account::Address,
    validator::{ValidatorRecord, ValidatorStatus},
};

/// Build a `KeystoreEntry` from raw seed material with the public key
/// derived + cached. Mirrors the production loader path.
fn make_entry(seed: [u8; 32], key_version: u32) -> KeystoreEntry {
    let pk = ml_dsa_public_key_from_seed(AlgId::MlDsa65, &seed).unwrap();
    KeystoreEntry {
        sig_alg_id: AlgId::MlDsa65,
        commit_seed: seed,
        key_version,
        public_key: pk,
        archival_sk: None,
    }
}

/// Build a `ValidatorRecord` with the derived pk for `seed`.
fn record_with_seed(addr: [u8; 32], seed: [u8; 32]) -> ValidatorRecord {
    let pk = ml_dsa_public_key_from_seed(AlgId::MlDsa65, &seed).unwrap();
    ValidatorRecord {
        operator: Address(addr),
        node_id: format!("test-{}", hex::encode(&addr[..2])),
        consensus_alg_id: AlgId::MlDsa65,
        consensus_pk: pk,
        self_bond: 1_000,
        status: ValidatorStatus::Active,
        registered_height: 0,
        tombstoned: false,
    }
}

#[test]
fn picks_v1_seed_pre_rotation() {
    // Ordinary case: keystore holds only v1; on-chain pk matches v1.
    // The producer signs with the v1 seed.
    const ADDR: [u8; 32] = [0xA1; 32];
    let v1_seed = [0x11u8; 32];

    let mut ks = Keystore::new();
    ks.upsert(ADDR, make_entry(v1_seed, DEFAULT_KEY_VERSION));

    let record = record_with_seed(ADDR, v1_seed);
    let active: Vec<&ValidatorRecord> = vec![&record];
    let signers = snapshot_block_signers(&ks, &active);

    assert_eq!(signers.len(), 1);
    assert_eq!(signers[0].validator_address, ADDR.to_vec());
    assert_eq!(signers[0].commit_seed, v1_seed);
}

#[test]
fn picks_v2_seed_after_activation() {
    // Phase 4 Gap A core: keystore holds v1 AND v2 entries, on-chain
    // pk has been flipped to v2 (simulating a successful
    // activate_pending_consensus_key_rotations flip). The producer
    // MUST select v2 — picking v1 would produce signatures the
    // verifier rejects.
    const ADDR: [u8; 32] = [0xA2; 32];
    let v1_seed = [0x11u8; 32];
    let v2_seed = [0x22u8; 32];

    let mut ks = Keystore::new();
    ks.upsert(ADDR, make_entry(v1_seed, 1));
    ks.upsert(ADDR, make_entry(v2_seed, 2));

    // On-chain: consensus_pk = derived(v2_seed) — post-activation.
    let record = record_with_seed(ADDR, v2_seed);
    let active: Vec<&ValidatorRecord> = vec![&record];
    let signers = snapshot_block_signers(&ks, &active);

    assert_eq!(signers.len(), 1, "v2 entry must be selected");
    assert_eq!(
        signers[0].commit_seed, v2_seed,
        "producer must sign with v2 seed when on-chain pk is v2"
    );
}

#[test]
fn skips_validator_when_pk_unstaged() {
    // Operator missed the pre-ship: rotation has activated on-chain
    // (consensus_pk is now v2's pk) but keystore only has v1.
    // `snapshot_block_signers` must drop this validator from the
    // signer list — quorum-loss is the natural consequence (warned).
    const ADDR: [u8; 32] = [0xA3; 32];
    let v1_seed = [0x11u8; 32];
    let v2_seed = [0x22u8; 32];

    let mut ks = Keystore::new();
    ks.upsert(ADDR, make_entry(v1_seed, 1));
    // ks does NOT contain v2 — operator forgot to stage it.

    let record = record_with_seed(ADDR, v2_seed);
    let active: Vec<&ValidatorRecord> = vec![&record];
    let signers = snapshot_block_signers(&ks, &active);

    assert!(
        signers.is_empty(),
        "unstaged rotation pk → drop validator from signer set (no panic)"
    );
}

#[test]
fn includes_only_validators_with_matching_seeds_in_mixed_set() {
    // Multi-validator: V_a's pk matches; V_b's pk doesn't (rotation
    // missed pre-ship); V_c not in keystore at all (D-06: registered
    // on-chain but seed not yet loaded). Result: only V_a signs.
    const ADDR_A: [u8; 32] = [0xB1; 32];
    const ADDR_B: [u8; 32] = [0xB2; 32];
    const ADDR_C: [u8; 32] = [0xB3; 32];

    let seed_a = [0x01u8; 32];
    let seed_b_v1 = [0x02u8; 32];
    let seed_b_v2_unstaged = [0x99u8; 32];

    let mut ks = Keystore::new();
    ks.upsert(ADDR_A, make_entry(seed_a, 1));
    ks.upsert(ADDR_B, make_entry(seed_b_v1, 1));
    // ADDR_C: no entry at all.

    let rec_a = record_with_seed(ADDR_A, seed_a);
    // V_b on-chain pk has been flipped to v2 but v2 is not staged:
    let rec_b = record_with_seed(ADDR_B, seed_b_v2_unstaged);
    let rec_c = record_with_seed(ADDR_C, [0x55u8; 32]);

    let active: Vec<&ValidatorRecord> = vec![&rec_a, &rec_b, &rec_c];
    let signers = snapshot_block_signers(&ks, &active);

    assert_eq!(signers.len(), 1, "only V_a signs");
    assert_eq!(signers[0].validator_address, ADDR_A.to_vec());
}

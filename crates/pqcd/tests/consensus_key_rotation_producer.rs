// SPDX-License-Identifier: BUSL-1.1
//! Phase 4 Gap A — producer-path integration test for the `ConsensusKeyRotate`
//! activation flow.
//!
//! ## Why this test exists
//!
//! `crates/pqc-consensus/tests/consensus_key_rotation_replay.rs` covers
//! the state-store side: it proves that
//! `StateStore::activate_pending_consensus_key_rotations` is wired into
//! both the live engine and the cold-sync replay paths and that it
//! produces byte-identical state-roots end-to-end. That test is purely
//! a state-machine + replay-parity assertion; it does NOT exercise the
//! producer-side keystore lookup.
//!
//! Phase 4 Gap A (`PHASE-4-KEY-ROTATION-RESEARCH.md` §1.2) closes the
//! producer-side hole: when the on-chain `ValidatorRecord.consensus_pk`
//! flips at the rotation boundary, `Keystore::get_for_pk(addr,
//! &record.consensus_pk)` MUST select the staged v_n+1 entry, not the
//! v_n entry the validator was using before. This test pins that the
//! keystore + state-store contract holds across:
//!
//!  1. `keystore.json` initially contains v1 only → `get_for_pk` selects
//!     v1 and `entry.commit_seed` would produce the signature the
//!     verifier expects.
//!  2. Operator stages a v2 entry into `keystore.json` (the
//!     `--in-place` path — exact same atomic-rename writer
//!     `pqcd wallet rotate-consensus-key --in-place` uses).
//!  3. `Keystore::reload_if_changed` picks up v2 (mtime advanced).
//!  4. `StateStore::activate_pending_consensus_key_rotations` flips
//!     `ValidatorRecord.consensus_pk` to v2's pk at the rotation
//!     height (simulated directly — same path the unit tests at
//!     `crates/pqc-state/src/tests.rs::activate_*` cover).
//!  5. `get_for_pk(&addr, &record.consensus_pk)` now returns v2's entry,
//!     and v2's `commit_seed` derives the new pk.
//!  6. The unstaged-v2 case (operator forgot the pre-ship): keystore
//!     still has v1 only after the on-chain flip → `get_for_pk` returns
//!     None → producer-side correctly drops the validator from the
//!     signer set (graceful quorum dropout, not panic).
//!
//! ## Scope
//!
//! Pure keystore + state-store contract test. Does NOT spin up a
//! 3-node devnet (the full §1.5 integration harness is an `#[ignore]`
//! follow-up). The `snapshot_block_signers` private helper is
//! exercised indirectly via its semantic equivalent — `Keystore::get_for_pk`
//! is the only consensus-rotation-relevant lookup it calls — covered
//! by the `crates/pqcd/src/devnet.rs::snapshot_block_signers_tests`
//! unit module.
//!
//! ## How to interpret a failure
//!
//! - `phase_a_pre_rotation_picks_v1` fails: producer-path keystore
//!   lookup is broken even before any rotation. Likely a regression in
//!   `Keystore::from_validators` or `get_for_pk` derived-pk caching.
//! - `phase_b_rotation_then_v2_staged_picks_v2` fails: the
//!   `--in-place`-style atomic rewrite + reload_if_changed contract
//!   broke. Check the file-format codec or the mtime-gated reload.
//! - `phase_c_unstaged_drops_validator` fails: the graceful-skip
//!   contract for missing pk versions broke. Producer would now sign
//!   with the wrong key (or panic), which is worse than the quorum
//!   dropout this test pins.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use pqc_crypto::{ml_dsa_public_key_from_seed, AlgId};
use pqc_state::StateStore;
use pqc_types::{
    account::Address,
    consensus_rotation::ConsensusKeyRotation,
    validator::{ValidatorRecord, ValidatorStatus},
};
use pqcd::keystore::Keystore;

const ROTATION_AT_HEIGHT: u64 = 50;

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn tempdir(label: &str) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let path = std::env::temp_dir().join(format!(
        "pqcd-rotation-prod-{label}-{}-{unique}-{n}",
        std::process::id()
    ));
    std::fs::create_dir_all(&path).unwrap();
    path
}

/// Build a single-validator `StateStore` with the validator pinned to
/// `current_pk`, plus a pending rotation that will activate at
/// `ROTATION_AT_HEIGHT` flipping the pk to `next_pk`.
fn build_state_with_pending_rotation(
    operator: Address,
    current_pk: Vec<u8>,
    next_pk: Vec<u8>,
) -> StateStore {
    let mut state = StateStore::new();
    state.insert_validator(ValidatorRecord {
        operator: operator.clone(),
        node_id: "phase4-gap-a-validator".to_owned(),
        consensus_alg_id: AlgId::MlDsa65,
        consensus_pk: current_pk,
        self_bond: 1_000,
        status: ValidatorStatus::Active,
        registered_height: 0,
        tombstoned: false,
    });
    state.insert_consensus_key_rotation(ConsensusKeyRotation {
        operator,
        new_alg_id: AlgId::MlDsa65,
        new_pk_bytes: next_pk,
        rotation_start_height: ROTATION_AT_HEIGHT,
        recorded_at_height: 1,
    });
    state
}

/// Write the operator's local `keystore.json` containing the v1 entry
/// only. Mirrors the genesis-time bootstrap (single-version per
/// validator).
fn write_keystore_v1(path: &std::path::Path, addr: [u8; 32], v1_seed: [u8; 32]) {
    let body = serde_json::json!({
        "validators": [
            {
                "address_hex": hex::encode(addr),
                "sig_alg_id": AlgId::MlDsa65.as_u16(),
                "commit_seed_hex": hex::encode(v1_seed),
                "key_version": 1,
            }
        ]
    });
    std::fs::write(path, serde_json::to_vec_pretty(&body).unwrap()).unwrap();
}

/// Stage a v2 entry into the running keystore.json — same shape the
/// `pqcd wallet rotate-consensus-key --in-place` CLI emits.
fn stage_keystore_v2(path: &std::path::Path, addr: [u8; 32], v1_seed: [u8; 32], v2_seed: [u8; 32]) {
    let body = serde_json::json!({
        "validators": [
            {
                "address_hex": hex::encode(addr),
                "sig_alg_id": AlgId::MlDsa65.as_u16(),
                "commit_seed_hex": hex::encode(v1_seed),
                "key_version": 1,
            },
            {
                "address_hex": hex::encode(addr),
                "sig_alg_id": AlgId::MlDsa65.as_u16(),
                "commit_seed_hex": hex::encode(v2_seed),
                "key_version": 2,
            }
        ]
    });
    std::fs::write(path, serde_json::to_vec_pretty(&body).unwrap()).unwrap();
}

#[test]
fn phase_a_pre_rotation_picks_v1() {
    // Pre-rotation: keystore has v1, on-chain pk is v1's pk.
    // get_for_pk MUST return the v1 entry.
    let dir = tempdir("phase_a");
    let path = dir.join("keystore.json");

    let operator_addr = [0x01u8; 32];
    let v1_seed = [0x11u8; 32];
    let v1_pk = ml_dsa_public_key_from_seed(AlgId::MlDsa65, &v1_seed).unwrap();
    let v2_seed = [0x22u8; 32];
    let v2_pk = ml_dsa_public_key_from_seed(AlgId::MlDsa65, &v2_seed).unwrap();

    write_keystore_v1(&path, operator_addr, v1_seed);

    let state = build_state_with_pending_rotation(Address(operator_addr), v1_pk.clone(), v2_pk);
    let validator = state
        .active_validators()
        .into_iter()
        .find(|v| v.operator.0 == operator_addr)
        .expect("validator present");

    let ks = Keystore::load_from_file(&path).expect("load");
    let entry = ks
        .get_for_pk(&operator_addr, &validator.consensus_pk)
        .expect("pre-rotation lookup must succeed");
    assert_eq!(entry.key_version, 1);
    assert_eq!(entry.commit_seed, v1_seed);
    assert_eq!(entry.public_key, v1_pk);

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn phase_b_rotation_then_v2_staged_picks_v2() {
    // The full Phase-4 Gap A flow:
    // 1. Operator stages v1 only at boot.
    // 2. Operator runs `pqcd wallet rotate-consensus-key --in-place`,
    //    which writes a 2-entry keystore.json (v1 + v2).
    // 3. The producer's mtime-gated reload picks up the v2 entry.
    // 4. At ROTATION_AT_HEIGHT the state-store activation hook flips
    //    consensus_pk on-chain.
    // 5. get_for_pk returns the v2 entry (matched by derived pk).
    let dir = tempdir("phase_b");
    let path = dir.join("keystore.json");

    let operator_addr = [0x01u8; 32];
    let v1_seed = [0x11u8; 32];
    let v1_pk = ml_dsa_public_key_from_seed(AlgId::MlDsa65, &v1_seed).unwrap();
    let v2_seed = [0x22u8; 32];
    let v2_pk = ml_dsa_public_key_from_seed(AlgId::MlDsa65, &v2_seed).unwrap();

    // Step 1: boot with v1 only.
    write_keystore_v1(&path, operator_addr, v1_seed);
    let mut ks = Keystore::new();
    ks.reload_if_changed(&path).expect("first load");
    assert_eq!(ks.staged_versions_for(&operator_addr), vec![1]);

    // Step 2: build state with the pending rotation (will activate at
    // height 50). At this point the on-chain pk is still v1's pk.
    let mut state =
        build_state_with_pending_rotation(Address(operator_addr), v1_pk.clone(), v2_pk.clone());

    // Step 3: operator stages v2 BEFORE the activation height
    // (matches the recommended workflow). Sleep briefly to ensure the
    // mtime moves on low-resolution filesystems.
    std::thread::sleep(std::time::Duration::from_millis(15));
    stage_keystore_v2(&path, operator_addr, v1_seed, v2_seed);
    let changed = ks.reload_if_changed(&path).expect("reload after stage");
    assert!(changed, "reload must report change");
    assert_eq!(
        ks.staged_versions_for(&operator_addr),
        vec![1, 2],
        "both versions present after staging"
    );

    // Pre-activation: on-chain pk is still v1; get_for_pk picks v1.
    let pre_validator = state
        .active_validators()
        .into_iter()
        .find(|v| v.operator.0 == operator_addr)
        .unwrap()
        .clone();
    let pre_entry = ks
        .get_for_pk(&operator_addr, &pre_validator.consensus_pk)
        .expect("pre-activation pick");
    assert_eq!(pre_entry.key_version, 1);

    // Step 4: simulate the activation flip at ROTATION_AT_HEIGHT.
    // `activate_pending_consensus_key_rotations` is the exact same
    // function the live engine + cold-sync replay paths call.
    let activated = state.activate_pending_consensus_key_rotations(ROTATION_AT_HEIGHT);
    assert!(
        activated.iter().any(|(addr, _)| addr.0 == operator_addr),
        "activation must report this validator"
    );

    // Step 5: post-activation, on-chain pk is v2's pk; get_for_pk
    // selects v2 transparently.
    let post_validator = state
        .active_validators()
        .into_iter()
        .find(|v| v.operator.0 == operator_addr)
        .unwrap()
        .clone();
    assert_eq!(
        post_validator.consensus_pk, v2_pk,
        "state-store activation flipped the pk"
    );
    let post_entry = ks
        .get_for_pk(&operator_addr, &post_validator.consensus_pk)
        .expect("post-activation pick");
    assert_eq!(
        post_entry.key_version, 2,
        "post-activation lookup must select v2"
    );
    assert_eq!(
        post_entry.commit_seed, v2_seed,
        "v2 seed produces signatures that verify under the new on-chain pk"
    );

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn phase_c_unstaged_drops_validator() {
    // Operator missed the pre-ship: keystore has v1 only, but the
    // chain has activated v2. get_for_pk returns None — the producer's
    // snapshot_block_signers will drop this validator from the signer
    // set with a `tracing::warn!`, and quorum loss is the natural
    // (graceful) consequence.
    let dir = tempdir("phase_c");
    let path = dir.join("keystore.json");

    let operator_addr = [0x01u8; 32];
    let v1_seed = [0x11u8; 32];
    let v1_pk = ml_dsa_public_key_from_seed(AlgId::MlDsa65, &v1_seed).unwrap();
    let v2_seed_unstaged = [0x22u8; 32];
    let v2_pk_unstaged = ml_dsa_public_key_from_seed(AlgId::MlDsa65, &v2_seed_unstaged).unwrap();

    write_keystore_v1(&path, operator_addr, v1_seed);
    let mut state =
        build_state_with_pending_rotation(Address(operator_addr), v1_pk, v2_pk_unstaged);

    let ks = Keystore::load_from_file(&path).expect("load");
    assert_eq!(
        ks.staged_versions_for(&operator_addr),
        vec![1],
        "pre-condition: operator only has v1 staged"
    );

    // Activate the rotation on-chain. v2 is now the on-chain pk.
    let _ = state.activate_pending_consensus_key_rotations(ROTATION_AT_HEIGHT);
    let validator = state
        .active_validators()
        .into_iter()
        .find(|v| v.operator.0 == operator_addr)
        .unwrap()
        .clone();

    // Lookup MUST return None (NOT panic, NOT return v1).
    let entry = ks.get_for_pk(&operator_addr, &validator.consensus_pk);
    assert!(
        entry.is_none(),
        "missing-pk lookup must return None — caller drops validator from signers"
    );

    // Sanity: get_latest still works (returns v1, but that's only used
    // by non-rotation paths like archival).
    assert_eq!(
        ks.get_latest(&operator_addr)
            .expect("v1 still latest")
            .key_version,
        1
    );

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn rolling_keystore_with_both_versions_survives_activation() {
    // Operator-friendly pattern documented in the runbook:
    // stage v2 well ahead of activation height, leave v1 alone. Same
    // keystore.json file is correct for the validator BOTH before AND
    // after activation; no operator action at the boundary.
    let dir = tempdir("rolling");
    let path = dir.join("keystore.json");

    let operator_addr = [0x01u8; 32];
    let v1_seed = [0x11u8; 32];
    let v1_pk = ml_dsa_public_key_from_seed(AlgId::MlDsa65, &v1_seed).unwrap();
    let v2_seed = [0x22u8; 32];
    let v2_pk = ml_dsa_public_key_from_seed(AlgId::MlDsa65, &v2_seed).unwrap();

    // Stage both upfront.
    stage_keystore_v2(&path, operator_addr, v1_seed, v2_seed);
    let ks = Keystore::load_from_file(&path).expect("load");

    // Phase 1: pre-activation. On-chain pk is v1 → get_for_pk returns v1.
    let mut state =
        build_state_with_pending_rotation(Address(operator_addr), v1_pk.clone(), v2_pk.clone());
    let pre = state
        .active_validators()
        .into_iter()
        .find(|v| v.operator.0 == operator_addr)
        .unwrap()
        .clone();
    assert_eq!(
        ks.get_for_pk(&operator_addr, &pre.consensus_pk)
            .unwrap()
            .key_version,
        1
    );

    // Phase 2: activation flips on-chain pk to v2 → same keystore →
    // get_for_pk returns v2.
    let _ = state.activate_pending_consensus_key_rotations(ROTATION_AT_HEIGHT);
    let post = state
        .active_validators()
        .into_iter()
        .find(|v| v.operator.0 == operator_addr)
        .unwrap()
        .clone();
    assert_eq!(
        ks.get_for_pk(&operator_addr, &post.consensus_pk)
            .unwrap()
            .key_version,
        2
    );

    std::fs::remove_dir_all(&dir).ok();
}

// ── HSM phase-plan trait integration ─────────────────────────────────
//
// `pqc-hsm` introduces the `CommitSigner` trait (post-Phase-4
// scaffolding). The producer-side rotation lookup MUST work through
// the trait surface as well as the legacy concrete-`Vec<LocalCommitSigner>`
// path. This block extends the rotation test with the trait-object
// variant — pinning that future SoftHSM / CloudHSM signers slot in
// without regressing the Phase-4 Gap-A activation logic.
//
// See the private design notes and `crates/pqc-hsm`.

// `CommitSigner` trait methods are invoked through `Box<dyn CommitSigner>`
// in the test bodies below; the dyn-vtable dispatch reaches the methods
// without an explicit `use pqc_hsm::CommitSigner` since each call site
// goes through a trait object.

/// The trait-object variant of `snapshot_block_signers` MUST select
/// the v2 entry after activation, exactly as the concrete path does
/// in `phase_b_rotation_then_v2_staged_picks_v2`. This is the
/// HSM-phase parity gate: at the call site, swapping
/// `Vec<LocalCommitSigner>` for `Vec<Box<dyn CommitSigner>>` produces
/// the same per-validator outcome.
#[test]
fn hsm_trait_object_picks_v2_after_activation() {
    let dir = tempdir("hsm_trait");
    let path = dir.join("keystore.json");

    let operator_addr = [0x01u8; 32];
    let v1_seed = [0x11u8; 32];
    let v1_pk = ml_dsa_public_key_from_seed(AlgId::MlDsa65, &v1_seed).unwrap();
    let v2_seed = [0x22u8; 32];
    let v2_pk = ml_dsa_public_key_from_seed(AlgId::MlDsa65, &v2_seed).unwrap();

    // Stage both versions upfront — same shape as the rolling-keystore
    // operator pattern.
    stage_keystore_v2(&path, operator_addr, v1_seed, v2_seed);
    let ks = Keystore::load_from_file(&path).expect("load");

    let mut state =
        build_state_with_pending_rotation(Address(operator_addr), v1_pk.clone(), v2_pk.clone());

    // Pre-activation: trait-object path picks v1.
    let pre_records: Vec<ValidatorRecord> = state
        .active_validators()
        .into_iter()
        .map(|v| (*v).clone())
        .collect();
    let pre_refs: Vec<&ValidatorRecord> = pre_records.iter().collect();
    let pre_signers = pqcd::devnet::snapshot_block_signers_dyn(&ks, &pre_refs);
    assert_eq!(pre_signers.len(), 1, "pre-rotation: one signer");
    assert_eq!(pre_signers[0].validator_address(), &operator_addr);
    assert_eq!(pre_signers[0].alg_id(), AlgId::MlDsa65);
    // Sign canary preimage through the trait — round-trip must work.
    let pre_sig = pre_signers[0]
        .sign_commit(b"VIPER-HSM-CANARY-V1")
        .expect("trait sign_commit pre-activation");
    assert!(!pre_sig.is_empty());

    // Activate the rotation on-chain; trait-object path now picks v2.
    let _ = state.activate_pending_consensus_key_rotations(ROTATION_AT_HEIGHT);
    let post_records: Vec<ValidatorRecord> = state
        .active_validators()
        .into_iter()
        .map(|v| (*v).clone())
        .collect();
    let post_refs: Vec<&ValidatorRecord> = post_records.iter().collect();
    let post_signers = pqcd::devnet::snapshot_block_signers_dyn(&ks, &post_refs);
    assert_eq!(post_signers.len(), 1, "post-rotation: one signer");
    let post_sig = post_signers[0]
        .sign_commit(b"VIPER-HSM-CANARY-V1")
        .expect("trait sign_commit post-activation");
    assert!(!post_sig.is_empty());

    // The signature SHOULD NOT verify under the v1 pubkey (it's signed
    // by v2's seed) — proves the trait object switched seeds at the
    // activation boundary, not just a dispatch passthrough.
    use pqc_crypto::sign::{PublicKey, Signature, SignatureVerifier};
    use pqc_crypto::MlDsaVerifier;
    let v1_pk_obj = PublicKey {
        alg_id: AlgId::MlDsa65,
        bytes: v1_pk.clone(),
    };
    let post_sig_obj = Signature {
        alg_id: AlgId::MlDsa65,
        bytes: post_sig.clone(),
    };
    assert!(
        MlDsaVerifier
            .verify(&v1_pk_obj, b"VIPER-HSM-CANARY-V1", &post_sig_obj)
            .is_err(),
        "post-activation sig MUST NOT verify under v1 pk — proves seed swap"
    );
    let v2_pk_obj = PublicKey {
        alg_id: AlgId::MlDsa65,
        bytes: v2_pk,
    };
    MlDsaVerifier
        .verify(&v2_pk_obj, b"VIPER-HSM-CANARY-V1", &post_sig_obj)
        .expect("post-activation sig MUST verify under v2 pk");

    std::fs::remove_dir_all(&dir).ok();
}

/// Unstaged-pk skip path through the trait: when the operator missed
/// the v2 pre-ship, the trait-object signer list drops the validator
/// just like the concrete path does.
#[test]
fn hsm_trait_object_skips_unstaged_validator() {
    let dir = tempdir("hsm_trait_unstaged");
    let path = dir.join("keystore.json");

    let operator_addr = [0x01u8; 32];
    let v1_seed = [0x11u8; 32];
    let v1_pk = ml_dsa_public_key_from_seed(AlgId::MlDsa65, &v1_seed).unwrap();
    let v2_seed_unstaged = [0x22u8; 32];
    let v2_pk_unstaged = ml_dsa_public_key_from_seed(AlgId::MlDsa65, &v2_seed_unstaged).unwrap();

    write_keystore_v1(&path, operator_addr, v1_seed);
    let mut state =
        build_state_with_pending_rotation(Address(operator_addr), v1_pk, v2_pk_unstaged);

    let ks = Keystore::load_from_file(&path).expect("load");
    let _ = state.activate_pending_consensus_key_rotations(ROTATION_AT_HEIGHT);
    let records: Vec<ValidatorRecord> = state
        .active_validators()
        .into_iter()
        .map(|v| (*v).clone())
        .collect();
    let refs: Vec<&ValidatorRecord> = records.iter().collect();

    let signers = pqcd::devnet::snapshot_block_signers_dyn(&ks, &refs);
    assert!(
        signers.is_empty(),
        "trait-object path drops the validator when no matching seed staged"
    );

    std::fs::remove_dir_all(&dir).ok();
}

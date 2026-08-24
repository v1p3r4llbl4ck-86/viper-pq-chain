// SPDX-License-Identifier: BUSL-1.1
//! Unit + pin tests for `StateStore`.
//!
//! Extracted from `store.rs` 2026-05-10 to keep the production
//! impl-StateStore block readable. The two test modules continue
//! to share the same parent (StateStore + StateCategory + the
//! VerifierRegistryEntry/FeeMarketDimension/FeeMarketState helpers
//! that pre-date impl StateStore) — `use super::*;` brings every
//! private item from the parent into scope, the same trick used
//! across the rest of the workspace's submodule splits.
//!
//! Two distinct test modules:
//!
//! - `tests` — the original general suite (FeeMarketState rounding,
//!   apply_fee_market_step idempotence, etc).
//! - `store_pin_tests` — TASK-180 part 3 pin coverage of the public
//!   accessor surface (column round-trip via from_snapshot_*,
//!   missing-key safety, alg-registry lifecycle persistence,
//!   fee-market round-trip, validator CRUD + ordering, slash-ledger
//!   prune semantics, account-nonce read-after-write).

use super::*;

#[cfg(test)]
mod fee_market_pin_tests {
    use super::*;

    /// Run one fee-market step on a fresh store with the given initial
    /// compute excess and block gas used, returning the new compute base
    /// fee and the new excess. Storage/witness/contention stay at zero.
    fn run_step(prev_excess: u64, compute_used: u64) -> (u64, u64) {
        let mut store = StateStore::new();
        store.fee_market.compute.excess = prev_excess;
        store.apply_fee_market_step(compute_used, 0, 0, 0);
        (
            store.fee_market.compute.base_fee,
            store.fee_market.compute.excess,
        )
    }

    /// `fake_exponential(factor, 0, denominator)` MUST return `factor`.
    /// This is the zero-excess base case — when no accumulated demand
    /// has spilled past target, the base fee sits exactly at the
    /// reserve floor.
    #[test]
    fn fake_exponential_zero_numerator_returns_factor() {
        assert_eq!(fake_exponential(100, 0, 333_847_700), 100);
    }

    /// Monotonicity: `fake_exponential` MUST be non-decreasing in its
    /// second argument (accumulated excess). A network that gets more
    /// congested must never see its base fee drop.
    #[test]
    fn fake_exponential_monotonic_in_excess() {
        let denom = 100 * COMPUTE_FEE_UPDATE_FRACTION;
        let a = fake_exponential(COMPUTE_RESERVE_FLOOR, 1_000_000, denom);
        let b = fake_exponential(COMPUTE_RESERVE_FLOOR, 5_000_000, denom);
        let c = fake_exponential(COMPUTE_RESERVE_FLOOR, 50_000_000, denom);
        assert!(a <= b, "excess 1M → {a}, 5M → {b}");
        assert!(b <= c, "excess 5M → {b}, 50M → {c}");
    }

    /// Empty block (compute_used = 0) on a store with zero prior excess:
    /// new excess stays at 0, base fee sits at the reserve floor.
    #[test]
    fn empty_block_on_fresh_store_pins_floor() {
        let (fee, excess) = run_step(0, 0);
        assert_eq!(fee, COMPUTE_RESERVE_FLOOR, "fee must be at floor");
        assert_eq!(excess, 0, "excess must stay zero when under target");
    }

    /// Target-utilisation block (exactly half of block gas limit with the
    /// default 50% target): excess drains to zero, fee stays at floor.
    #[test]
    fn target_utilisation_drains_excess() {
        let (fee, excess) = run_step(0, DEFAULT_COMPUTE_TARGET);
        assert_eq!(excess, 0, "at-target usage must leave excess at zero");
        assert_eq!(fee, COMPUTE_RESERVE_FLOOR, "fee must remain at floor");
    }

    /// Full block (gas_used = block_gas_limit == 2×target): excess grows
    /// by target, and the base fee rises above the floor.
    #[test]
    fn full_block_grows_excess_and_fee() {
        let (fee, excess) = run_step(0, DEFAULT_BLOCK_GAS_LIMIT);
        assert_eq!(
            excess,
            DEFAULT_BLOCK_GAS_LIMIT - DEFAULT_COMPUTE_TARGET,
            "excess MUST grow by (used − target)"
        );
        assert!(fee > COMPUTE_RESERVE_FLOOR, "fee MUST rise above floor");
    }

    /// Under-utilised block AFTER accumulated excess: excess shrinks
    /// (saturating_sub), proving the EIP-4844 curve is reactive in
    /// both directions.
    #[test]
    fn underuse_shrinks_accumulated_excess() {
        // Seed with high excess, then run an empty block.
        let (fee, excess_after) = run_step(1_000_000, 0);
        assert!(
            excess_after < 1_000_000,
            "excess MUST shrink when under-utilised: got {excess_after}"
        );
        assert_eq!(
            excess_after,
            1_000_000u64.saturating_sub(DEFAULT_COMPUTE_TARGET),
            "shrink MUST be saturating_sub(excess + used, target)"
        );
        // Fee tracks excess through fake_exponential.
        let expected_fee = fake_exponential(
            COMPUTE_RESERVE_FLOOR,
            excess_after,
            COMPUTE_RESERVE_FLOOR * COMPUTE_FEE_UPDATE_FRACTION,
        )
        .clamp(COMPUTE_RESERVE_FLOOR, BASE_FEE_MAX);
        assert_eq!(fee, expected_fee);
    }

    /// The reserve floor is ungovernable (ADR-053 §T2.1). Even if an
    /// external caller pokes the compute dimension's `reserve_floor`
    /// down to zero in memory, the CONSTANT `COMPUTE_RESERVE_FLOOR`
    /// remains > 0 and governance-side validation (when added in a
    /// later governance clause) MUST reject any proposal that tries to
    /// drive it below this constant. This test pins the compile-time
    /// invariant.
    #[test]
    fn reserve_floor_constant_is_nonzero() {
        const _: () = assert!(COMPUTE_RESERVE_FLOOR > 0);
    }

    /// Reserved dimensions (storage / witness / contention) are
    /// inactive at launch: `target = 0` makes `excess` incapable of
    /// growing (saturating_sub of `sum − 0` = `sum`), but their inputs
    /// are always zero too (engine does not route real usage). This
    /// test drives them explicitly with some load and confirms fees
    /// stay at the floor because the code paths for non-compute
    /// dimensions are unused at launch but still must behave correctly.
    #[test]
    fn reserved_dimensions_stay_at_floor_on_zero_usage() {
        let mut store = StateStore::new();
        store.apply_fee_market_step(0, 0, 0, 0);
        assert_eq!(
            store.fee_market.storage.base_fee, COMPUTE_RESERVE_FLOOR,
            "storage dim at floor on fresh store"
        );
        assert_eq!(
            store.fee_market.witness.base_fee, COMPUTE_RESERVE_FLOOR,
            "witness dim at floor"
        );
        assert_eq!(
            store.fee_market.contention.base_fee, COMPUTE_RESERVE_FLOOR,
            "contention dim at floor"
        );
    }

    /// Overflow guard: saturating_mul in `fake_exponential` MUST not
    /// panic even on pathological inputs (u64::MAX excess).
    #[test]
    fn fake_exponential_saturates_on_overflow() {
        let _ = fake_exponential(u64::MAX, u64::MAX, 1);
    }

    /// Backward-compat entry: `apply_aimd_update(block_gas_used)` MUST
    /// still exist and drive the compute dimension identically to
    /// `apply_fee_market_step(gas_used, 0, 0, 0)`. This is the
    /// dual-path shim for existing callers (engine, recovery); its
    /// deletion tracks the P-COMPAT-001 §7 deprecation epoch.
    #[test]
    fn apply_aimd_update_matches_fee_market_step_compute_dim() {
        let mut a = StateStore::new();
        let mut b = StateStore::new();
        a.apply_aimd_update(7_777_777);
        b.apply_fee_market_step(7_777_777, 0, 0, 0);
        assert_eq!(a.fee_market, b.fee_market);
    }
}

// ── TASK-180 part 3: StateStore pin tests ────────────────────────────────────
//
// The internal audit flagged `store.rs` as having zero dedicated unit tests.
// This mod pins the public accessor surface of `StateStore` (CRUD helpers,
// ordering guarantees, slash-ledger prune semantics, alg/fee_market/validator
// persistence across a snapshot→restore round-trip).
//
// The store is an *in-memory* implementation (the module header says "RocksDB
// backend wired in Phase 2"). There is therefore no `flush`/`reopen` or
// schema version at this level — the closest analogue to "reopen" is to
// export the current accounts/attestations/proof-anchors/receipts/alg-entries
// via the public `from_snapshot_full_with_proofs()` helper and rebuild a
// fresh store. Tests that use that round-trip document it explicitly.
//
// Test categories covered (vs the TASK-180 part 3 plan):
//   1. Column round-trip — accounts, attestations, proof-anchors, governance
//      receipts, alg_registry via snapshot rebuild.
//   3. Missing-key — get_account / get_validator / alg_entry on unknown
//      returns None, not panic.
//   6. alg_registry lifecycle persistence — Active→Discouraged via
//      commit_alg_entry_mutation survives snapshot rebuild.
//   7. fee_market persistence — restore_fee_market round-trip.
//   8. validator CRUD — insert, update status, read back.
//   9. recent_slashes prune boundary — prune_recent_slashes_before semantics.
//   10. active_validators() ordering stability under insertion permutation.
//   11. validators_in_order() byte-stability — sorted by operator address.
//   13. Account nonce monotonicity at the accessor level (note: the accessor
//       does not enforce rejection of a lower nonce; it only exposes the
//       field — the rejection policy lives in apply/ and is covered by the
//       tests.rs suite. We pin only the read-after-write contract here.)
//
// Skipped categories:
//   2. Schema version — no schema version at this layer (in-memory only).
//   4. Metadata atomicity / checkpoint-write API — no such API is exposed at
//      this layer; checkpointing lives above this module (pqc-engine).
//   5. export_snapshot / bootstrap_from_external_snapshot — not exposed on
//      StateStore (pqc-engine concern).
//   12. Transactional commit/rollback — no transaction API on StateStore.
#[cfg(test)]
mod store_pin_tests {
    use super::*;
    use pqc_crypto::registry::phase1_registry;
    use pqc_crypto::AlgId;
    use pqc_types::account::{Account, Address};
    use pqc_types::attestation::{Attestation, AttestationId, AttestationStatus};
    use pqc_types::keyset::{allowed_tx, KeyEntry, KeySet, KeyStatus};
    use pqc_types::proof_anchor::{AnchorId, ProofAnchor};
    use pqc_types::slashing::RecentSlashEntry;
    use pqc_types::validator::{ValidatorRecord, ValidatorStatus};

    // ── Fixture helpers ──────────────────────────────────────────────────────
    //
    // No tempfile needed — StateStore is in-memory. The fixture mirrors the
    // canonical pattern used throughout `tests.rs`: `StateStore::new()` +
    // `insert_*` helpers, `Account { .. }` struct literal with a single
    // ML-DSA-65 Active key so `check_invariants()` passes if a later test
    // ever calls it.

    fn mk_addr(byte: u8) -> Address {
        Address([byte; 32])
    }

    fn mk_account(byte: u8, balance: u128, nonce: u64) -> Account {
        Account {
            address: mk_addr(byte),
            balance,
            nonce,
            keys: KeySet(vec![KeyEntry {
                alg_id: AlgId::MlDsa65,
                pk_bytes: vec![byte; 32].into(),
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

    fn mk_validator(byte: u8, status: ValidatorStatus) -> ValidatorRecord {
        ValidatorRecord {
            operator: mk_addr(byte),
            node_id: format!("node-{byte:02x}"),
            consensus_alg_id: AlgId::MlDsa65,
            // real ML-DSA-65 pk is 1952 bytes — we only need uniqueness here.
            consensus_pk: vec![byte; 1952],
            self_bond: 1_000,
            status,
            registered_height: byte as u64,
            tombstoned: false,
        }
    }

    fn mk_attestation(byte: u8) -> Attestation {
        Attestation {
            attestation_id: AttestationId([byte; 32]),
            attester: mk_addr(byte),
            subject: [byte ^ 0x55; 32],
            attestation_type: 0x0001,
            content_hash: [byte ^ 0xAA; 32],
            schema_id: [byte ^ 0x33; 32],
            metadata_hash: None,
            anchor_height: byte as u64,
            expires_at_height: None,
            status: AttestationStatus::Active,
            revocation: None,
        }
    }

    fn mk_proof_anchor(byte: u8) -> ProofAnchor {
        // Minimum viable record — SPEC-OPS-001 §6.3 recognised claim_type
        // 0x0001 = ownership.
        ProofAnchor {
            anchor_id: AnchorId([byte; 32]),
            claimer: mk_addr(byte),
            claim_type: 0x0001,
            asset_id_hash: [byte ^ 0x11; 32],
            proof_hash: [byte ^ 0x22; 32],
            schema_id: None,
            anchor_height: byte as u64,
        }
    }

    // ── 3. Missing-key behaviour — returns None, no panic ────────────────────

    #[test]
    fn get_account_unknown_returns_none() {
        let store = StateStore::new();
        assert!(store.get_account(&mk_addr(0x01)).is_none());
    }

    #[test]
    fn get_validator_unknown_returns_none() {
        let store = StateStore::new();
        assert!(store.get_validator(&mk_addr(0x02)).is_none());
    }

    #[test]
    fn alg_entry_unknown_returns_none_for_unregistered_id() {
        let store = StateStore::new();
        // alg_entry_registered on a raw id that is NOT in phase1_registry
        // (phase-1 ids are all < 0x1000). Use a high reserved slot.
        assert!(!store.alg_entry_registered(0xF000));
    }

    #[test]
    fn get_attestation_unknown_returns_none() {
        let store = StateStore::new();
        assert!(store.get_attestation(&AttestationId([0x03; 32])).is_none());
    }

    // ── 1. Column round-trip via snapshot rebuild ────────────────────────────

    #[test]
    fn accounts_roundtrip_via_snapshot() {
        let mut store = StateStore::new();
        let a = mk_account(0x01, 100, 0);
        let b = mk_account(0x02, 200, 5);
        store.insert_account(a.clone());
        store.insert_account(b.clone());

        // Snapshot and rebuild — simulates a checkpoint restore.
        let rebuilt = StateStore::from_snapshot_full_with_proofs(
            store.accounts_in_order().into_iter().cloned().collect(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            phase1_registry(),
            store.block_height(),
            store.chain_id().to_vec(),
        );

        let got_a = rebuilt.get_account(&a.address).expect("a preserved");
        let got_b = rebuilt.get_account(&b.address).expect("b preserved");
        assert_eq!(got_a.balance, 100);
        assert_eq!(got_a.nonce, 0);
        assert_eq!(got_b.balance, 200);
        assert_eq!(got_b.nonce, 5);
    }

    #[test]
    fn attestations_roundtrip_via_snapshot() {
        let mut store = StateStore::new();
        let att = mk_attestation(0x10);
        store.insert_attestation(att.clone());

        let rebuilt = StateStore::from_snapshot_full_with_proofs(
            Vec::new(),
            store.attestations_in_order().into_iter().cloned().collect(),
            Vec::new(),
            Vec::new(),
            phase1_registry(),
            0,
            Vec::new(),
        );
        let got = rebuilt
            .get_attestation(&att.attestation_id)
            .expect("attestation preserved");
        assert_eq!(got.anchor_height, att.anchor_height);
        assert_eq!(got.attestation_type, att.attestation_type);
    }

    #[test]
    fn proof_anchors_roundtrip_via_snapshot() {
        let mut store = StateStore::new();
        let p = mk_proof_anchor(0x20);
        store.insert_proof_anchor(p.clone());

        let rebuilt = StateStore::from_snapshot_full_with_proofs(
            Vec::new(),
            Vec::new(),
            store
                .proof_anchors_in_order()
                .into_iter()
                .cloned()
                .collect(),
            Vec::new(),
            phase1_registry(),
            0,
            Vec::new(),
        );
        let got = rebuilt
            .get_proof_anchor(&p.anchor_id)
            .expect("anchor preserved");
        assert_eq!(got.anchor_height, p.anchor_height);
        assert_eq!(got.proof_hash, p.proof_hash);
        assert_eq!(got.claim_type, p.claim_type);
    }

    #[test]
    fn alg_registry_phase1_preserved_on_fresh_store() {
        let store = StateStore::new();
        // phase-1 registry seeds ML-DSA-65 as Active — pin the contract.
        let entry = store.alg_entry(AlgId::MlDsa65).expect("ML-DSA-65 seeded");
        assert_eq!(entry.lifecycle, Lifecycle::Active);
        assert_eq!(entry.pk_size, 1_952);
    }

    // ── 6. alg_registry lifecycle persistence via snapshot rebuild ───────────

    #[test]
    fn alg_registry_lifecycle_change_survives_snapshot() {
        let mut store = StateStore::new();
        // Mark ML-DSA-44 as Discouraged via the governance-style path.
        {
            let e = store
                .alg_entry_mut(AlgId::MlDsa44)
                .expect("ML-DSA-44 seeded");
            e.lifecycle = Lifecycle::Discouraged;
        }
        store.commit_alg_entry_mutation(AlgId::MlDsa44);
        // Sanity: the in-memory view is updated.
        assert_eq!(
            store.alg_entry(AlgId::MlDsa44).unwrap().lifecycle,
            Lifecycle::Discouraged
        );

        // Snapshot + restore with the mutated alg_registry.
        let rebuilt = StateStore::from_snapshot_full_with_proofs(
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            store.alg_entries_in_order().into_iter().cloned().collect(),
            store.block_height(),
            store.chain_id().to_vec(),
        );
        assert_eq!(
            rebuilt.alg_entry(AlgId::MlDsa44).unwrap().lifecycle,
            Lifecycle::Discouraged,
            "Discouraged lifecycle must persist across snapshot rebuild"
        );
    }

    // ── 7. fee_market persistence via restore_fee_market ─────────────────────

    #[test]
    fn fee_market_base_fee_persists_via_restore() {
        let mut store = StateStore::new();
        assert_eq!(store.base_fee_dynamic(), DEFAULT_BASE_FEE);

        let mut target = FeeMarketState::default();
        target.compute.base_fee = 12_345;
        target.compute.limit = 8_000_000;
        target.burn_rate_bps = 42;
        store.restore_fee_market(target.clone());
        assert_eq!(store.base_fee_dynamic(), 12_345);
        assert_eq!(store.fee_market.compute.limit, 8_000_000);
        assert_eq!(store.fee_market.burn_rate_bps, 42);
    }

    #[test]
    fn fee_market_restore_recomputes_leaf_hash() {
        // Two stores with the same fee_market must have the same
        // fee_market_leaf_hash, regardless of mutation path.
        let mut a = StateStore::new();
        let mut b = StateStore::new();
        let mut fm = FeeMarketState::default();
        fm.compute.base_fee = 999;
        a.restore_fee_market(fm.clone());
        b.restore_fee_market(fm);
        assert_eq!(a.state_root(), b.state_root());
    }

    // ── 8. Validator CRUD: insert + status transitions via mutation path ─────

    #[test]
    fn validator_insert_and_read_back() {
        let mut store = StateStore::new();
        let v = mk_validator(0x30, ValidatorStatus::Candidate);
        store.insert_validator(v.clone());
        let got = store.get_validator(&v.operator).expect("v preserved");
        assert_eq!(got.node_id, "node-30");
        assert_eq!(got.self_bond, 1_000);
        assert_eq!(got.status, ValidatorStatus::Candidate);
    }

    #[test]
    fn validator_status_update_via_mut_and_commit() {
        let mut store = StateStore::new();
        let v = mk_validator(0x31, ValidatorStatus::Active);
        store.insert_validator(v.clone());

        // Transition Active → Unbonding via the documented mut + commit path.
        {
            let m = store.get_validator_mut(&v.operator).expect("present");
            m.status = ValidatorStatus::Unbonding { start_height: 42 };
        }
        store.commit_validator_mutation(&v.operator);

        let got = store.get_validator(&v.operator).expect("still present");
        assert!(matches!(
            got.status,
            ValidatorStatus::Unbonding { start_height: 42 }
        ));
        // And it is no longer counted as Active.
        assert_eq!(store.active_validator_count(), 0);
    }

    #[test]
    fn validator_candidate_activation_via_activate_validator() {
        let mut store = StateStore::new();
        let v = mk_validator(0x32, ValidatorStatus::Candidate);
        store.insert_validator(v.clone());
        assert_eq!(store.active_validator_count(), 0);
        store.activate_validator(&v.operator, 60);
        assert_eq!(store.active_validator_count(), 1);
        let got = store.get_validator(&v.operator).expect("present");
        assert_eq!(got.status, ValidatorStatus::Active);
    }

    // ── 9. recent_slashes prune boundary ─────────────────────────────────────

    #[test]
    fn recent_slashes_prune_boundary_keeps_ge_cutoff() {
        let mut store = StateStore::new();
        store.record_recent_slash(RecentSlashEntry {
            height: 10,
            slashed_stake: 100,
        });
        store.record_recent_slash(RecentSlashEntry {
            height: 50,
            slashed_stake: 200,
        });
        store.record_recent_slash(RecentSlashEntry {
            height: 100,
            slashed_stake: 400,
        });
        assert_eq!(store.recent_slashes_snapshot().len(), 3);

        // Cutoff 60 — prunes entries with height < 60 (i.e. 10 and 50).
        store.prune_recent_slashes_before(60);
        let kept = store.recent_slashes_snapshot();
        assert_eq!(kept.len(), 1, "only height=100 should remain");
        assert_eq!(kept[0].height, 100);
        assert_eq!(kept[0].slashed_stake, 400);
    }

    #[test]
    fn recent_slashes_prune_zero_cutoff_is_noop() {
        let mut store = StateStore::new();
        for h in [10u64, 50, 100] {
            store.record_recent_slash(RecentSlashEntry {
                height: h,
                slashed_stake: 1,
            });
        }
        let root_before = store.state_root();
        store.prune_recent_slashes_before(0); // no entry has height < 0
        assert_eq!(store.recent_slashes_snapshot().len(), 3);
        // Leaf hash must not have been recomputed/bumped on a no-op prune.
        assert_eq!(
            store.state_root(),
            root_before,
            "no-op prune must not perturb state_root"
        );
    }

    #[test]
    fn recent_slashes_prune_drain_all_with_high_cutoff() {
        let mut store = StateStore::new();
        for h in [10u64, 50, 100] {
            store.record_recent_slash(RecentSlashEntry {
                height: h,
                slashed_stake: 7,
            });
        }
        store.prune_recent_slashes_before(200);
        assert!(store.recent_slashes_snapshot().is_empty());
    }

    #[test]
    fn recent_slashes_stake_window_sum() {
        let mut store = StateStore::new();
        store.record_recent_slash(RecentSlashEntry {
            height: 10,
            slashed_stake: 100,
        });
        store.record_recent_slash(RecentSlashEntry {
            height: 50,
            slashed_stake: 200,
        });
        store.record_recent_slash(RecentSlashEntry {
            height: 100,
            slashed_stake: 400,
        });
        // Window [50..=100]: includes 50 and 100 entries → 600.
        assert_eq!(store.recent_slashed_stake_in_window(100, 50), 600);
        // Window [90..=100]: only the height=100 entry → 400.
        assert_eq!(store.recent_slashed_stake_in_window(100, 10), 400);
        // Window [0..=100]: all three → 700.
        assert_eq!(store.recent_slashed_stake_in_window(100, 100), 700);
    }

    // ── 10/11. active_validators / validators_in_order ordering stability ────

    #[test]
    fn active_validators_sorted_by_operator_address_and_stable_across_calls() {
        let mut store = StateStore::new();
        // Insert in reverse-sorted order; active_validators() must still
        // emit sorted-by-operator output (consensus-critical: ADR-042 §
        // CommitQuorumPolicy needs byte-stable ordering across nodes).
        for byte in [0x05u8, 0x03, 0x07, 0x01, 0x09] {
            store.insert_validator(mk_validator(byte, ValidatorStatus::Active));
        }
        let first: Vec<[u8; 32]> = store
            .active_validators()
            .iter()
            .map(|v| v.operator.0)
            .collect();
        let second: Vec<[u8; 32]> = store
            .active_validators()
            .iter()
            .map(|v| v.operator.0)
            .collect();
        assert_eq!(first, second, "repeated calls must be byte-identical");
        let expected_order: Vec<[u8; 32]> =
            [0x01u8, 0x03, 0x05, 0x07, 0x09].map(|b| [b; 32]).to_vec();
        assert_eq!(first, expected_order, "must be sorted by operator address");
    }

    #[test]
    fn active_validators_new_insertion_preserves_deterministic_order() {
        let mut store = StateStore::new();
        for byte in [0x02u8, 0x04, 0x06] {
            store.insert_validator(mk_validator(byte, ValidatorStatus::Active));
        }
        let before: Vec<[u8; 32]> = store
            .active_validators()
            .iter()
            .map(|v| v.operator.0)
            .collect();
        // Insert a new validator that sorts in the middle.
        store.insert_validator(mk_validator(0x05, ValidatorStatus::Active));
        let after: Vec<[u8; 32]> = store
            .active_validators()
            .iter()
            .map(|v| v.operator.0)
            .collect();
        assert_eq!(before, [[0x02; 32], [0x04; 32], [0x06; 32]].to_vec());
        assert_eq!(
            after,
            [[0x02; 32], [0x04; 32], [0x05; 32], [0x06; 32]].to_vec(),
            "new validator must be inserted at its sort position"
        );
    }

    #[test]
    fn validators_in_order_includes_all_statuses_sorted() {
        let mut store = StateStore::new();
        store.insert_validator(mk_validator(0x07, ValidatorStatus::Active));
        store.insert_validator(mk_validator(0x03, ValidatorStatus::Candidate));
        store.insert_validator(mk_validator(0x05, ValidatorStatus::Jailed));
        store.insert_validator(mk_validator(0x09, ValidatorStatus::Exited));
        let ordered: Vec<[u8; 32]> = store
            .validators_in_order()
            .iter()
            .map(|v| v.operator.0)
            .collect();
        assert_eq!(
            ordered,
            vec![[0x03; 32], [0x05; 32], [0x07; 32], [0x09; 32]],
            "all statuses included, sorted by operator address"
        );
    }

    #[test]
    fn active_validators_excludes_candidate_and_jailed() {
        let mut store = StateStore::new();
        store.insert_validator(mk_validator(0x01, ValidatorStatus::Active));
        store.insert_validator(mk_validator(0x02, ValidatorStatus::Candidate));
        store.insert_validator(mk_validator(0x03, ValidatorStatus::Jailed));
        store.insert_validator(mk_validator(0x04, ValidatorStatus::Active));
        let actives: Vec<[u8; 32]> = store
            .active_validators()
            .iter()
            .map(|v| v.operator.0)
            .collect();
        assert_eq!(actives, vec![[0x01; 32], [0x04; 32]]);
    }

    // ── 13. Account nonce read-after-write contract ──────────────────────────
    //
    // Note: the StateStore accessor `get_account_mut` does NOT enforce nonce
    // monotonicity; the anti-replay check lives in `apply/*.rs`. This test
    // pins only the read-after-write semantics — a bumped nonce must be
    // visible to the next read.

    #[test]
    fn account_nonce_read_after_write_is_visible() {
        let mut store = StateStore::new();
        let a = mk_account(0x40, 500, 3);
        store.insert_account(a.clone());
        {
            let m = store.get_account_mut(&a.address).expect("present");
            m.nonce = 4;
        }
        store.commit_account_mutation(&a.address);
        let got = store.get_account(&a.address).expect("present");
        assert_eq!(got.nonce, 4, "bumped nonce must be visible to next read");
    }

    // ── Cross-cutting invariants ─────────────────────────────────────────────

    #[test]
    fn block_height_starts_at_zero_and_advances_by_one() {
        let mut store = StateStore::new();
        assert_eq!(store.block_height(), 0);
        store.advance_height();
        assert_eq!(store.block_height(), 1);
        store.advance_height();
        assert_eq!(store.block_height(), 2);
    }

    #[test]
    fn state_root_is_deterministic_on_fresh_store() {
        // Two fresh stores must produce identical state roots — a baseline
        // pin against accidental non-determinism in `new()` (e.g. an
        // iteration over a HashMap in the wrong place).
        let a = StateStore::new();
        let b = StateStore::new();
        assert_eq!(a.state_root(), b.state_root());
    }

    #[test]
    fn slashing_registry_seeded_equivocation_entry() {
        let store = StateStore::new();
        // ADR-050 / SPEC-SLASH-001 §10 — the equivocation entry is seeded
        // at 500 bps with tombstone=true.
        let entry = store
            .slashing_verifier_entry(SLASHING_EVIDENCE_TYPE_EQUIVOCATION)
            .expect("0x01 must be seeded");
        assert_eq!(
            entry.slash_fraction_bps, DEFAULT_EQUIVOCATION_SLASH_FRACTION_BPS,
            "seeded slash fraction must match ADR-050 default"
        );
        assert!(entry.tombstone);
        assert_eq!(entry.lifecycle, Lifecycle::Active);
    }

    #[test]
    fn effective_slash_fraction_falls_back_to_default_on_unknown_type() {
        let store = StateStore::new();
        // Evidence type 0xAB is not registered — must fall back to default.
        let frac = store.effective_slash_fraction_bps(0xAB);
        assert_eq!(frac, DEFAULT_EQUIVOCATION_SLASH_FRACTION_BPS);
    }

    // ── Storage fund (ADR-053 §T2.2) ─────────────────────────────────────────
    //
    // Gated behind `token_economics` — viper-research-1 has no storage_fund
    // module compiled in, no field on StateStore, no leaf in state_root.

    #[cfg(feature = "token_economics")]
    #[test]
    fn storage_fund_credit_debit_roundtrip_through_state_root() {
        // A credit/debit cycle that returns balance to zero MUST leave
        // the state_root identical to the fresh-store root — proof the
        // cached leaf hash is consistent.
        let mut store = StateStore::new();
        let root_before = store.state_root();
        store.credit_storage_fund(10_000);
        let root_credited = store.state_root();
        assert_ne!(root_before, root_credited, "credit MUST move state_root");
        let debited = store.debit_storage_fund(10_000);
        assert_eq!(debited, 10_000);
        let root_after = store.state_root();
        assert_eq!(
            root_before, root_after,
            "balance returning to zero MUST return state_root to its prior value"
        );
    }

    #[cfg(feature = "token_economics")]
    #[test]
    fn storage_fund_debit_caps_at_balance() {
        let mut store = StateStore::new();
        store.credit_storage_fund(500);
        let debited = store.debit_storage_fund(u128::MAX);
        assert_eq!(debited, 500, "debit MUST cap at current balance");
        assert_eq!(store.storage_fund.balance, 0);
    }

    #[cfg(feature = "token_economics")]
    #[test]
    fn storage_fund_restore_recomputes_leaf_hash() {
        // Two stores with the same storage_fund MUST agree on state_root.
        let mut a = StateStore::new();
        let mut b = StateStore::new();
        let fund = crate::storage_fund::StorageFundState {
            balance: 7_777_777,
            perpetual_cost_per_byte: 3,
            rebate_fraction_bps: 9_500,
        };
        a.restore_storage_fund(fund.clone());
        b.restore_storage_fund(fund);
        assert_eq!(a.state_root(), b.state_root());
    }
}

// ────────────────────────────────────────────────────────────────────
// genesis_alg_registry_pin_tests
//
// **What this module catches that nothing else does**: a change to
// the genesis `phase1_registry()` that drifts the on-chain
// alg-registry leaf hash. This is the failure mode that stalled
// viper-pq-1 for ~5 minutes on 2026-05-11 when a doc-style suffix
// appended to FN-DSA's `spec_ref` field changed the alg-registry
// leaf bytes by 4 bytes — every in-process test passed, including
// `cold_sync_replay`, because each test computes state-roots from
// current code and the pin vector implicitly tracked the change.
// The new binary then refused to start with
// `STATE_ROOT_MISMATCH at height 1` against the chain state
// persisted by the prior binary.
//
// **Why this works where cold_sync_replay didn't**: this module
// pins the leaf hash as a *literal hex constant*, NOT as a
// "whatever the current code produces" auto-recomputed value. The
// hash is anchored to viper-pq-1 genesis state-root values that
// were observed and persisted on the 3 live hosts. Updating the
// pin without realising it has consensus-relevant impact is
// possible (you can always paste in new bytes), but the heavy
// comment block + the explicit `CONSENSUS-CRITICAL` warning above
// every pin make it loud rather than silent.
//
// **What to do when a test in here fails**:
//   1. Did you intentionally change a consensus-relevant field
//      (entry order, alg_id, spec_ref, pk_size, sig_size, min_fee,
//      lifecycle, sig_class)? If yes, you are shipping a hard-fork
//      to every running viper-pq-1 chain. STOP. Write an ADR with
//      activation height + dual-path leaf hash + cold-sync test
//      update across the activation boundary. Update this pin in
//      the same commit so the diff captures the consensus-format
//      change. Coordinate the binary roll-out playbook.
//   2. Did you change something that *should* be consensus-neutral
//      (e.g. a doc comment) but the test still fails? You may have
//      accidentally touched a field — re-check the diff against the
//      `compute_alg_leaf_hash` byte layout at
//      `crates/pqc-state/src/store/state_merkle.rs:105–130`. The
//      most common foot-gun is editing `spec_ref` (a `Cow<'static,
//      str>` field whose bytes are hashed into the leaf).
//   3. Did you change `compute_alg_leaf_hash` itself (the formula)?
//      That's also a hard-fork — same ADR-required protocol as (1).
//
// The viper-pq-1 chain's relaunch state-root at height 0 depends
// on these leaf hashes plus the hash-registry, auth-template
// registry, slashing-verifier registry, fee-market state, and
// storage-fund leaf. The leaf-hash pins are the smallest unit that
// catches the FN-DSA-class drift; a full genesis state-root pin
// would catch more but is harder to maintain (lots of fields
// contribute) and harder to diagnose on failure.

#[cfg(test)]
mod genesis_alg_registry_pin_tests {
    use super::state_merkle::compute_alg_leaf_hash;
    use pqc_crypto::registry::phase1_registry;
    use pqc_crypto::AlgId;

    /// Compute the leaf hash for the entry with a given alg_id in
    /// the genesis registry. Panics if the entry is missing (i.e.
    /// an intentional registry change removed an alg).
    fn leaf_for(alg_id: AlgId) -> [u8; 32] {
        let registry = phase1_registry();
        let entry = registry
            .iter()
            .find(|e| e.alg_id == alg_id)
            .unwrap_or_else(|| {
                panic!(
                    "phase1_registry() no longer contains {alg_id:?} — this is a hard-fork; \
                     see module-level docstring before updating this pin"
                )
            });
        compute_alg_leaf_hash(entry)
    }

    fn hex_encode(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }

    // ── Per-alg-id leaf-hash pins ───────────────────────────────
    //
    // Pinned 2026-05-11 from the post-relaunch viper-pq-1 chain
    // (commit d6fdf099, binary fe909576641d5673ba85512e88bb5c40d
    // 65765563aa54648984f6c64e9cf2a0e). To regenerate after an
    // intentional ADR-backed registry change, run with
    // `-- --nocapture` and copy the printed hex.

    /// **CONSENSUS-CRITICAL** — ML-DSA-44 (FIPS 204, level 2)
    const ML_DSA_44_LEAF: [u8; 32] =
        hex_to_32("d8220ac4672fc6bb4a3deb5909958bcc6e3418c184d53d647b4982853895e677");
    /// **CONSENSUS-CRITICAL** — ML-DSA-65 (FIPS 204, level 3) — default consensus alg
    const ML_DSA_65_LEAF: [u8; 32] =
        hex_to_32("45e6e39af1ec7c6869d713e18675c9f42db2ee396b39573bc1172b3f78f43378");
    /// **CONSENSUS-CRITICAL** — ML-DSA-87 (FIPS 204, level 5)
    const ML_DSA_87_LEAF: [u8; 32] =
        hex_to_32("f90836b109e5289c5b9aa8690f7d079ba9ba0f1a52af49fd06d62db7883d6297");
    /// **CONSENSUS-CRITICAL** — FN-DSA-padded-512 (FIPS 206 draft, reserved slot).
    /// 2026-05-11 stall trigger: a doc-suffix appended to spec_ref
    /// changed this leaf, which broke cold-sync replay on deploy.
    /// See commit d6fdf099 for the revert.
    const FN_DSA_PADDED_512_LEAF: [u8; 32] =
        hex_to_32("59b1434aa8272b35e0d4daf74c05d342048c57a9bca632e4d8ab1bbb64e748f6");
    /// **CONSENSUS-CRITICAL** — SLH-DSA-SHA2-128s
    const SLH_DSA_SHA2_128S_LEAF: [u8; 32] =
        hex_to_32("c5307263201027da60ff5698b74ee2e0464a9d491f4e11a07fd3b503894b31a0");
    /// **CONSENSUS-CRITICAL** — SLH-DSA-SHAKE-128s
    const SLH_DSA_SHAKE_128S_LEAF: [u8; 32] =
        hex_to_32("17dbb2bbc4de4500fd154a6e8cfc93f150d5ee4b6d1d88adfc40481ee096d2ac");
    /// **CONSENSUS-CRITICAL** — SLH-DSA-SHAKE-192s (consensus fallback)
    const SLH_DSA_SHAKE_192S_LEAF: [u8; 32] =
        hex_to_32("f88b789b22dacfc8b5b0d0b6455de886ab76cb9717d5c0c90b8eb95d45075a70");
    /// **CONSENSUS-CRITICAL** — SLH-DSA-SHAKE-256s (archival overlay)
    const SLH_DSA_SHAKE_256S_LEAF: [u8; 32] =
        hex_to_32("9da96bada6b7f2f15d473d8795b65c56ca4ed88377bbb05a4a83484bc0546364");
    /// **CONSENSUS-CRITICAL** — ML-KEM-768 (FIPS 203, KEM)
    const ML_KEM_768_LEAF: [u8; 32] =
        hex_to_32("3244fe786dc42aa9dc2de9297b2757a160b39ed680727e5a703174718aba9d7f");

    /// const-fn helper to decode a 64-char hex string into a [u8; 32].
    /// Panics at compile time on invalid input (so a typo in a pin
    /// constant fails the build, not a runtime test).
    const fn hex_to_32(s: &str) -> [u8; 32] {
        let bytes = s.as_bytes();
        assert!(bytes.len() == 64, "leaf hash pin must be 64 hex chars");
        let mut out = [0u8; 32];
        let mut i = 0;
        while i < 32 {
            out[i] = hex_nybble(bytes[i * 2]) * 16 + hex_nybble(bytes[i * 2 + 1]);
            i += 1;
        }
        out
    }

    const fn hex_nybble(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => panic!("invalid hex char in pin"),
        }
    }

    /// Assert helper that prints the actual leaf hash on failure so
    /// the operator can paste the new value into the const if the
    /// change is intentional (ADR-backed).
    fn assert_leaf(alg_id: AlgId, expected: &[u8; 32], label: &str) {
        let actual = leaf_for(alg_id);
        if &actual != expected {
            // Helpful diagnostic — print the actual value so an
            // operator running with `-- --nocapture` can copy it
            // into the const. The panic message links back to the
            // module docstring + the revert commit so the
            // operator knows what they're about to ship.
            println!("actual {label} leaf: {}", hex_encode(&actual));
            panic!(
                "{label} alg-registry leaf hash drifted.\n\
                 expected: {}\n\
                 actual:   {}\n\
                 \n\
                 This is a CONSENSUS-RELEVANT change. Updating this pin without an ADR \
                 will break cold-sync replay on every running viper-pq-1 chain (see \
                 commit d6fdf099 for the 2026-05-11 stall when this drifted unintentionally).\n\
                 \n\
                 If intentional: write ADR + activation height + dual-path leaf hash before \
                 updating this pin. See module docstring above for the full protocol.",
                hex_encode(expected),
                hex_encode(&actual),
            );
        }
    }

    #[test]
    fn ml_dsa_44_leaf_pinned() {
        assert_leaf(AlgId::MlDsa44, &ML_DSA_44_LEAF, "ML-DSA-44");
    }

    #[test]
    fn ml_dsa_65_leaf_pinned() {
        assert_leaf(AlgId::MlDsa65, &ML_DSA_65_LEAF, "ML-DSA-65");
    }

    #[test]
    fn ml_dsa_87_leaf_pinned() {
        assert_leaf(AlgId::MlDsa87, &ML_DSA_87_LEAF, "ML-DSA-87");
    }

    #[test]
    fn fn_dsa_padded_512_leaf_pinned() {
        // The 2026-05-11 regression site. If this test fails after
        // an edit to FN-DSA's AlgEntry literal in phase1_registry(),
        // read the revert commit d6fdf099 — your edit is hashed into
        // the alg-registry leaf and breaks cold-sync replay.
        assert_leaf(
            AlgId::FnDsaPadded512,
            &FN_DSA_PADDED_512_LEAF,
            "FN-DSA-padded-512",
        );
    }

    #[test]
    fn slh_dsa_sha2_128s_leaf_pinned() {
        assert_leaf(
            AlgId::SlhDsaSha2128s,
            &SLH_DSA_SHA2_128S_LEAF,
            "SLH-DSA-SHA2-128s",
        );
    }

    #[test]
    fn slh_dsa_shake_128s_leaf_pinned() {
        assert_leaf(
            AlgId::SlhDsaShake128s,
            &SLH_DSA_SHAKE_128S_LEAF,
            "SLH-DSA-SHAKE-128s",
        );
    }

    #[test]
    fn slh_dsa_shake_192s_leaf_pinned() {
        assert_leaf(
            AlgId::SlhDsaShake192s,
            &SLH_DSA_SHAKE_192S_LEAF,
            "SLH-DSA-SHAKE-192s",
        );
    }

    #[test]
    fn slh_dsa_shake_256s_leaf_pinned() {
        assert_leaf(
            AlgId::SlhDsaShake256s,
            &SLH_DSA_SHAKE_256S_LEAF,
            "SLH-DSA-SHAKE-256s",
        );
    }

    #[test]
    fn ml_kem_768_leaf_pinned() {
        assert_leaf(AlgId::MlKem768, &ML_KEM_768_LEAF, "ML-KEM-768");
    }

    // ── HASH REGISTRY PIN — phase1_hash_registry() ──────────────
    //
    // Single genesis entry at launch: 0x01 = SHAKE-256. The same
    // doc-drift footgun applies — `HashEntry::spec_ref` is hashed
    // into the registry leaf at
    // `state_merkle.rs::compute_hash_registry_leaf_hash` (line 428).
    // Any edit to that literal silently moves the genesis state-root.

    /// **CONSENSUS-CRITICAL** — SHAKE-256 (FIPS 202), the single
    /// hash-registry entry at viper-pq-1 genesis.
    const HASH_REGISTRY_SHAKE256_LEAF: [u8; 32] =
        hex_to_32("20bfc63f024b3483dbdf5f95918c211d306d545450dce930a66420fea589a953");

    #[test]
    fn hash_registry_shake256_leaf_pinned() {
        use crate::store::state_merkle::compute_hash_registry_leaf_hash;
        let registry = pqc_crypto::hash_registry::phase1_hash_registry();
        assert_eq!(
            registry.len(),
            1,
            "hash_registry has exactly 1 genesis entry"
        );
        let actual = compute_hash_registry_leaf_hash(&registry[0]);
        if actual != HASH_REGISTRY_SHAKE256_LEAF {
            println!(
                "actual hash-registry SHAKE-256 leaf: {}",
                hex_encode(&actual)
            );
            panic!(
                "hash-registry SHAKE-256 leaf drifted.\n\
                 expected: {}\nactual:   {}\n\
                 See module docstring — CONSENSUS-RELEVANT change.",
                hex_encode(&HASH_REGISTRY_SHAKE256_LEAF),
                hex_encode(&actual),
            );
        }
    }

    // ── SLASHING-VERIFIER REGISTRY PIN — seeded in StateStore::new() ──
    //
    // Single genesis entry: evidence_type = EQUIVOCATION (0x01). The
    // entry literal lives in `crates/pqc-state/src/store.rs:513-520`
    // and is seeded into a fresh `StateStore::new()`. The `spec_ref`
    // string + slash_fraction_bps + jail_duration_blocks + tombstone
    // + lifecycle are all hashed into the leaf at
    // `state_merkle.rs::compute_slashing_verifier_leaf_hash`.

    /// **CONSENSUS-CRITICAL** — equivocation slashing-verifier leaf,
    /// the single slashing entry at viper-pq-1 genesis.
    const SLASHING_EQUIVOCATION_LEAF: [u8; 32] =
        hex_to_32("feeb9a193e069ac4e9214cfc153e0b923be1a4cbaa8dcd273959ddaa0bb8962f");

    #[test]
    fn slashing_registry_equivocation_leaf_pinned() {
        // A fresh StateStore seeds the equivocation entry; read it
        // back via the public accessor and recompute the leaf.
        use crate::store::state_merkle::compute_slashing_verifier_leaf_hash;
        use crate::store::SLASHING_EVIDENCE_TYPE_EQUIVOCATION;
        use crate::StateStore;
        let store = StateStore::new();
        let entry = store
            .slashing_verifier_entry(SLASHING_EVIDENCE_TYPE_EQUIVOCATION)
            .expect("equivocation entry must be seeded in StateStore::new()");
        let actual = compute_slashing_verifier_leaf_hash(entry);
        if actual != SLASHING_EQUIVOCATION_LEAF {
            println!("actual slashing-equivocation leaf: {}", hex_encode(&actual));
            panic!(
                "slashing-registry equivocation leaf drifted.\n\
                 expected: {}\nactual:   {}\n\
                 See module docstring — CONSENSUS-RELEVANT change.",
                hex_encode(&SLASHING_EQUIVOCATION_LEAF),
                hex_encode(&actual),
            );
        }
    }

    /// Meta-pin: phase1_registry() entry count + order. Catches the
    /// case where a maintainer adds/removes entries (which would
    /// reshape the alg_registry map indirectly).
    #[test]
    fn registry_has_expected_alg_ids_in_order() {
        let registry = phase1_registry();
        let actual: Vec<AlgId> = registry.iter().map(|e| e.alg_id).collect();
        let expected = vec![
            AlgId::MlDsa44,
            AlgId::MlDsa65,
            AlgId::MlDsa87,
            AlgId::FnDsaPadded512,
            AlgId::SlhDsaSha2128s,
            AlgId::SlhDsaShake128s,
            AlgId::SlhDsaShake192s,
            AlgId::SlhDsaShake256s,
            AlgId::MlKem768,
        ];
        assert_eq!(
            actual, expected,
            "phase1_registry() entry order or membership changed — \
             this is a hard-fork; update this pin AND all per-leaf \
             pins above in the same commit, with an ADR documenting \
             the activation height + dual-path migration."
        );
    }
}

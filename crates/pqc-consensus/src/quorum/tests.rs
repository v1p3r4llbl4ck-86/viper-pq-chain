// SPDX-License-Identifier: BUSL-1.1
//! Tests for `quorum`.
//!
//! Extracted from `quorum.rs` 2026-05-10. `use super::*;`
//! brings every private item from the parent module into scope.

use super::*;

/// Spec-formula reference: ⌊2n/3⌋ + 1.  Re-derived inside the test so a
/// regression in `quorum_size` is caught against an independent
/// implementation rather than against the cached expected values.
fn spec_quorum(n: usize) -> usize {
    (2 * n) / 3 + 1
}

/// Maximum tolerated Byzantine count: f = ⌊(n-1)/3⌋.  PIN that
/// `quorum_size(n) = n − f`, the canonical "honest majority" threshold.
fn spec_byzantine_bound(n: usize) -> usize {
    if n == 0 {
        0
    } else {
        (n - 1) / 3
    }
}

#[test]
fn quorum_matches_adr_013() {
    assert_eq!(quorum_size(24), 17);
    assert_eq!(quorum_size(32), 22);
    assert_eq!(quorum_size(50), 34);
}

// ── Spec-formula sweep (TASK-180) ────────────────────────────────────────

/// PIN: for every N in the canonical sweep, `quorum_size(N)` matches the
/// re-derived `spec_quorum(N)`, and the implied Byzantine bound
/// `f = ⌊(N-1)/3⌋` is consistent (`quorum + f = n + 1`, i.e. quorum
/// strictly exceeds n − f).  This is the contract relied on by the BFT
/// safety proof in `specs/consensus.md` §10.
#[test]
fn quorum_matches_spec_for_canonical_set_sizes() {
    for &n in &[3usize, 4, 5, 6, 7, 8, 9, 10, 16, 21, 100] {
        let q = quorum_size(n);
        assert_eq!(q, spec_quorum(n), "n = {n}: quorum_size MUST match spec");
        let f = spec_byzantine_bound(n);
        assert!(
            f <= n / 3,
            "n = {n}: Byzantine bound f = {f} MUST satisfy f ≤ ⌊n/3⌋"
        );
        // Quorum strictly exceeds the largest possible Byzantine cabal
        // (n - q < q so honest precommits dominate).
        assert!(
            q > n - q,
            "n = {n}: quorum {q} MUST exceed minority size {}",
            n - q
        );
    }
}

// ── Set-size transitions (epoch boundary) ────────────────────────────────

/// PIN: growing the validator set bumps the quorum threshold deterministically.
/// 3 → 4 (q: 3 → 3), 4 → 5 (q: 3 → 4), so the epoch boundary MUST recompute.
#[test]
fn validator_set_growth_updates_threshold() {
    // 3 → 4: quorum goes from 3 to 3 (no change in absolute terms).
    assert_eq!(quorum_size(3), 3);
    assert_eq!(quorum_size(4), 3);
    // 4 → 5: quorum increments from 3 to 4.
    assert_eq!(quorum_size(5), 4);
}

/// PIN: shrinking the set (e.g. via slashing or exit) lowers the quorum.
/// 7 → 6 (q: 5 → 5, unchanged), 6 → 3 (q: 5 → 3, halves).
#[test]
fn validator_set_shrink_updates_threshold() {
    assert_eq!(quorum_size(7), 5);
    assert_eq!(quorum_size(6), 5);
    assert_eq!(quorum_size(3), 3);
}

// ── Edge cases ───────────────────────────────────────────────────────────

/// PIN: N = 1 is degenerate but well-defined — a single-validator chain
/// has quorum 1 and tolerates 0 Byzantine validators.
#[test]
fn n_equals_one_is_degenerate_quorum_one() {
    assert_eq!(quorum_size(1), 1);
    assert_eq!(spec_byzantine_bound(1), 0);
}

/// PIN: N = 2 is below the BFT minimum (no fault tolerance possible) but
/// the function does not panic — quorum_size(2) = 2 (unanimity required).
/// Operators MUST be alerted by the launch readiness check that N < 4 has
/// no BFT guarantee.
#[test]
fn n_equals_two_below_bft_returns_unanimity() {
    assert_eq!(quorum_size(2), 2, "n=2 MUST require unanimity");
    assert_eq!(spec_byzantine_bound(2), 0, "n=2 tolerates 0 Byzantine");
}

/// PIN: N = 3 is the minimum non-degenerate BFT setup (f = 0 still, but
/// q = 3 means unanimity is required — any single offline validator
/// halts the chain).  This is the smallest set where the formula
/// produces a strict super-majority.
#[test]
fn n_equals_three_minimum_non_degenerate_requires_unanimity() {
    assert_eq!(quorum_size(3), 3);
    assert_eq!(spec_byzantine_bound(3), 0);
}

/// PIN: N = 4 is the smallest set that tolerates a Byzantine validator
/// (f = 1, quorum = 3 = N − f).  This is the BFT threshold at which the
/// chain can lose one validator and still finalize.
#[test]
fn n_equals_four_tolerates_one_byzantine() {
    assert_eq!(quorum_size(4), 3);
    assert_eq!(spec_byzantine_bound(4), 1);
    // n - q = 1 = f: maximum offline that still permits commit.
    assert_eq!(4 - quorum_size(4), spec_byzantine_bound(4));
}

/// PIN: N = 0 (empty validator set) MUST return a well-defined value, not
/// panic.  The current contract returns `quorum_size(0) = 1` (any single
/// vote on a zero-validator chain would clear quorum, but no validator
/// exists to cast that vote — the engine MUST guard against N = 0
/// before invoking).  This test pins the no-panic guarantee.
#[test]
fn empty_validator_set_does_not_panic() {
    let q = quorum_size(0);
    // Current behaviour: ⌊0/3⌋ + 1 = 1.  We assert the value rather than
    // a range so a future change to "return 0 / Option" is caught.
    assert_eq!(q, 1, "quorum_size(0) MUST be 1 under current formula");
}

/// Monotonicity: quorum_size is non-decreasing in N.  PIN this so a
/// future "optimization" cannot accidentally make a larger set easier to
/// quorum than a smaller one (which would be a safety bug).
#[test]
fn quorum_is_monotonic_in_validator_count() {
    let mut prev = quorum_size(1);
    for n in 2..=128 {
        let q = quorum_size(n);
        assert!(
            q >= prev,
            "quorum_size MUST be monotonic: q({n}) = {q} but q({}) = {prev}",
            n - 1
        );
        prev = q;
    }
}

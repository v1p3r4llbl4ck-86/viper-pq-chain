// SPDX-License-Identifier: BUSL-1.1
//! Tests for `round`.
//!
//! Extracted from `round.rs` 2026-05-10. `use super::*;`
//! brings every private item from the parent module into scope.

use super::*;

// ── Preimage tests ────────────────────────────────────────────────────────

fn test_fork_digest() -> ForkDigest {
    ForkDigest::viper_research_1()
}

#[test]
fn vote_preimage_is_deterministic() {
    let fd = test_fork_digest();
    let hash = [0xABu8; 32];
    let a = vote_preimage(&fd, 1, 0, VoteStep::Prevote, &hash);
    let b = vote_preimage(&fd, 1, 0, VoteStep::Prevote, &hash);
    assert_eq!(a, b);
}

#[test]
fn vote_preimage_differs_by_step() {
    let fd = test_fork_digest();
    let hash = [0x11u8; 32];
    let prevote = vote_preimage(&fd, 1, 0, VoteStep::Prevote, &hash);
    let precommit = vote_preimage(&fd, 1, 0, VoteStep::Precommit, &hash);
    assert_ne!(
        prevote, precommit,
        "prevote and precommit preimages must differ"
    );
}

#[test]
fn vote_preimage_differs_from_commit_preimage() {
    // Verify that the VIPER-VOTE-V1 preimage is distinct from the
    // PQC-COMMIT-V1 preimage used in commit.rs. Both are BIP340
    // double-tagged hashes under ADR-053 §T2.4, so the distinction
    // comes entirely from the domain tag (CVE-2012-2459 defense).
    let fd = test_fork_digest();
    let hash = [0x42u8; 32];
    let vote_pi = vote_preimage(&fd, 5, 0, VoteStep::Precommit, &hash);

    // Reconstruct the legacy commit preimage inline with the same
    // tagged-hash pattern `commit_preimage` uses.
    let mut legacy_body = Vec::new();
    legacy_body.extend_from_slice(fd.as_bytes());
    legacy_body.extend_from_slice(&5u64.to_be_bytes());
    legacy_body.extend_from_slice(&hash);
    let legacy_pi = pqc_crypto::tagged_hash(b"PQC-COMMIT-V1", &legacy_body);

    assert_ne!(
        vote_pi, legacy_pi,
        "new vote preimage must differ from legacy commit preimage"
    );
}

#[test]
fn proposal_preimage_differs_from_vote_preimage() {
    let fd = test_fork_digest();
    let hash = [0x77u8; 32];
    let prop = proposal_preimage(&fd, 2, 0, -1, &hash);
    let vote = vote_preimage(&fd, 2, 0, VoteStep::Prevote, &hash);
    assert_ne!(prop, vote);
}

#[test]
fn vote_preimage_differs_by_fork_digest() {
    // ADR-053 §T1.2: swapping the fork digest must change the preimage —
    // this is the cross-chain-replay invariant.
    let hash = [0x55u8; 32];
    let fd_a = ForkDigest::compute(1, &[1u8; 32]);
    let fd_b = ForkDigest::compute(1, &[2u8; 32]);
    let pi_a = vote_preimage(&fd_a, 3, 1, VoteStep::Precommit, &hash);
    let pi_b = vote_preimage(&fd_b, 3, 1, VoteStep::Precommit, &hash);
    assert_ne!(pi_a, pi_b);
}

// ── Proposer selection tests ──────────────────────────────────────────────

#[test]
fn proposer_rotates_round_robin_by_height() {
    let v0 = [0x00u8; 32];
    let v1 = [0x01u8; 32];
    let v2 = [0x02u8; 32];
    let validators = vec![v0, v1, v2]; // already sorted
                                       // sorted order: v0=0x00, v1=0x01, v2=0x02

    // height=0, round=0 → idx = (0+0)%3 = 0 → v0
    assert_eq!(select_proposer(&validators, 0, 0, None), Some(v0));
    // height=1, round=0 → idx = 1 → v1
    assert_eq!(select_proposer(&validators, 1, 0, None), Some(v1));
    // height=2, round=0 → idx = 2 → v2
    assert_eq!(select_proposer(&validators, 2, 0, None), Some(v2));
    // height=3, round=0 → idx = 0 → v0 (wraps)
    assert_eq!(select_proposer(&validators, 3, 0, None), Some(v0));
}

#[test]
fn proposer_advances_on_round_increment() {
    let v0 = [0x00u8; 32];
    let v1 = [0x01u8; 32];
    let validators = vec![v0, v1];

    // height=0, round=0 → v0
    assert_eq!(select_proposer(&validators, 0, 0, None), Some(v0));
    // height=0, round=1 → v1 (view change)
    assert_eq!(select_proposer(&validators, 0, 1, None), Some(v1));
}

#[test]
fn proposer_selection_is_independent_of_input_order() {
    let v0 = [0x00u8; 32];
    let v1 = [0x01u8; 32];
    let v2 = [0x02u8; 32];

    let order_a = vec![v0, v1, v2];
    let order_b = vec![v2, v0, v1];
    let order_c = vec![v1, v2, v0];

    for height in 0..6u64 {
        let a = select_proposer(&order_a, height, 0, None);
        let b = select_proposer(&order_b, height, 0, None);
        let c = select_proposer(&order_c, height, 0, None);
        assert_eq!(
            a, b,
            "proposer must be same regardless of input order (height={height})"
        );
        assert_eq!(
            b, c,
            "proposer must be same regardless of input order (height={height})"
        );
    }
}

// ── VoteStore tests ───────────────────────────────────────────────────────

fn make_vote(
    validator: [u8; 32],
    height: u64,
    round: u32,
    step: VoteStep,
    hash: [u8; 32],
) -> ConsensusVote {
    ConsensusVote {
        height,
        round,
        step,
        block_hash: hash,
        validator_address: validator,
        signature: Vec::new(),
    }
}

#[test]
fn vote_store_records_votes_and_counts() {
    let mut store = VoteStore::new();
    let v0 = [0x00u8; 32];
    let v1 = [0x01u8; 32];
    let hash = [0xBBu8; 32];

    let e0 = store.record(make_vote(v0, 1, 0, VoteStep::Prevote, hash));
    let e1 = store.record(make_vote(v1, 1, 0, VoteStep::Prevote, hash));
    assert!(e0.is_none());
    assert!(e1.is_none());
    assert_eq!(store.prevote_count_for(1, 0, &hash), 2);
}

#[test]
fn vote_store_detects_equivocation_on_conflicting_hash() {
    let mut store = VoteStore::new();
    let v0 = [0x00u8; 32];
    let hash_a = [0xAAu8; 32];
    let hash_b = [0xBBu8; 32];

    let e0 = store.record(make_vote(v0, 1, 0, VoteStep::Prevote, hash_a));
    assert!(e0.is_none(), "first vote should not trigger equivocation");

    let e1 = store.record(make_vote(v0, 1, 0, VoteStep::Prevote, hash_b));
    assert!(e1.is_some(), "conflicting vote must trigger equivocation");
    let evidence = e1.unwrap();
    assert_eq!(evidence.validator_address, v0);
    assert_eq!(evidence.height, 1);
    assert_eq!(evidence.step, VoteStep::Prevote);
    assert_eq!(store.equivocation_count(), 1);
}

#[test]
fn vote_store_does_not_flag_two_nil_votes_as_equivocation() {
    let mut store = VoteStore::new();
    let v0 = [0x00u8; 32];

    let e0 = store.record(make_vote(v0, 1, 0, VoteStep::Prevote, NIL_HASH));
    let e1 = store.record(make_vote(v0, 1, 0, VoteStep::Prevote, NIL_HASH));
    assert!(e0.is_none());
    assert!(
        e1.is_none(),
        "two nil votes for same (v, h, r, step) are not equivocation"
    );
    assert_eq!(store.equivocation_count(), 0);
}

#[test]
fn vote_store_polka_requires_quorum_count() {
    let mut store = VoteStore::new();
    let v0 = [0x00u8; 32];
    let v1 = [0x01u8; 32];
    let v2 = [0x02u8; 32];
    let hash = [0xCCu8; 32];

    // n=3 → quorum = floor(2×3/3)+1 = 3
    store.record(make_vote(v0, 1, 0, VoteStep::Prevote, hash));
    assert!(!store.has_polka(1, 0, &hash, 3), "1 vote < quorum=3");
    store.record(make_vote(v1, 1, 0, VoteStep::Prevote, hash));
    assert!(!store.has_polka(1, 0, &hash, 3), "2 votes < quorum=3");
    store.record(make_vote(v2, 1, 0, VoteStep::Prevote, hash));
    assert!(store.has_polka(1, 0, &hash, 3), "3 votes == quorum=3");
}

#[test]
fn vote_store_commit_quorum() {
    let mut store = VoteStore::new();
    let hash = [0xDDu8; 32];
    for i in 0u8..3 {
        let addr = [i; 32];
        store.record(make_vote(addr, 2, 0, VoteStep::Precommit, hash));
    }
    assert!(store.has_commit_quorum(2, 0, &hash, 3));
    assert!(!store.has_commit_quorum(2, 0, &hash, 4));
}

// ── ConsensusRound state machine tests ───────────────────────────────────

fn validator(id: u8) -> [u8; 32] {
    [id; 32]
}

/// Build n=3 consensus round.
fn round_n3(height: u64) -> ConsensusRound {
    ConsensusRound::new(height, 3)
}

#[test]
fn round_proposal_triggers_prevote() {
    let mut r = round_n3(1);
    let hash = [0x01u8; 32];
    let actions = r.on_proposal_received(hash);
    assert_eq!(
        actions,
        vec![RoundAction::BroadcastPrevote { block_hash: hash }]
    );
    assert_eq!(r.phase, RoundPhase::Prevote);
}

#[test]
fn round_propose_timeout_triggers_nil_prevote() {
    let mut r = round_n3(1);
    let actions = r.on_propose_timeout();
    assert_eq!(
        actions,
        vec![RoundAction::BroadcastPrevote {
            block_hash: NIL_HASH
        }]
    );
}

#[test]
fn round_polka_triggers_precommit() {
    let mut r = round_n3(1);
    let hash = [0x42u8; 32];
    r.on_proposal_received(hash);

    // Feed 3 prevotes (quorum=3 for n=3)
    let _ = r.on_prevote(make_vote(validator(0), 1, 0, VoteStep::Prevote, hash));
    let _ = r.on_prevote(make_vote(validator(1), 1, 0, VoteStep::Prevote, hash));
    let actions = r.on_prevote(make_vote(validator(2), 1, 0, VoteStep::Prevote, hash));

    assert_eq!(
        actions,
        vec![RoundAction::BroadcastPrecommit { block_hash: hash }]
    );
    assert_eq!(r.phase, RoundPhase::Precommit);
    assert_eq!(r.locked_block, Some(hash));
}

#[test]
fn round_commit_quorum_decides() {
    let mut r = round_n3(1);
    let hash = [0x55u8; 32];
    r.on_proposal_received(hash);
    // Polka
    for i in 0..3 {
        r.on_prevote(make_vote(validator(i), 1, 0, VoteStep::Prevote, hash));
    }
    // Precommits — third one completes quorum
    r.on_precommit(make_vote(validator(0), 1, 0, VoteStep::Precommit, hash));
    r.on_precommit(make_vote(validator(1), 1, 0, VoteStep::Precommit, hash));
    let actions = r.on_precommit(make_vote(validator(2), 1, 0, VoteStep::Precommit, hash));

    assert_eq!(
        actions,
        vec![RoundAction::Commit {
            block_hash: hash,
            round: 0
        }]
    );
    assert!(r.is_decided());
    assert_eq!(r.committed_block_hash(), Some(hash));
}

#[test]
fn round_precommit_timeout_advances_round() {
    let mut r = round_n3(1);
    let hash = [0x10u8; 32];
    r.on_proposal_received(hash);
    r.on_prevote_timeout();
    let actions = r.on_precommit_timeout();
    assert_eq!(actions, vec![RoundAction::NextRound]);
    assert_eq!(r.round, 1);
    assert_eq!(r.phase, RoundPhase::Propose);
}

#[test]
fn round_view_change_uses_next_proposer() {
    // n=3: validators [0x00, 0x01, 0x02], height=1
    // round=0 proposer = sorted[(1+0)%3] = sorted[1] = 0x01
    // round=1 proposer = sorted[(1+1)%3] = sorted[2] = 0x02
    let v0 = [0x00u8; 32];
    let v1 = [0x01u8; 32];
    let v2 = [0x02u8; 32];
    let validators = [v0, v1, v2];

    let proposer_r0 = select_proposer(&validators, 1, 0, None);
    let proposer_r1 = select_proposer(&validators, 1, 1, None);
    assert_ne!(
        proposer_r0, proposer_r1,
        "view change must advance to different proposer"
    );
}

#[test]
fn round_equivocation_is_detected_in_state_machine() {
    let mut r = round_n3(1);
    let hash_a = [0xA0u8; 32];
    let hash_b = [0xB0u8; 32];
    let v0 = validator(0);

    r.on_proposal_received(hash_a);
    // First prevote
    r.on_prevote(make_vote(v0, 1, 0, VoteStep::Prevote, hash_a));
    // Second prevote with different hash — equivocation
    r.on_prevote(make_vote(v0, 1, 0, VoteStep::Prevote, hash_b));

    assert_eq!(r.vote_store.equivocation_count(), 1);
    let evidence = &r.vote_store.equivocations()[0];
    assert_eq!(evidence.validator_address, v0);
}

// SPDX-License-Identifier: BUSL-1.1
//! BFT consensus round state machine — SPEC-CONSENSUS-001.
//!
//! Provides:
//! - Vote types and signature preimage functions (§7.4)
//! - Proposer selection (§5)
//! - VoteStore with equivocation detection (§10)
//! - ConsensusRound: per-height state machine (§6)
//!
//! This module is pure logic — no I/O, no async. Callers feed in votes and
//! timeout events; the module returns actions to take.

use std::collections::HashMap;

use pqc_crypto::tagged_hash;
use pqc_types::ForkDigest;

use crate::quorum::quorum_size;

// ── Vote step ─────────────────────────────────────────────────────────────────

/// A step within a consensus round (SPEC-CONSENSUS-001 §3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VoteStep {
    Prevote = 1,
    Precommit = 2,
}

// ── Nil hash sentinel ─────────────────────────────────────────────────────────

/// The nil block hash: 32 zero bytes. Used when a validator cannot vote for a
/// real block (no proposal received, propose timeout, locked on different block).
pub const NIL_HASH: [u8; 32] = [0u8; 32];

// ── Signature preimage functions ──────────────────────────────────────────────

/// Domain tag for vote signing preimages — consumed under the BIP340
/// double-tagged construction (ADR-053 §T2.4). Exposed as a constant so
/// the slashing-side vote reconstruction (`pqc_state::apply::slashing`)
/// can reuse the exact same byte string; equivocation detection MUST
/// hash under the same tag as the producer.
pub const VOTE_DOMAIN_TAG: &[u8] = b"VIPER-VOTE-V1";

/// Domain tag for proposal signing preimages — see [`VOTE_DOMAIN_TAG`].
pub const PROPOSAL_DOMAIN_TAG: &[u8] = b"VIPER-PROPOSAL-V1";

/// Compute the vote preimage for Prevote or Precommit signing.
///
/// Per SPEC-CONSENSUS-001 §7.4 + ADR-053 §T1.2 + §T2.4:
/// ```text
/// preimage = tagged_hash(
///   "VIPER-VOTE-V1",
///   fork_digest[4] || height_be64 || round_be32 || step_u8 || block_hash,
/// )
///          = SHAKE-256(
///              H("VIPER-VOTE-V1") || H("VIPER-VOTE-V1") ||
///              fork_digest[4] || height_be64 || round_be32 ||
///              step_u8 || block_hash,
///              output_len = 32,
///          )
/// ```
///
/// The 4-byte `fork_digest` prefix scopes every vote signature to a specific
/// `(fork_version, genesis_validators_root)` pair so a signed vote on one
/// chain cannot be replayed on any parallel/future chain that shares the
/// `"VIPER-VOTE-V1"` domain tag (ADR-053 §T1.2). The double-tag outer hash
/// (ADR-053 §T2.4) defends against CVE-2012-2459-class domain collisions.
pub fn vote_preimage(
    fork_digest: &ForkDigest,
    height: u64,
    round: u32,
    step: VoteStep,
    block_hash: &[u8; 32],
) -> [u8; 32] {
    let mut body = Vec::with_capacity(4 + 8 + 4 + 1 + 32);
    body.extend_from_slice(fork_digest.as_bytes());
    body.extend_from_slice(&height.to_be_bytes());
    body.extend_from_slice(&round.to_be_bytes());
    body.push(step as u8);
    body.extend_from_slice(block_hash);
    tagged_hash(VOTE_DOMAIN_TAG, &body)
}

/// Compute the proposal preimage for Proposal signing.
///
/// Per SPEC-CONSENSUS-001 §7.4 + ADR-053 §T1.2 + §T2.4:
/// ```text
/// preimage = tagged_hash(
///   "VIPER-PROPOSAL-V1",
///   fork_digest[4] || height_be64 || round_be32 || pol_round_i32_be || block_hash,
/// )
/// ```
///
/// `pol_round` is -1 for a new proposal, or ≥ 0 when re-proposing a locked
/// block (the round at which the polka was observed). The `fork_digest`
/// prefix serves the same cross-chain-replay purpose described on
/// [`vote_preimage`]; the double-tag outer hash (ADR-053 §T2.4) defends
/// against domain-tag collisions.
pub fn proposal_preimage(
    fork_digest: &ForkDigest,
    height: u64,
    round: u32,
    pol_round: i32,
    block_hash: &[u8; 32],
) -> [u8; 32] {
    let mut body = Vec::with_capacity(4 + 8 + 4 + 4 + 32);
    body.extend_from_slice(fork_digest.as_bytes());
    body.extend_from_slice(&height.to_be_bytes());
    body.extend_from_slice(&round.to_be_bytes());
    body.extend_from_slice(&pol_round.to_be_bytes()); // two's-complement big-endian
    body.extend_from_slice(block_hash);
    tagged_hash(PROPOSAL_DOMAIN_TAG, &body)
}

// ── Proposer selection ────────────────────────────────────────────────────────

/// Select the block proposer.
///
/// If `randao_accumulator` is Some, uses RANDAO + height sortition (ADR-042 v1).
/// If None, falls back to sorted round-robin (legacy single-node path).
///
/// Legacy formula (equal voting power, SPEC-CONSENSUS-001 §5.1):
/// ```text
/// proposer(h, r) = sorted_validators[(h + r) % len]
/// ```
///
/// Returns None if `validators` is empty.
pub fn select_proposer(
    validators: &[[u8; 32]],
    height: u64,
    round: u32,
    randao_accumulator: Option<&[u8; 32]>,
) -> Option<[u8; 32]> {
    if validators.is_empty() {
        return None;
    }
    if let Some(randao) = randao_accumulator {
        let idx = crate::epoch::select_epoch_proposer(validators, height, randao)?;
        Some(validators[idx])
    } else {
        // Legacy: sorted round-robin (height + round) % n
        let mut sorted: Vec<&[u8; 32]> = validators.iter().collect();
        sorted.sort();
        let len = sorted.len() as u128;
        let idx = ((height as u128 + round as u128) % len) as usize;
        Some(*sorted[idx])
    }
}

// ── Consensus vote ────────────────────────────────────────────────────────────

/// A signed consensus vote (Prevote or Precommit).
///
/// The `signature` field is an ML-DSA-65 (or FN-DSA) signature over
/// `vote_preimage(height, round, step, block_hash)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsensusVote {
    pub height: u64,
    pub round: u32,
    pub step: VoteStep,
    /// 32-byte block hash, or `NIL_HASH` for nil.
    pub block_hash: [u8; 32],
    /// Validator operator address (32 bytes).
    pub validator_address: [u8; 32],
    /// Signature over `vote_preimage`. Empty in tests that do not perform real
    /// ML-DSA signing (the VoteStore does not verify signatures; that is the
    /// responsibility of the network admission layer).
    pub signature: Vec<u8>,
}

// ── Vote store & equivocation detection ──────────────────────────────────────

/// Key for the vote store: unique per (validator, height, round, step).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct VoteKey {
    validator: [u8; 32],
    height: u64,
    round: u32,
    step: VoteStep,
}

/// Evidence of equivocation: two conflicting signed messages at the same
/// (height, round, step) from the same validator (SPEC-CONSENSUS-001 §10.1).
#[derive(Debug, Clone)]
pub struct EquivocationEvidence {
    pub validator_address: [u8; 32],
    pub height: u64,
    pub round: u32,
    pub step: VoteStep,
    pub vote_a: ConsensusVote,
    pub vote_b: ConsensusVote,
}

/// In-memory vote store for one consensus instance.
///
/// Tracks received votes per (validator, height, round, step) and detects
/// equivocation (two votes with different block_hash at the same key).
///
/// This store does NOT verify signatures; the caller is responsible for
/// verifying signatures before calling `record`.
#[derive(Debug, Default)]
pub struct VoteStore {
    // One vote per (validator, height, round, step).
    votes: HashMap<VoteKey, ConsensusVote>,
    equivocations: Vec<EquivocationEvidence>,
}

impl VoteStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a vote. Returns `Some(evidence)` if equivocation is detected.
    ///
    /// Equivocation is defined as two votes at the same (height, round, step) with
    /// different block_hash values where at least one is non-nil (SPEC-CONSENSUS-001 §10.1).
    /// Duplicate votes with the same block_hash are silently discarded.
    pub fn record(&mut self, vote: ConsensusVote) -> Option<EquivocationEvidence> {
        let key = VoteKey {
            validator: vote.validator_address,
            height: vote.height,
            round: vote.round,
            step: vote.step,
        };

        if let Some(existing) = self.votes.get(&key) {
            if existing.block_hash != vote.block_hash {
                // Different hashes: equivocation if at least one is non-nil.
                if existing.block_hash != NIL_HASH || vote.block_hash != NIL_HASH {
                    let evidence = EquivocationEvidence {
                        validator_address: vote.validator_address,
                        height: vote.height,
                        round: vote.round,
                        step: vote.step,
                        vote_a: existing.clone(),
                        vote_b: vote,
                    };
                    self.equivocations.push(evidence.clone());
                    return Some(evidence);
                }
            }
            // Duplicate (same hash) or two nils: discard.
            return None;
        }

        self.votes.insert(key, vote);
        None
    }

    /// Return all prevotes recorded for `(height, round)`.
    pub fn prevotes(&self, height: u64, round: u32) -> Vec<&ConsensusVote> {
        self.votes
            .values()
            .filter(|v| v.height == height && v.round == round && v.step == VoteStep::Prevote)
            .collect()
    }

    /// Return all precommits recorded for `(height, round)`.
    pub fn precommits(&self, height: u64, round: u32) -> Vec<&ConsensusVote> {
        self.votes
            .values()
            .filter(|v| v.height == height && v.round == round && v.step == VoteStep::Precommit)
            .collect()
    }

    /// Count prevotes for a specific non-nil block hash at `(height, round)`.
    pub fn prevote_count_for(&self, height: u64, round: u32, block_hash: &[u8; 32]) -> usize {
        self.prevotes(height, round)
            .iter()
            .filter(|v| &v.block_hash == block_hash)
            .count()
    }

    /// Count precommits for a specific non-nil block hash at `(height, round)`.
    pub fn precommit_count_for(&self, height: u64, round: u32, block_hash: &[u8; 32]) -> usize {
        self.precommits(height, round)
            .iter()
            .filter(|v| &v.block_hash == block_hash)
            .count()
    }

    /// Return `true` if a polka exists: ≥ `quorum` prevotes for the same non-nil block hash.
    pub fn has_polka(&self, height: u64, round: u32, block_hash: &[u8; 32], quorum: usize) -> bool {
        if block_hash == &NIL_HASH {
            return false;
        }
        self.prevote_count_for(height, round, block_hash) >= quorum
    }

    /// Return `true` if a commit quorum exists: ≥ `quorum` precommits for the same non-nil block hash.
    pub fn has_commit_quorum(
        &self,
        height: u64,
        round: u32,
        block_hash: &[u8; 32],
        quorum: usize,
    ) -> bool {
        if block_hash == &NIL_HASH {
            return false;
        }
        self.precommit_count_for(height, round, block_hash) >= quorum
    }

    /// Return all recorded equivocation evidence.
    pub fn equivocations(&self) -> &[EquivocationEvidence] {
        &self.equivocations
    }

    /// Return the count of recorded equivocation incidents.
    pub fn equivocation_count(&self) -> usize {
        self.equivocations.len()
    }
}

// ── Round state machine ───────────────────────────────────────────────────────

/// The current phase of a consensus round (SPEC-CONSENSUS-001 §6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoundPhase {
    Propose,
    Prevote,
    Precommit,
    Decided,
}

/// Actions returned by the `ConsensusRound` state machine.
///
/// The caller is responsible for acting on these: broadcasting messages to
/// peers, committing blocks, or advancing to the next round.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoundAction {
    /// Broadcast a prevote to all validators.
    BroadcastPrevote { block_hash: [u8; 32] },
    /// Broadcast a precommit to all validators.
    BroadcastPrecommit { block_hash: [u8; 32] },
    /// Quorum reached — commit this block and advance height.
    Commit { block_hash: [u8; 32], round: u32 },
    /// Round timed out without commit — advance to round+1.
    NextRound,
}

/// Per-height BFT consensus state machine (SPEC-CONSENSUS-001 §6).
///
/// Instantiate one `ConsensusRound` per height. Feed it votes via `on_prevote`
/// and `on_precommit`, and timeout events via `on_*_timeout`. Act on the
/// returned `RoundAction` values.
///
/// The state machine does not verify signatures (caller responsibility) and
/// does not communicate over the network (caller responsibility).
pub struct ConsensusRound {
    pub height: u64,
    pub round: u32,
    pub phase: RoundPhase,
    pub validator_count: usize,
    /// Block this validator has locked on (from a prior precommit), if any.
    pub locked_block: Option<[u8; 32]>,
    pub locked_round: Option<u32>,
    pub vote_store: VoteStore,
}

impl ConsensusRound {
    pub fn new(height: u64, validator_count: usize) -> Self {
        Self {
            height,
            round: 0,
            phase: RoundPhase::Propose,
            validator_count,
            locked_block: None,
            locked_round: None,
            vote_store: VoteStore::new(),
        }
    }

    fn quorum(&self) -> usize {
        quorum_size(self.validator_count)
    }

    /// Called when a valid Proposal is received for the current (height, round).
    ///
    /// Returns the prevote action: vote for the proposed block (if not locked on
    /// a different one) or vote nil (if locked on a conflicting block).
    pub fn on_proposal_received(&mut self, block_hash: [u8; 32]) -> Vec<RoundAction> {
        if self.phase != RoundPhase::Propose {
            return Vec::new();
        }
        self.phase = RoundPhase::Prevote;

        // Locking rule: vote for proposal only if not locked or locked on same block.
        let vote_hash = match self.locked_block {
            Some(locked) if locked != block_hash => NIL_HASH,
            _ => block_hash,
        };
        vec![RoundAction::BroadcastPrevote {
            block_hash: vote_hash,
        }]
    }

    /// Called when the propose timeout fires without receiving a valid Proposal.
    pub fn on_propose_timeout(&mut self) -> Vec<RoundAction> {
        if self.phase != RoundPhase::Propose {
            return Vec::new();
        }
        self.phase = RoundPhase::Prevote;
        vec![RoundAction::BroadcastPrevote {
            block_hash: NIL_HASH,
        }]
    }

    /// Called when a Prevote is received.
    ///
    /// If a polka (≥ quorum prevotes for the same non-nil hash) is observed for
    /// the first time, transitions to Precommit and returns a precommit action.
    pub fn on_prevote(&mut self, vote: ConsensusVote) -> Vec<RoundAction> {
        let _ = self.vote_store.record(vote.clone());

        if self.phase == RoundPhase::Decided {
            return Vec::new();
        }
        if vote.height != self.height || vote.round != self.round {
            return Vec::new();
        }
        if vote.block_hash == NIL_HASH {
            return Vec::new();
        }

        // Check if receiving this vote completed a polka.
        if self.phase == RoundPhase::Prevote
            && self
                .vote_store
                .has_polka(self.height, self.round, &vote.block_hash, self.quorum())
        {
            self.phase = RoundPhase::Precommit;
            self.locked_block = Some(vote.block_hash);
            self.locked_round = Some(self.round);
            return vec![RoundAction::BroadcastPrecommit {
                block_hash: vote.block_hash,
            }];
        }

        Vec::new()
    }

    /// Called when the prevote timeout fires (quorum prevotes not yet seen).
    pub fn on_prevote_timeout(&mut self) -> Vec<RoundAction> {
        if self.phase != RoundPhase::Prevote {
            return Vec::new();
        }
        self.phase = RoundPhase::Precommit;
        vec![RoundAction::BroadcastPrecommit {
            block_hash: NIL_HASH,
        }]
    }

    /// Called when a Precommit is received.
    ///
    /// If a commit quorum (≥ quorum precommits for the same non-nil hash) is
    /// observed, returns a `Commit` action. Otherwise returns an empty list.
    pub fn on_precommit(&mut self, vote: ConsensusVote) -> Vec<RoundAction> {
        let _ = self.vote_store.record(vote.clone());

        if self.phase == RoundPhase::Decided {
            return Vec::new();
        }
        if vote.height != self.height || vote.round != self.round {
            return Vec::new();
        }
        if vote.block_hash == NIL_HASH {
            return Vec::new();
        }

        let quorum = self.quorum();
        if self
            .vote_store
            .has_commit_quorum(self.height, self.round, &vote.block_hash, quorum)
        {
            self.phase = RoundPhase::Decided;
            return vec![RoundAction::Commit {
                block_hash: vote.block_hash,
                round: self.round,
            }];
        }

        Vec::new()
    }

    /// Called when the precommit timeout fires (commit quorum not yet seen).
    ///
    /// Advances to the next round and resets the phase to Propose.
    pub fn on_precommit_timeout(&mut self) -> Vec<RoundAction> {
        if self.phase == RoundPhase::Decided {
            return Vec::new();
        }
        self.round += 1;
        self.phase = RoundPhase::Propose;
        vec![RoundAction::NextRound]
    }

    /// Return `true` if a commit has been reached at this height.
    pub fn is_decided(&self) -> bool {
        self.phase == RoundPhase::Decided
    }

    /// Return the committed block hash, if the round has been decided.
    pub fn committed_block_hash(&self) -> Option<[u8; 32]> {
        if self.phase == RoundPhase::Decided {
            // The committed block hash is the one that reached quorum.
            // Find it from the precommit store.
            for round in 0..=self.round {
                for vote in self.vote_store.precommits(self.height, round) {
                    if vote.block_hash != NIL_HASH {
                        let quorum = self.quorum();
                        if self.vote_store.has_commit_quorum(
                            self.height,
                            round,
                            &vote.block_hash,
                            quorum,
                        ) {
                            return Some(vote.block_hash);
                        }
                    }
                }
            }
        }
        None
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;

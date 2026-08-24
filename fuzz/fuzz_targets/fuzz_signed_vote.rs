// SPDX-License-Identifier: BUSL-1.1
//! cargo-fuzz target: fuzz the SignedVote (Precommit / Prevote) decoder.
//!
//! Consensus votes arrive over the `ConsensusVote` gossip topic. The proposer
//! aggregates them into block.commit_signatures via
//! `merge_distributed_precommits_into_block`. Before that path runs, the raw
//! payload must be decoded into a `SignedVote { msg_type, height, round,
//! block_hash, validator_address, signature }`. A panic here halts the
//! aggregator (= the elected proposer for the height) — exactly the
//! consensus-availability attack the threat model §3.2 names.
//!
//! # Running
//!
//! ```bash
//! cargo +nightly fuzz run fuzz_signed_vote --manifest-path fuzz/Cargo.toml
//! ```
//!
//! # Invariant
//!
//! `decode_signed_vote(arbitrary_bytes)` must always return either Ok or
//! Err(SignedVoteDecodeError) — never panic, overflow, or UB.
//!
//! # Why this target matters
//!
//! TASK-216 / L2 fuzzing. Pairs with `fuzz_p2p_envelope`: that target covers
//! the outer gossipsub wrapper; this one covers the inner consensus payload.
//! Together they cover the full peer-controlled byte path from gossip wire
//! to in-memory `pending_precommits` insertion.

#![no_main]
use libfuzzer_sys::fuzz_target;
use pqc_types::decode_signed_vote;

fuzz_target!(|data: &[u8]| {
    let _ = decode_signed_vote(data);
});

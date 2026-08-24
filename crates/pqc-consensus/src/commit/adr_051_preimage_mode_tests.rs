// SPDX-License-Identifier: BUSL-1.1
//! Tests for `commit`.
//!
//! Extracted from `commit.rs` 2026-05-10. `use super::*;`
//! brings every private item from the parent module into scope.

//! ADR-051: pin the commit-sig preimage mode unification.
//!
//! Legacy mode must produce bytes identical to the `commit_preimage`
//! helper (devnet-2 bytewise stability pin — replays that cross the
//! cutover boundary from pre-ADR-051 to a Legacy policy must verify
//! identical signatures).
//!
//! Distributed mode must produce bytes identical to the §8.4 vote
//! preimage with `round = 0` and `step = Precommit` — ensuring the
//! producer's signing-side helper (`vote_preimage` via
//! `build_signed_precommit`) and the verifier both see the same
//! bytes, which is the core ADR-051 invariant.
use super::*;
use crate::round::{vote_preimage, VoteStep};
use pqc_types::block::BlockHash;

fn test_fork_digest() -> ForkDigest {
    ForkDigest::viper_research_1()
}

#[test]
fn legacy_mode_matches_commit_preimage_helper() {
    let fd = test_fork_digest();
    let height = 42;
    let block_hash = BlockHash([0xABu8; 32]);
    let via_mode = commit_preimage_for_mode(&fd, CommitPreimageMode::Legacy, height, &block_hash);
    let direct = commit_preimage(&fd, height, &block_hash);
    assert_eq!(
        via_mode, direct,
        "Legacy mode MUST produce byte-identical preimage to \
         commit_preimage(height, block_hash) — replays across the \
         ADR-051 cutover depend on this invariant."
    );
}

#[test]
fn distributed_mode_matches_vote_preimage_with_precommit_step_zero_round() {
    let fd = test_fork_digest();
    let height = 100;
    let round = 0u32;
    let block_hash = BlockHash([0xCDu8; 32]);
    let via_mode = commit_preimage_for_mode(
        &fd,
        CommitPreimageMode::Distributed { round },
        height,
        &block_hash,
    );
    let via_vote = vote_preimage(&fd, height, round, VoteStep::Precommit, &block_hash.0).to_vec();
    assert_eq!(
        via_mode, via_vote,
        "Distributed mode MUST produce byte-identical preimage to \
         vote_preimage(h, 0, Precommit, block_hash) — SPEC-CONSENSUS-001 \
         §10.4 'CommitSig is a Precommit message with a valid signature'."
    );
}

#[test]
fn legacy_and_distributed_produce_different_preimages() {
    let fd = test_fork_digest();
    let height = 100;
    let block_hash = BlockHash([0x11u8; 32]);
    let legacy = commit_preimage_for_mode(&fd, CommitPreimageMode::Legacy, height, &block_hash);
    let distributed = commit_preimage_for_mode(
        &fd,
        CommitPreimageMode::Distributed { round: 0 },
        height,
        &block_hash,
    );
    assert_ne!(
        legacy, distributed,
        "SPEC-CONSENSUS-001 §8.4 requires 'MUST NOT be intermixed' — \
         the two preimages must be byte-distinct so a signature under \
         one verifier does not accidentally verify under the other."
    );
}

#[test]
fn policy_mode_accessor_round_trips() {
    let validators = vec![CommitValidator {
        node_id: "v".into(),
        address: vec![1u8; 32],
        sig_alg_id: pqc_crypto::AlgId::MlDsa65,
        public_key: vec![0u8; 1952],
    }];
    let legacy_policy = CommitQuorumPolicy::new(validators.clone(), None).unwrap();
    assert_eq!(legacy_policy.preimage_mode(), CommitPreimageMode::Legacy);

    let distributed_policy = CommitQuorumPolicy::new(validators, None)
        .unwrap()
        .with_distributed_preimage(3);
    assert_eq!(
        distributed_policy.preimage_mode(),
        CommitPreimageMode::Distributed { round: 3 }
    );
}

/// End-to-end pin: a SignedVote(Precommit) signature — built using the
/// exact formula that `build_signed_precommit` in pqcd applies
/// (ml_dsa_sign_with_seed over `vote_preimage(height, round,
/// VoteStep::Precommit, block_hash)`) — MUST verify when fed to
/// `validate_block_commit_quorum` with a `Distributed { round }`
/// policy. This closes the round-trip the earlier pin tests left
/// implicit: they only verified byte-equivalence of the preimage on
/// the verifier side; this one proves that what the validator
/// actually signs for the gossip vote is exactly what the verifier
/// will accept as a CommitSig.
///
/// SPEC-CONSENSUS-001 §10.4 "CommitSig is a Precommit message with a
/// valid signature" — this test is the executable form of that claim.
#[test]
fn signed_vote_precommit_roundtrip_via_distributed_mode() {
    use pqc_crypto::{ml_dsa_public_key_from_seed, ml_dsa_sign_with_seed, AlgId};
    use pqc_types::block::{Block, BlockHeader, CommitSig};

    // Real ML-DSA-65 keypair — same derivation path the
    // pqcd keystore + build_signed_precommit use at runtime.
    let seed = [0x42u8; 32];
    let pk = ml_dsa_public_key_from_seed(AlgId::MlDsa65, &seed).expect("pk derivation");
    let address = vec![0xAAu8; 32];

    // Distributed-mode policy with our single validator at round 0.
    let policy = CommitQuorumPolicy::new(
        vec![CommitValidator {
            node_id: "v-roundtrip".into(),
            address: address.clone(),
            sig_alg_id: AlgId::MlDsa65,
            public_key: pk,
        }],
        Some(1),
    )
    .expect("policy must build")
    .with_distributed_preimage(0);

    // Build a concrete block; its hash is what the precommit signs.
    let height = 100u64;
    let block = Block {
        header: BlockHeader {
            height,
            prev_hash: BlockHash([0x00u8; 32]),
            state_root: BlockHash([0x11u8; 32]),
            tx_root: BlockHash([0x22u8; 32]),
            timestamp: 1_710_000_000,
            proposer: address.clone(),
            ..Default::default()
        },
        tx_hashes: Vec::new(),
        commit_signatures: Vec::new(),
    };
    let block_hash = crate::engine::compute_block_hash(&block);

    // Sign EXACTLY as `build_signed_precommit` does: ML-DSA over
    // vote_preimage(fork_digest, height, round=0, Precommit, block_hash).
    let preimage = vote_preimage(
        policy.fork_digest(),
        height,
        0,
        VoteStep::Precommit,
        &block_hash.0,
    )
    .to_vec();
    let signature = ml_dsa_sign_with_seed(AlgId::MlDsa65, &seed, &preimage).expect("sign");

    // Attach as a CommitSig (the block's wire-level container) and
    // feed to the verifier under the Distributed-mode policy.
    let mut block_with_sig = block.clone();
    block_with_sig.commit_signatures.push(CommitSig {
        validator_address: address,
        sig_alg_id: AlgId::MlDsa65,
        round: 0,
        signature,
    });

    validate_block_commit_quorum(&block_with_sig, &policy).expect(
        "end-to-end: ML-DSA signature over §8.4 Precommit preimage \
         MUST verify under Distributed-mode CommitQuorumPolicy — \
         this is the ADR-051 §10.4 invariant",
    );
}

/// SPEC-CONSENSUS-001 §10.1 — "Precommits from different rounds MAY
/// be combined if they all reference the same `block_hash(B)`".
///
/// This pin test (TASK-171) proves the verifier honours §10.1: a
/// block whose commit_signatures contain sigs signed at MULTIPLE
/// DIFFERENT rounds over the SAME block_hash must verify. Before
/// TASK-171 the verifier built a single preimage from a
/// policy-level round, silently failing any sig whose round
/// differed — a liveness footgun that would kill devnet-3 the
/// first time a timeout pushed any validator to round 1.
///
/// Scenario: 3 validators, quorum=2. Validator 0 signs Precommit at
/// round=0. Validator 1 signs Precommit at round=1 (simulating a
/// round-advance after a round-0 timeout). Validator 2 signs at
/// round=2 (another timeout). All three reference the SAME
/// block_hash(B). The verifier must accept the mixed-round set.
#[test]
fn distributed_mode_accepts_precommits_from_different_rounds() {
    use pqc_crypto::{ml_dsa_public_key_from_seed, ml_dsa_sign_with_seed, AlgId};
    use pqc_types::block::{Block, BlockHeader, CommitSig};

    let seeds: [[u8; 32]; 3] = [[0x10; 32], [0x20; 32], [0x30; 32]];
    let addresses: [Vec<u8>; 3] = [vec![0xA1; 32], vec![0xA2; 32], vec![0xA3; 32]];
    let pks: Vec<Vec<u8>> = seeds
        .iter()
        .map(|s| ml_dsa_public_key_from_seed(AlgId::MlDsa65, s).unwrap())
        .collect();

    let validators: Vec<CommitValidator> = (0..3)
        .map(|i| CommitValidator {
            node_id: format!("v{i}"),
            address: addresses[i].clone(),
            sig_alg_id: AlgId::MlDsa65,
            public_key: pks[i].clone(),
        })
        .collect();
    let policy = CommitQuorumPolicy::new(validators, Some(3))
        .unwrap()
        .with_distributed_preimage(0);

    let height = 42u64;
    let block = Block {
        header: BlockHeader {
            height,
            prev_hash: BlockHash([0x00u8; 32]),
            state_root: BlockHash([0x77u8; 32]),
            tx_root: BlockHash([0x88u8; 32]),
            timestamp: 1_710_000_000,
            proposer: addresses[0].clone(),
            ..Default::default()
        },
        tx_hashes: Vec::new(),
        commit_signatures: Vec::new(),
    };
    let block_hash = crate::engine::compute_block_hash(&block);

    // Three validators each sign at a DIFFERENT round (0, 1, 2)
    // over the same block_hash — the §10.1 multi-round combine case.
    let rounds: [u32; 3] = [0, 1, 2];
    let mut sigs = Vec::with_capacity(3);
    for i in 0..3 {
        let preimage = vote_preimage(
            policy.fork_digest(),
            height,
            rounds[i],
            VoteStep::Precommit,
            &block_hash.0,
        )
        .to_vec();
        let signature = ml_dsa_sign_with_seed(AlgId::MlDsa65, &seeds[i], &preimage).expect("sign");
        sigs.push(CommitSig {
            validator_address: addresses[i].clone(),
            sig_alg_id: AlgId::MlDsa65,
            round: rounds[i],
            signature,
        });
    }

    let mut block_with_sigs = block.clone();
    block_with_sigs.commit_signatures = sigs;

    validate_block_commit_quorum(&block_with_sigs, &policy).expect(
        "SPEC-CONSENSUS-001 §10.1: Precommits from different rounds \
         (0, 1, 2) over the SAME block_hash MUST verify — else any \
         timeout-driven round advance on devnet-3 kills consensus.",
    );
}

/// Symmetric negative: a CommitSig whose `round` field does NOT
/// match the round the signer actually used at signing time MUST
/// fail verification. This pins that the verifier is using the
/// per-sig round and not a hoisted policy round.
#[test]
fn distributed_mode_rejects_sig_with_wrong_round_field() {
    use pqc_crypto::{ml_dsa_public_key_from_seed, ml_dsa_sign_with_seed, AlgId};
    use pqc_types::block::{Block, BlockHeader, CommitSig};

    let seed = [0x42u8; 32];
    let pk = ml_dsa_public_key_from_seed(AlgId::MlDsa65, &seed).unwrap();
    let address = vec![0xAAu8; 32];

    let policy = CommitQuorumPolicy::new(
        vec![CommitValidator {
            node_id: "v".into(),
            address: address.clone(),
            sig_alg_id: AlgId::MlDsa65,
            public_key: pk,
        }],
        Some(1),
    )
    .unwrap()
    .with_distributed_preimage(0);

    let height = 100u64;
    let block = Block {
        header: BlockHeader {
            height,
            prev_hash: BlockHash([0u8; 32]),
            state_root: BlockHash([1u8; 32]),
            tx_root: BlockHash([2u8; 32]),
            timestamp: 1_710_000_000,
            proposer: address.clone(),
            ..Default::default()
        },
        tx_hashes: Vec::new(),
        commit_signatures: Vec::new(),
    };
    let block_hash = crate::engine::compute_block_hash(&block);

    // Sign at round=0 but tag the CommitSig as round=1 — forgery /
    // mis-encoding scenario. Verifier rebuilds preimage with
    // round=1, mismatches the signature, rejects.
    let preimage = vote_preimage(
        policy.fork_digest(),
        height,
        0,
        VoteStep::Precommit,
        &block_hash.0,
    )
    .to_vec();
    let signature = ml_dsa_sign_with_seed(AlgId::MlDsa65, &seed, &preimage).unwrap();

    let mut block_with_sig = block.clone();
    block_with_sig.commit_signatures.push(CommitSig {
        validator_address: address,
        sig_alg_id: AlgId::MlDsa65,
        round: 1, // WRONG — signed at 0, tagged as 1
        signature,
    });

    let err = validate_block_commit_quorum(&block_with_sig, &policy).unwrap_err();
    assert!(
        matches!(err, CommitValidationError::InvalidSignature { .. }),
        "signing at round 0 but claiming round 1 in CommitSig MUST \
         fail verification — pins per-sig round-binding."
    );
}

/// TASK-181 — 20× determinism harness for the ADR-051 Distributed-mode
/// preimage + signature pair.
///
/// Re-runs the full Distributed-mode preimage construction and ML-DSA-65
/// signature 20 times back-to-back with FIXED inputs (height, round,
/// block_hash, validator seed). All 20 iterations MUST produce
/// byte-identical preimage AND byte-identical signature bytes.
///
/// Why this matters:
///   * Preimage byte-identity is the ADR-051 §10.4 invariant — any
///     non-determinism in the preimage builder would silently produce
///     replay-incompatible commit material across nodes/runs.
///   * Signature byte-identity holds because `ml_dsa_sign_with_seed`
///     uses ML-DSA-65 deterministic signing (FIPS 204 §3.4 with the
///     deterministic randomness path) — any drift to randomized
///     signing in the signing crate would surface here as a quorum
///     determinism failure.
///
/// This is a unit-level test (no I/O, no async, no network), so 20
/// iterations cost only milliseconds — no `#[ignore]` needed.
#[test]
fn adr_051_distributed_mode_byte_pins_20x() {
    use pqc_crypto::{ml_dsa_public_key_from_seed, ml_dsa_sign_with_seed, AlgId};
    use pqc_types::block::{Block, BlockHeader, CommitSig};

    // Fixed inputs across all 20 runs.
    let seed = [0x42u8; 32];
    let pk =
        ml_dsa_public_key_from_seed(AlgId::MlDsa65, &seed).expect("pk derivation must succeed");
    let address = vec![0xAAu8; 32];
    let height = 100u64;
    let round = 0u32;
    let block = Block {
        header: BlockHeader {
            height,
            prev_hash: BlockHash([0x00u8; 32]),
            state_root: BlockHash([0x11u8; 32]),
            tx_root: BlockHash([0x22u8; 32]),
            timestamp: 1_710_000_000,
            proposer: address.clone(),
            ..Default::default()
        },
        tx_hashes: Vec::new(),
        commit_signatures: Vec::new(),
    };
    let block_hash = crate::engine::compute_block_hash(&block);

    // Run the build 20 times, capturing both preimage and signature
    // bytes per iteration.
    let mut preimages: Vec<Vec<u8>> = Vec::with_capacity(20);
    let mut signatures: Vec<Vec<u8>> = Vec::with_capacity(20);
    let policy_fork_digest = ForkDigest::viper_research_1();
    for _ in 0..20 {
        let preimage = commit_preimage_for_mode(
            &policy_fork_digest,
            CommitPreimageMode::Distributed { round },
            height,
            &block_hash,
        );
        let signature = ml_dsa_sign_with_seed(AlgId::MlDsa65, &seed, &preimage).expect("sign");
        preimages.push(preimage);
        signatures.push(signature);
    }

    // Every iteration must equal iteration 0 byte-for-byte.
    for i in 1..20 {
        assert_eq!(
            preimages[i], preimages[0],
            "20× determinism: distributed-mode preimage at run {i} \
             diverged from run 0 — ADR-051 §10.4 requires byte-stable \
             preimage construction"
        );
        assert_eq!(
            signatures[i], signatures[0],
            "20× determinism: ML-DSA-65 signature at run {i} diverged \
             from run 0 — ml_dsa_sign_with_seed MUST be deterministic \
             for fixed (seed, message) per FIPS 204 §3.4 deterministic \
             signing path. A drift here breaks cross-node quorum."
        );
    }

    // End-to-end seal: the run-0 signature MUST verify under the
    // Distributed-mode policy (closes the loop with the verifier).
    let policy = CommitQuorumPolicy::new(
        vec![CommitValidator {
            node_id: "v-20x".into(),
            address: address.clone(),
            sig_alg_id: AlgId::MlDsa65,
            public_key: pk,
        }],
        Some(1),
    )
    .expect("policy build")
    .with_distributed_preimage(round);
    let mut block_with_sig = block.clone();
    block_with_sig.commit_signatures.push(CommitSig {
        validator_address: address,
        sig_alg_id: AlgId::MlDsa65,
        round,
        signature: signatures[0].clone(),
    });
    validate_block_commit_quorum(&block_with_sig, &policy)
        .expect("20× pinned signature MUST verify under Distributed-mode policy");
}

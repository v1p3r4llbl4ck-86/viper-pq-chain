// SPDX-License-Identifier: BUSL-1.1
//! Tests for `commit`.
//!
//! Extracted from `commit.rs` 2026-05-10. `use super::*;`
//! brings every private item from the parent module into scope.

//! TASK-151: Byzantine fault rejection in `validate_block_commit_quorum`.
//!
//! These tests pin the safety-side rejection paths of the commit
//! validator — the only code path that gates a block from being
//! accepted on the honest chain. They target the three classes
//! of rejection that run BEFORE expensive signature verification
//! (MissingCommitSignatures, DuplicateSigner, UnauthorizedSigner),
//! so the tests are fast and do not need real ML-DSA signatures.
//!
//! Scenarios that require valid signatures AND a quorum shortfall
//! (e.g. `InsufficientQuorum` with all-valid signers below the
//! threshold) are intentionally deferred — the fast-path rejection
//! tests here cover the highest-impact byzantine attack classes
//! that the quorum gate must reject, and signing-path coverage is
//! already exercised by the M1 cutover devnet + the existing
//! `bft_consensus.rs` integration suite.
//!
//! See audit-plan §4.3 "Classes of finding tipiche nel consensus"
//! and audit-readiness §5 gap D19.

use super::*;
use pqc_crypto::{ml_dsa_public_key_from_seed, ml_dsa_sign_with_seed, AlgId};
use pqc_types::block::{Block, BlockHash, BlockHeader, CommitSig};

/// Build a CommitQuorumPolicy with `n` real ML-DSA-65 validators.
/// Returns the policy and a parallel vec of seeds so tests can
/// produce valid signatures on demand.
fn mk_policy_with_seeds(n: u8) -> (CommitQuorumPolicy, Vec<[u8; 32]>) {
    let seeds: Vec<[u8; 32]> = (1..=n).map(|i| [i; 32]).collect();
    let validators: Vec<CommitValidator> = seeds
        .iter()
        .enumerate()
        .map(|(idx, seed)| {
            let pk = ml_dsa_public_key_from_seed(AlgId::MlDsa65, seed).expect("pk derivation");
            CommitValidator {
                node_id: format!("validator-{}", idx + 1),
                address: vec![(idx as u8) + 1; 32],
                sig_alg_id: AlgId::MlDsa65,
                public_key: pk,
            }
        })
        .collect();
    let policy = CommitQuorumPolicy::new(validators, None).expect("policy must build");
    (policy, seeds)
}

/// Build a policy without deriving real keys — for fast tests that
/// do not need to pass signature verification (empty + unauthorized).
fn mk_policy(n: u8) -> CommitQuorumPolicy {
    let validators: Vec<CommitValidator> = (1..=n)
        .map(|i| CommitValidator {
            node_id: format!("validator-{i}"),
            address: vec![i; 32],
            sig_alg_id: AlgId::MlDsa65,
            public_key: vec![i; 1952],
        })
        .collect();
    CommitQuorumPolicy::new(validators, None).expect("policy must build")
}

/// A minimal Block with the given commit_signatures. The header
/// fields are synthetic; validate_block_commit_quorum only reads
/// header.height + commit_signatures, so the rest is irrelevant.
fn mk_block(height: u64, sigs: Vec<CommitSig>) -> Block {
    Block {
        header: BlockHeader {
            height,
            prev_hash: BlockHash([0xAA; 32]),
            state_root: BlockHash([0xBB; 32]),
            tx_root: BlockHash([0xCC; 32]),
            timestamp: 1_700_000_000,
            proposer: vec![0x01; 32],
            ..Default::default()
        },
        tx_hashes: Vec::new(),
        commit_signatures: sigs,
    }
}

/// Byzantine scenario A: block proposer submits a block with zero
/// commit signatures. MUST be rejected with `MissingCommitSignatures`
/// before any other check runs.
#[test]
fn empty_commit_signatures_returns_missing() {
    let policy = mk_policy(4);
    let block = mk_block(100, Vec::new());
    let err = validate_block_commit_quorum(&block, &policy).unwrap_err();
    assert!(
        matches!(err, CommitValidationError::MissingCommitSignatures),
        "empty commit_signatures MUST trip MissingCommitSignatures; got {err:?}"
    );
}

/// Byzantine scenario B: a compromised proposer tries to pad the
/// commit_signatures with duplicate entries from the same validator
/// to fake a quorum. The first entry signs correctly, passes
/// unauthorized + signature check, and bumps `unique_signers` —
/// the SECOND entry with the same address trips the duplicate
/// guard and the block MUST be rejected.
///
/// Requires a real ML-DSA-65 signature for the first entry so
/// the loop progresses to the duplicate check on the second
/// iteration (the sig-verify path short-circuits on bad bytes
/// before the duplicate detection ever fires).
#[test]
fn duplicate_signer_is_rejected() {
    let (policy, seeds) = mk_policy_with_seeds(4);
    // Build the canonical preimage the validator signs: commit
    // for height H and the hash of the block being committed.
    let height = 100u64;
    let block_header = BlockHeader {
        height,
        prev_hash: BlockHash([0xAA; 32]),
        state_root: BlockHash([0xBB; 32]),
        tx_root: BlockHash([0xCC; 32]),
        timestamp: 1_700_000_000,
        proposer: vec![0x01; 32],
        ..Default::default()
    };
    let block_for_hash = Block {
        header: block_header.clone(),
        tx_hashes: Vec::new(),
        commit_signatures: Vec::new(),
    };
    let block_hash = compute_block_hash(&block_for_hash);
    let preimage = commit_preimage(policy.fork_digest(), height, &block_hash);

    // Validator 1 produces a real signature.
    let sig_bytes = ml_dsa_sign_with_seed(AlgId::MlDsa65, &seeds[0], &preimage).expect("sign");
    let sig_one = CommitSig {
        validator_address: vec![1u8; 32],
        sig_alg_id: AlgId::MlDsa65,
        round: 0,
        signature: sig_bytes,
    };

    let block = Block {
        header: block_header,
        tx_hashes: Vec::new(),
        // Same validator address twice: first entry passes, second
        // trips DuplicateSigner before re-running signature verify.
        commit_signatures: vec![sig_one.clone(), sig_one],
    };

    let err = validate_block_commit_quorum(&block, &policy).unwrap_err();
    match err {
        CommitValidationError::DuplicateSigner {
            validator_address_hex,
        } => {
            assert_eq!(validator_address_hex, hex::encode([1u8; 32]));
        }
        other => panic!("expected DuplicateSigner, got {other:?}"),
    }
}

/// Byzantine scenario C: an outsider (non-validator) signs a
/// precommit and the proposer includes it to pad the count. The
/// validator registry lookup MUST reject it with UnauthorizedSigner
/// before signature verification.
#[test]
fn unauthorized_signer_is_rejected() {
    let policy = mk_policy(4);
    let outsider = vec![0xFFu8; 32]; // not in the policy's (1..=4)
    let sig = CommitSig {
        validator_address: outsider.clone(),
        sig_alg_id: AlgId::MlDsa65,
        round: 0,
        signature: vec![0xBB; 3_309],
    };
    let block = mk_block(100, vec![sig]);
    let err = validate_block_commit_quorum(&block, &policy).unwrap_err();
    match err {
        CommitValidationError::UnauthorizedSigner {
            validator_address_hex,
        } => {
            assert_eq!(validator_address_hex, hex::encode(&outsider));
        }
        other => panic!("expected UnauthorizedSigner, got {other:?}"),
    }
}

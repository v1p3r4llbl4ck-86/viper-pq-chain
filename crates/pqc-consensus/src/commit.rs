// SPDX-License-Identifier: BUSL-1.1
//! Commit material validation for the minimal BFT prototype path.
//!
//! The current prototype does not implement a full multi-round consensus
//! protocol yet, but it does require committed blocks to carry validator
//! signatures that can be checked against a static validator set and an
//! explicit quorum threshold.

use std::collections::HashSet;

use pqc_crypto::{
    sign::{PublicKey, Signature, SignatureVerifier},
    tagged_hash, AlgId, MlDsaVerifier,
};
use pqc_state::StateStore;
use pqc_types::block::{Block, BlockHash};
use pqc_types::ForkDigest;
use thiserror::Error;

use crate::{engine::compute_block_hash, quorum::quorum_size};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitValidator {
    pub node_id: String,
    pub address: Vec<u8>,
    pub sig_alg_id: AlgId,
    pub public_key: Vec<u8>,
}

/// How `commit_signatures` are verified — legacy self-contained preimage
/// vs. the SPEC-CONSENSUS-001 §8.4 Precommit vote preimage (ADR-051).
///
/// Legacy: `"PQC-COMMIT-V1" || height_be64 || block_hash` (pqc-consensus
/// prototype baseline; hash produced by `commit_preimage`).
///
/// Distributed: `SHAKE-256("VIPER-VOTE-V1" || height_be64 || round_be32 ||
/// step_u8 (Precommit=2) || block_hash)` — identical to what
/// `build_signed_precommit` uses for gossiped Precommit votes, so
/// peer-collected precommits are directly usable as CommitSig bytes with
/// zero re-signing. Required for the M2b multi-node BFT path (ADR-051).
/// The round defaults to 0 on the single-round prototype slice; the
/// multi-round finalizer (M2c) will carry per-signature round context
/// via a richer `CommitSig` payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CommitPreimageMode {
    /// Legacy: `"PQC-COMMIT-V1" || height || block_hash`.
    ///
    /// Default mode — preserves byte-stability with every devnet-2 block
    /// already on disk. `distributed_signing = false` in `DevnetConfig`.
    #[default]
    Legacy,
    /// ADR-051: Precommit vote preimage `SHAKE-256("VIPER-VOTE-V1" ||
    /// height || round_be32 || step_u8 (Precommit=2) || block_hash)`. The
    /// `round` is carried inside the variant so the single-round
    /// prototype slice pins it to 0 without adding a separate field at
    /// the `CommitQuorumPolicy` level; M2c generalises.
    Distributed { round: u32 },
}

#[derive(Debug, Clone)]
pub struct CommitQuorumPolicy {
    validators: Vec<CommitValidator>,
    quorum_threshold: usize,
    preimage_mode: CommitPreimageMode,
    fork_digest: ForkDigest,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CommitValidationError {
    #[error("EMPTY_VALIDATOR_SET")]
    EmptyValidatorSet,
    #[error("INVALID_COMMIT_QUORUM_THRESHOLD: quorum {quorum_threshold} is invalid for validator set size {validator_count}")]
    InvalidQuorumThreshold {
        quorum_threshold: usize,
        validator_count: usize,
    },
    #[error("DUPLICATE_VALIDATOR_CONFIG: {validator_address_hex}")]
    DuplicateValidatorConfig { validator_address_hex: String },
    #[error("MISSING_COMMIT_SIGNATURES")]
    MissingCommitSignatures,
    #[error("UNAUTHORIZED_COMMIT_SIGNER: {validator_address_hex}")]
    UnauthorizedSigner { validator_address_hex: String },
    #[error("DUPLICATE_COMMIT_SIGNER: {validator_address_hex}")]
    DuplicateSigner { validator_address_hex: String },
    #[error("INVALID_COMMIT_SIGNATURE: {validator_address_hex}: {detail}")]
    InvalidSignature {
        validator_address_hex: String,
        detail: String,
    },
    #[error("INSUFFICIENT_COMMIT_QUORUM: required {required}, got {got}")]
    InsufficientQuorum { required: usize, got: usize },
}

impl CommitQuorumPolicy {
    pub fn new(
        validators: Vec<CommitValidator>,
        quorum_threshold: Option<usize>,
    ) -> Result<Self, CommitValidationError> {
        if validators.is_empty() {
            return Err(CommitValidationError::EmptyValidatorSet);
        }

        let mut seen = HashSet::new();
        for validator in &validators {
            let key = hex::encode(&validator.address);
            if !seen.insert(key.clone()) {
                return Err(CommitValidationError::DuplicateValidatorConfig {
                    validator_address_hex: key,
                });
            }
        }

        let validator_count = validators.len();
        let quorum_threshold = quorum_threshold.unwrap_or_else(|| quorum_size(validator_count));
        if quorum_threshold == 0 || quorum_threshold > validator_count {
            return Err(CommitValidationError::InvalidQuorumThreshold {
                quorum_threshold,
                validator_count,
            });
        }

        Ok(Self {
            validators,
            quorum_threshold,
            preimage_mode: CommitPreimageMode::Legacy,
            fork_digest: ForkDigest::viper_research_1(),
        })
    }

    /// Override the fork digest used for commit-signature preimages
    /// (ADR-053 §T1.2).
    ///
    /// Defaults to [`ForkDigest::viper_research_1`]. Production callers
    /// that have computed the genesis-derived digest should set it here so
    /// every signature verified under this policy carries the real 4-byte
    /// prefix.
    pub fn with_fork_digest(mut self, fork_digest: ForkDigest) -> Self {
        self.fork_digest = fork_digest;
        self
    }

    pub fn fork_digest(&self) -> &ForkDigest {
        &self.fork_digest
    }

    /// Flip this policy into ADR-051 distributed-signing mode.
    ///
    /// Does NOT change the validator set or threshold — only the preimage
    /// used by `validate_block_commit_quorum`. Producers signing commits
    /// under this policy MUST use the same §8.4 Precommit preimage (via
    /// `build_signed_precommit` or the equivalent helper).
    pub fn with_distributed_preimage(mut self, round: u32) -> Self {
        self.preimage_mode = CommitPreimageMode::Distributed { round };
        self
    }

    pub fn preimage_mode(&self) -> CommitPreimageMode {
        self.preimage_mode
    }

    pub fn validators(&self) -> &[CommitValidator] {
        &self.validators
    }

    pub fn quorum_threshold(&self) -> usize {
        self.quorum_threshold
    }

    pub fn validator_by_address(&self, address: &[u8]) -> Option<&CommitValidator> {
        self.validators
            .iter()
            .find(|validator| validator.address.as_slice() == address)
    }

    /// Build a `CommitQuorumPolicy` from the active validators in the on-chain state.
    ///
    /// Returns `None` if the active validator set is empty (e.g., genesis state before
    /// any validators are registered). Callers should fall back to a static config policy
    /// when `None` is returned.
    ///
    /// This replaces `build_commit_quorum_policy(config)` for nodes that use on-chain
    /// validator staking (TASK-064, GAP-04 closure).
    pub fn from_state_store(
        store: &StateStore,
        quorum_threshold: Option<usize>,
    ) -> Result<Option<Self>, CommitValidationError> {
        let active = store.active_validators();
        if active.is_empty() {
            return Ok(None);
        }

        let validators: Vec<CommitValidator> = active
            .into_iter()
            .map(|record| CommitValidator {
                node_id: record.node_id.clone(),
                address: record.operator.0.to_vec(),
                sig_alg_id: record.consensus_alg_id,
                public_key: record.consensus_pk.clone(),
            })
            .collect();

        CommitQuorumPolicy::new(validators, quorum_threshold).map(Some)
    }
}

/// Domain tag for legacy commit signing preimages — see ADR-053 §T2.4.
pub const LEGACY_COMMIT_DOMAIN_TAG: &[u8] = b"PQC-COMMIT-V1";

/// Legacy commit preimage — ADR-053 §T1.2 adds the 4-byte fork digest prefix
/// so cross-chain replay of a legacy commit signature is impossible, and
/// ADR-053 §T2.4 wraps the result in BIP340-style tagged hashing so a
/// domain-tag collision cannot forge an alternative preimage that the
/// verifier would accept.
///
/// The returned `Vec<u8>` is the 32-byte signed digest (not raw bytes);
/// the caller invokes `ml_dsa_sign` over these 32 bytes directly.
pub fn commit_preimage(fork_digest: &ForkDigest, height: u64, block_hash: &BlockHash) -> Vec<u8> {
    let mut body = Vec::with_capacity(4 + 8 + 32);
    body.extend_from_slice(fork_digest.as_bytes());
    body.extend_from_slice(&height.to_be_bytes());
    body.extend_from_slice(&block_hash.0);
    tagged_hash(LEGACY_COMMIT_DOMAIN_TAG, &body).to_vec()
}

/// Build the preimage the producer/verifier must sign/verify under the
/// current policy mode. Centralised so the producer signing path and
/// `validate_block_commit_quorum` cannot drift (ADR-051 §Decision item 3
/// "producer and verifier build the SAME bytes").
pub fn commit_preimage_for_mode(
    fork_digest: &ForkDigest,
    mode: CommitPreimageMode,
    height: u64,
    block_hash: &BlockHash,
) -> Vec<u8> {
    match mode {
        CommitPreimageMode::Legacy => commit_preimage(fork_digest, height, block_hash),
        CommitPreimageMode::Distributed { round } => {
            // `vote_preimage` returns a 32-byte SHAKE-256 digest — that
            // digest IS the signed bytes (SPEC-CONSENSUS-001 §8.4 step 4
            // "the signature is over the hash output"). Wrap in a Vec so
            // the caller sees a byte-slice-shaped preimage identical to
            // the Legacy path.
            crate::round::vote_preimage(
                fork_digest,
                height,
                round,
                crate::round::VoteStep::Precommit,
                &block_hash.0,
            )
            .to_vec()
        }
    }
}

pub fn validate_block_commit_quorum(
    block: &Block,
    policy: &CommitQuorumPolicy,
) -> Result<(), CommitValidationError> {
    if block.commit_signatures.is_empty() {
        return Err(CommitValidationError::MissingCommitSignatures);
    }

    let verifier = MlDsaVerifier;
    let block_hash = compute_block_hash(block);
    // Legacy mode's preimage is round-independent, so we can hoist the
    // preimage out of the loop. Distributed mode builds per-sig inside
    // the loop — each sig carries its own `round` (§10.1 "Precommits
    // from different rounds MAY be combined") and the signed bytes
    // MUST use THAT sig's round.
    let legacy_preimage = match policy.preimage_mode {
        CommitPreimageMode::Legacy => Some(commit_preimage(
            &policy.fork_digest,
            block.header.height,
            &block_hash,
        )),
        CommitPreimageMode::Distributed { .. } => None,
    };
    let mut unique_signers = HashSet::new();
    let mut valid_commits = 0usize;

    for commit in &block.commit_signatures {
        let signer_hex = hex::encode(&commit.validator_address);
        if !unique_signers.insert(signer_hex.clone()) {
            return Err(CommitValidationError::DuplicateSigner {
                validator_address_hex: signer_hex,
            });
        }

        let Some(validator) = policy.validator_by_address(&commit.validator_address) else {
            return Err(CommitValidationError::UnauthorizedSigner {
                validator_address_hex: signer_hex,
            });
        };

        // ADR-051 / TASK-171 / SPEC-CONSENSUS-001 §10.1: the preimage
        // for a Distributed-mode CommitSig is built from the sig's
        // OWN `round`, not a single policy-level default. This lets
        // the verifier accept precommits from different rounds that
        // all reference the same block_hash — the liveness property
        // the spec mandates under network faults.
        let sig_preimage_storage: Vec<u8>;
        let preimage: &[u8] = match &legacy_preimage {
            Some(p) => p.as_slice(),
            None => {
                sig_preimage_storage = crate::round::vote_preimage(
                    &policy.fork_digest,
                    block.header.height,
                    commit.round,
                    crate::round::VoteStep::Precommit,
                    &block_hash.0,
                )
                .to_vec();
                &sig_preimage_storage
            }
        };

        let public_key = PublicKey {
            alg_id: validator.sig_alg_id,
            bytes: validator.public_key.clone(),
        };
        let signature = Signature {
            alg_id: commit.sig_alg_id,
            bytes: commit.signature.clone(),
        };

        verifier
            .verify(&public_key, preimage, &signature)
            .map_err(|err| CommitValidationError::InvalidSignature {
                validator_address_hex: signer_hex,
                detail: err.to_string(),
            })?;
        valid_commits += 1;
    }

    if valid_commits < policy.quorum_threshold() {
        return Err(CommitValidationError::InsufficientQuorum {
            required: policy.quorum_threshold(),
            got: valid_commits,
        });
    }

    Ok(())
}

#[cfg(test)]
mod m2_dynamic_policy_tests;

#[cfg(test)]
mod byzantine_fault_tests;

#[cfg(test)]
mod adr_051_preimage_mode_tests;

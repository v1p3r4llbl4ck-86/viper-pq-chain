// SPDX-License-Identifier: BUSL-1.1
//! pqc-consensus — Block production and BFT finalization.
//!
//! Phase 1 target: Tendermint/CometBFT-like PoS BFT (ADR-007).
//! 24-validator devnet (ADR-013).
//!
//! Phase 2 path: HotStuff-like once validator set grows.

pub mod archival;
pub mod block_tree_cache;
pub mod chain;
pub mod commit;
pub mod engine;
pub mod epoch;
// Light client lives in its own crate since 2026-08-24 (verifier path must not
// depend on the node core). Re-exported here so existing `pqc_consensus::light_client::…`
// paths keep resolving.
pub use pqc_light_client as light_client;
pub mod proposer;
pub mod quorum;
pub mod reception;
pub mod recovery;
pub mod round;
pub mod storage;
pub mod storage_rocksdb;

#[cfg(test)]
pub(crate) mod test_support;

pub use archival::{
    compute_archival_epoch_root, summarize_closed_epoch, ArchivalEpochSummary,
    ARCHIVAL_EPOCH_ROOT_DOMAIN,
};
pub use block_tree_cache::{
    BlockTreeCache, DEFAULT_CAPACITY as BLOCK_TREE_CACHE_CAPACITY,
    DEFAULT_TTL as BLOCK_TREE_CACHE_TTL,
};
pub use chain::{BlockMetadata, ChainError, ChainStore, StoredBlock};
pub use commit::{
    commit_preimage, commit_preimage_for_mode, validate_block_commit_quorum, CommitPreimageMode,
    CommitQuorumPolicy, CommitValidationError, CommitValidator,
};
pub use engine::{
    assemble_block, compute_block_hash, AssembleError, AssemblyConfig, AssemblyContext,
    BlockExecutionResult, SkipReason, SkippedTx,
};
pub use epoch::{
    advance_randao, epoch_for_height, is_epoch_boundary, select_epoch_proposer, EpochConfig,
    EpochInfo, EPOCH_DURATION_DEVNET, EPOCH_DURATION_MAINNET,
};
pub use pqc_state::FeeDistributionParams;
pub use proposer::{LocalProposer, LocalProposerConfig, ProposedBlock, ProposerError};
pub use quorum::quorum_size;
pub use reception::{classify_incoming_block, BlockReceptionClass, BlockReceptionError};
pub use recovery::{
    recover_tip, replay_blocks_from_genesis, replay_blocks_from_state, verify_chain_consistency,
    ReplayError, ReplayResult,
};
pub use round::{
    proposal_preimage, select_proposer, vote_preimage, ConsensusRound, ConsensusVote,
    EquivocationEvidence, RoundAction, RoundPhase, VoteStep, VoteStore, NIL_HASH,
};
pub use storage::{
    CheckpointRecoveryResult, DiskChainStore, RecoverySource, StorageError,
    TrustedCheckpointMetadata, STATE_FORMAT_VERSION,
};
pub use storage_rocksdb::{PruneStats, RocksDbChainStore};

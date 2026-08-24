// SPDX-License-Identifier: Apache-2.0
//! pqc-types — Core protocol types.
//!
//! Shared data structures derived from the protocol specs. No business logic here —
//! only type definitions and their invariants.

pub mod account;
pub mod archival;
pub mod attestation;
pub mod block;
pub mod churn;
pub mod consensus_msg;
pub mod consensus_rotation;
pub mod fork;
pub mod governance;
pub mod keyset;
pub mod multisig;
pub mod proof_anchor;
pub mod receipt;
pub mod slashing;
pub mod transaction;
pub mod validator;

pub use account::{Account, Address};
pub use archival::{
    decode_archival_record, decode_timestamp_anchor, decode_tsa_ref, decode_validator_archival_key,
    encode_archival_record, encode_timestamp_anchor, encode_tsa_ref, encode_validator_archival_key,
    AnchorKind, ArchivalDecodeError, ArchivalRecord, EpochNumber, TimestampAnchor, TsaRef,
    ValidatorArchivalKey, ARCHIVAL_ALG_ID_SLH_DSA_SHAKE_256S, SLH_DSA_SHAKE_256S_PK_LEN,
    SLH_DSA_SHAKE_256S_SIG_LEN, SLH_DSA_SHAKE_256S_SK_LEN, TIMESTAMP_ANCHOR_EXTERNAL_HASH_MAX_LEN,
};
pub use attestation::{
    attestation_type_name, is_supported_attestation_type, Attestation, AttestationId,
    AttestationRevocation, AttestationStatus,
};
pub use churn::{stake_weighted_activation_limit, stake_weighted_exit_limit, ChurnConfig};
pub use consensus_msg::{
    decode_signed_vote, encode_signed_vote, encode_signed_vote_bytes, SignedVote,
    SignedVoteDecodeError, MSG_TYPE_PRECOMMIT, MSG_TYPE_PREVOTE,
};
pub use consensus_rotation::ConsensusKeyRotation;
pub use fork::{ForkDigest, FORK_DIGEST_DOMAIN, VIPER_FORK_VERSION_V1};
pub use governance::{AddHashProposal, GovernanceProposalType, GovernanceReceipt, PendingUpgrade};
pub use keyset::{KeyEntry, KeySet, KeyStatus};
pub use multisig::{
    MultisigAccountState, MultisigDecodeError, MultisigMember, MultisigPolicy, MultisigWitness,
};
pub use proof_anchor::{claim_type_name, is_supported_claim_type, AnchorId, ProofAnchor};
pub use receipt::{compute_receipts_root, receipt_hash, Receipt};
pub use transaction::{MsgType, Transaction, TxHash};
pub use validator::{
    ValidatorRecord, ValidatorRegisterPayload, ValidatorStatus, VALIDATOR_MAX_ACTIVE_SET_SIZE,
    VALIDATOR_UNBONDING_PERIOD,
};

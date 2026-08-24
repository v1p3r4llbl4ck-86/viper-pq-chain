// SPDX-License-Identifier: BUSL-1.1
//! State transition rejection codes — SPEC-OPS-001 per-operation rejection tables.

use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ApplyError {
    // vault_create
    #[error("ACCOUNT_EXISTS: new_address is already present in chain state")]
    AccountExists,
    #[error("UNSUPPORTED_ALGORITHM: alg_id is inactive or banned in the Algorithm Registry")]
    UnsupportedAlgorithm,
    #[error("INVALID_KEY_PERMISSIONS: SLH-DSA genesis key must have allowed_tx_types = 0x04")]
    InvalidKeyPermissions,
    #[error("INVALID_KEY_SIZE: pk_bytes length does not match expected size for alg_id")]
    InvalidKeySize,
    #[error("INVALID_ACTIVATION_HEIGHT: valid_from_height is before the finalization height")]
    InvalidActivationHeight,

    // token_transfer
    #[error("TRANSFER_AMOUNT_ZERO: transfer amount must be > 0")]
    TransferAmountZero,
    #[error("SELF_TRANSFER: sender and recipient must be different addresses")]
    SelfTransfer,
    #[error("INSUFFICIENT_FUNDS: sender balance cannot cover amount + fees")]
    InsufficientFunds,
    #[error("INVALID_RECIPIENT: recipient address must be 32 bytes")]
    InvalidRecipient,

    // attestation_create
    #[error("ATTESTATION_EXISTS: attestation_id is already present in chain state")]
    AttestationExists,
    #[error("INVALID_ATTESTATION_TYPE: attestation_type is not recognized")]
    InvalidAttestationType,
    #[error("INVALID_HASH: hash field must be exactly 32 bytes")]
    InvalidHash,
    #[error("INVALID_EXPIRY: expires_at_height must be greater than the finalization height")]
    InvalidExpiry,

    // proof_anchor
    #[error("INVALID_CLAIM_TYPE: claim_type is not a recognized Phase 1 value")]
    InvalidClaimType,

    // vault_policy_update
    #[error("POLICY_VERSION_CONFLICT: new policy_version must be strictly greater than the current on-chain policy_version")]
    PolicyVersionConflict,

    // attestation_revoke
    #[error("ATTESTATION_NOT_FOUND: referenced attestation_id does not exist in chain state")]
    AttestationNotFound,
    #[error("ATTESTATION_ALREADY_REVOKED: attestation status is already Revoked")]
    AttestationAlreadyRevoked,
    #[error("UNAUTHORIZED_REVOKER: sender must be the original attester to revoke")]
    UnauthorizedRevoker,

    // key management
    #[error(
        "KEY_VERSION_CONFLICT: key_version must be strictly greater than all existing versions"
    )]
    KeyVersionConflict,
    #[error("KEY_NOT_FOUND: referenced key_version does not exist in the KeySet")]
    KeyNotFound,
    #[error("KEY_ALREADY_REVOKED: referenced key has already been revoked")]
    KeyAlreadyRevoked,
    #[error("INSUFFICIENT_ACTIVE_KEYS: operation would leave the account with zero active keys")]
    InsufficientActiveKeys,
    #[error("INVALID_KEY_ROTATION: rotation payload is not a valid add+revoke combination")]
    InvalidKeyRotation,
    #[error("SIGNER_IS_TARGET: signing key must not revoke itself in key_revoke")]
    SignerIsTarget,

    // consensus_key_rotate / slashing
    #[error("NOT_A_VALIDATOR: address is not a registered validator")]
    NotAValidator,
    #[error("ALGORITHM_NOT_ALLOWED_FOR_CONSENSUS: SLH-DSA and KEM algorithms must not be used for consensus keys")]
    AlgorithmNotAllowedForConsensus,
    #[error("INVALID_ROTATION_HEIGHT: rotation_start_height must be at least current_height + ROTATION_WINDOW")]
    InvalidRotationHeight,
    #[error("CONSENSUS_KEY_CONFLICT: new consensus public key is already registered for another validator")]
    ConsensusKeyConflict,

    // governance / registry update
    #[error(
        "PROPOSAL_OUT_OF_SCOPE: governance payload type is not implemented in this prototype slice"
    )]
    ProposalOutOfScope,
    #[error("INVALID_LIFECYCLE_TRANSITION: algorithm lifecycle transition is not forward-only or not supported in this slice")]
    InvalidLifecycleTransition,
    #[error("GOVERNANCE_NO_EFFECT: proposal does not change lifecycle or min_fee")]
    GovernanceNoEffect,

    // governance AddAlgorithm (ADR-049) + AddSlashingVerifier (ADR-050)
    #[error("ALGORITHM_ALREADY_REGISTERED: alg_id {0:#06x} is already present in the algorithm registry")]
    AlgorithmAlreadyRegistered(u16),
    #[error("RESERVED_ALG_ID_RANGE: alg_id {0:#06x} is in the reserved range 0x0000..=0x000F (core, code-governed)")]
    ReservedAlgIdRange(u16),
    #[error("INVALID_SIZE: pk_size/sig_size must be greater than zero and less than 256 KB")]
    InvalidSize,
    #[error("INVALID_INITIAL_LIFECYCLE: initial lifecycle must be Active or Discouraged")]
    InvalidInitialLifecycle,
    #[error("DUPLICATE_SLASHING_VERIFIER: evidence_type {0:#04x} is already registered")]
    DuplicateSlashingVerifier(u8),
    #[error("RESERVED_SLASHING_EVIDENCE_TYPE: evidence_type {0:#04x} is reserved (0x00 sentinel or 0x01..=0x0F core, code-governed)")]
    ReservedSlashingEvidenceType(u8),
    #[error("INVALID_SLASHING_FRACTION: slash_fraction_bps must be <= 10_000 (100%)")]
    InvalidSlashingFraction,
    #[error("HASH_ALREADY_REGISTERED: hash_id {0:#04x} is already present in the hash registry")]
    HashAlreadyRegistered(u8),
    #[error("RESERVED_HASH_ID_RANGE: hash_id {0:#04x} is reserved (0x00 sentinel or 0x01..=0x0F core, code-governed)")]
    ReservedHashIdRange(u8),

    // validator staking lifecycle (SPEC-VAL-001, TASK-064)
    #[error("VALIDATOR_ALREADY_REGISTERED: operator is already a registered validator")]
    ValidatorAlreadyRegistered,
    #[error("VALIDATOR_NOT_FOUND: sender is not a registered validator")]
    ValidatorNotFound,
    #[error("VALIDATOR_NOT_ACTIVE: validator must be in Active state for this operation")]
    ValidatorNotActive,
    #[error("VALIDATOR_NOT_JAILED: validator must be in Jailed state to unjail")]
    ValidatorNotJailed,
    #[error("VALIDATOR_SET_FULL: active set has reached max_validator_set_size")]
    ValidatorSetFull,
    #[error("VALIDATOR_EXIT_WOULD_EMPTY_SET: exit would leave the active set empty")]
    ValidatorExitWouldEmptySet,
    #[error(
        "ALGORITHM_NOT_ALLOWED_FOR_CONSENSUS_KEY: consensus key must use ML-DSA (SPEC-VAL-001 §4)"
    )]
    AlgorithmNotAllowedForConsensusKey,
    #[error("VALIDATOR_BOND_ZERO: self_bond must be greater than zero")]
    ValidatorBondZero,
    #[error("CONSENSUS_KEY_CONFLICT: consensus public key is already in use by another validator")]
    ValidatorConsensusKeyConflict,

    // validator peer-id binding (ADR-047, TASK-159)
    #[error(
        "VALIDATOR_PEER_ID_TOO_LARGE: peer_id must be a multihash of at most 64 bytes (ADR-047)"
    )]
    ValidatorPeerIdTooLarge,
    #[error("VALIDATOR_PEER_ID_CONFLICT: peer_id is already bound to another validator (ADR-047)")]
    ValidatorPeerIdConflict,
    #[error(
        "VALIDATOR_PEER_ID_EMPTY: ValidatorRotatePeerId requires a non-empty peer_id (ADR-047)"
    )]
    ValidatorPeerIdEmpty,
    #[error("VALIDATOR_NOT_ROTATABLE: ValidatorRotatePeerId sender must be Active, Candidate, or Jailed (ADR-047)")]
    ValidatorPeerIdNotRotatable,

    // equivocation slashing (SPEC-SLASH-001, TASK-097)
    #[error("ALREADY_TOMBSTONED: validator has already been tombstoned for equivocation")]
    AlreadyTombstoned,
    #[error("EVIDENCE_EXPIRED: evidence height is outside the validity window")]
    EvidenceExpired,
    #[error("INVALID_EQUIVOCATION_VOTE: malformed vote in equivocation evidence")]
    InvalidEquivocationVote,
    #[error(
        "EQUIVOCATION_NOT_PROVEN: votes do not prove equivocation (same block hash or both nil)"
    )]
    EquivocationNotProven,
    #[error("EVIDENCE_HEIGHT_MISMATCH: vote heights do not match the evidence height field")]
    EvidenceHeightMismatch,
    #[error("EVIDENCE_ROUND_MISMATCH: votes are at different rounds")]
    EvidenceRoundMismatch,
    #[error("EVIDENCE_STEP_MISMATCH: votes are at different steps")]
    EvidenceStepMismatch,
    #[error("INVALID_SIGNATURE: vote signature failed ML-DSA verification")]
    InvalidSignature,

    // governance multi-step voting (TASK-100)
    #[error("PROPOSAL_NOT_FOUND: referenced proposal_id does not exist")]
    ProposalNotFound,
    #[error("PROPOSAL_NOT_VOTING: proposal is not in Voting status")]
    ProposalNotVoting,
    #[error("VOTING_PERIOD_CLOSED: current height is past the proposal voting deadline")]
    VotingPeriodClosed,
    #[error("ALREADY_VOTED: sender has already voted on this proposal")]
    AlreadyVoted,
    #[error("NOT_AN_ACTIVE_VALIDATOR: only active validators may vote on governance proposals")]
    NotAnActiveValidatorForVote,
    #[error("DUPLICATE_PROPOSAL: a proposal with this id already exists")]
    DuplicateProposal,
    #[error("BURN_RATE_OUT_OF_RANGE: burn_rate_bps must be in 0..=10_000")]
    BurnRateOutOfRange,
    #[error("BLOCK_GAS_LIMIT_ZERO: new_block_gas_limit must be greater than zero")]
    BlockGasLimitZero,

    // archival overlay (SPEC-ARCHIVAL-001 §4.5–§4.7, TASK-161)
    #[error("ARCHIVAL_ALGORITHM_NOT_ALLOWED: archival key algorithm must be SLH-DSA-SHAKE-256s (alg_id 0x0022, SPEC-ARCHIVAL-001 §4.5)")]
    ArchivalAlgorithmNotAllowed,
    #[error("ARCHIVAL_INVALID_PK_SIZE: archival public key must be 64 bytes (SLH-DSA-SHAKE-256s, FIPS 205 Cat 5)")]
    ArchivalInvalidPkSize,
    #[error("ARCHIVAL_VALIDATOR_NOT_ELIGIBLE: sender must be Active or Candidate validator to register an archival key")]
    ArchivalValidatorNotEligible,
    #[error("DUPLICATE_ARCHIVAL_RECORD: an archival record for this epoch_number has already been applied (SPEC-ARCHIVAL-001 §4.6)")]
    DuplicateArchivalRecord,
    #[error("ARCHIVAL_EPOCH_IN_FUTURE: epoch_number must be ≤ current epoch at apply time")]
    ArchivalEpochInFuture,
    #[error("ARCHIVAL_SIGNER_NOT_AUTHORIZED: signer is not a member of the archival signer set (SPEC-ARCHIVAL-001 §4.2)")]
    ArchivalSignerNotAuthorized,
    #[error("ARCHIVAL_THRESHOLD_NOT_MET: verified signatures below m/n threshold (SPEC-ARCHIVAL-001 §4.3)")]
    ArchivalThresholdNotMet,
    #[error("ARCHIVAL_SIGNATURE_INVALID: SLH-DSA-SHAKE-256s signature verification failed")]
    ArchivalSignatureInvalid,
    #[error("ARCHIVAL_MISSING_KEY: signer has no registered archival public key")]
    ArchivalMissingKey,
    #[error("ARCHIVAL_RECORD_NOT_FOUND: referenced epoch_number has no archival record")]
    ArchivalRecordNotFound,
    #[error("ARCHIVAL_UNKNOWN_ANCHOR_KIND: anchor kind not in the AnchorKind enum (SPEC-ARCHIVAL-001 §6.3)")]
    ArchivalUnknownAnchorKind,
    #[error("ARCHIVAL_ANCHOR_TOO_LARGE: external_hash/tst_bytes exceeds the 16 KiB per-anchor sanity cap")]
    ArchivalAnchorTooLarge,
    #[error("ARCHIVAL_NOT_RENEWER: sender must be Active validator or a governance-registered archival_renewer")]
    ArchivalNotRenewer,

    // payload decoding
    #[error("PAYLOAD_DECODE_ERROR: {0}")]
    PayloadDecode(String),

    // tokenless build (viper-research-1, 2026-05-11 pivot)
    #[error("TOKEN_ECONOMICS_DISABLED: operation requires the token_economics feature, which is disabled in this build")]
    TokenEconomicsDisabled,

    // upgrade / migration (ADR-031)
    #[error("MIGRATION_NO_HANDLER: no UpgradeHandler registered for version {from_version} → {to_version}; \
             cannot automatically migrate this node — upgrade the binary or restore from a compatible snapshot")]
    MigrationNoHandler { from_version: u16, to_version: u16 },

    #[error(
        "SOFTWARE_UPGRADE_VERSION_MISMATCH: governance upgrade scheduled at timestamp_ns \
             {activate_at_timestamp_ns} requires STATE_FORMAT_VERSION={expected_version} but this \
             binary reports {actual_version}; upgrade the node binary before the next block"
    )]
    SoftwareUpgradeVersionMismatch {
        activate_at_timestamp_ns: u64,
        expected_version: u16,
        actual_version: u16,
    },
}

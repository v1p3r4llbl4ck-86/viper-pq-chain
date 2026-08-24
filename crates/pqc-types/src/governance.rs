// SPDX-License-Identifier: Apache-2.0
//! Minimal governance types for the Phase 2 prototype slice.

use std::collections::HashMap;

use pqc_crypto::{AlgId, HashId, Lifecycle, SigClass};

use crate::{account::Address, transaction::TxHash};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GovernanceProposalType {
    RegistryUpdate = 0x01,
    BurnRateUpdate = 0x02,
    FeeParamUpdate = 0x03,
    /// ADR-031: coordinated binary upgrade via governance vote.
    SoftwareUpgrade = 0x04,
    /// ADR-049: add a new signature algorithm to the registry at runtime.
    AddAlgorithm = 0x05,
    /// ADR-050: add a new slashing-evidence-type entry to the pluggable
    /// slashing-verifier registry (ADR-042 §16).
    AddSlashingVerifier = 0x06,
    /// ADR-053 §T1.4: add a new hash function to the on-chain hash registry.
    AddHash = 0x07,
    /// ADR-053 §T3.5: add a new auth template to the on-chain auth-template
    /// registry (used by `Account::verifier_template_id`).
    AddAuthTemplate = 0x08,
}

impl GovernanceProposalType {
    pub fn from_u8(raw: u8) -> Option<Self> {
        match raw {
            0x01 => Some(Self::RegistryUpdate),
            0x02 => Some(Self::BurnRateUpdate),
            0x03 => Some(Self::FeeParamUpdate),
            0x04 => Some(Self::SoftwareUpgrade),
            0x05 => Some(Self::AddAlgorithm),
            0x06 => Some(Self::AddSlashingVerifier),
            0x07 => Some(Self::AddHash),
            0x08 => Some(Self::AddAuthTemplate),
            _ => None,
        }
    }

    pub fn as_u8(self) -> u8 {
        match self {
            Self::RegistryUpdate => 0x01,
            Self::BurnRateUpdate => 0x02,
            Self::FeeParamUpdate => 0x03,
            Self::SoftwareUpgrade => 0x04,
            Self::AddAlgorithm => 0x05,
            Self::AddSlashingVerifier => 0x06,
            Self::AddHash => 0x07,
            Self::AddAuthTemplate => 0x08,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::RegistryUpdate => "registry_update",
            Self::BurnRateUpdate => "burn_rate_update",
            Self::FeeParamUpdate => "fee_param_update",
            Self::SoftwareUpgrade => "software_upgrade",
            Self::AddAlgorithm => "add_algorithm",
            Self::AddSlashingVerifier => "add_slashing_verifier",
            Self::AddHash => "add_hash",
            Self::AddAuthTemplate => "add_auth_template",
        }
    }
}

/// Status of a pending governance proposal in its lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProposalStatus {
    Voting,
    Executed,
    Expired,
    Rejected,
    /// Proposal passed tally but the effect could not be applied
    /// (e.g. unknown alg_id in a RegistryUpdate, invalid lifecycle transition).
    /// Serialized as 4 in all storage and leaf-hash contexts.
    ExecutionFailed,
}

/// The on-chain effect to apply when a proposal passes tally.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProposalEffect {
    RegistryUpdate {
        alg_id: AlgId,
        target_lifecycle: Option<Lifecycle>,
        new_min_fee: Option<u64>,
    },
    BurnRateUpdate {
        new_burn_rate_bps: u16,
    },
    FeeParamUpdate {
        new_block_gas_limit: u64,
    },
    /// ADR-031 + ADR-053 §T2.3: schedule a binary upgrade at
    /// `activate_at_timestamp_ns`. When the block-header timestamp first
    /// reaches (or exceeds) the scheduled timestamp, the state layer
    /// verifies that the compiled `STATE_FORMAT_VERSION` equals
    /// `expected_version`; if not it refuses to produce or accept blocks
    /// until the operator upgrades.
    ///
    /// Timestamps rather than heights because block times are variable
    /// under network load — a scheduled height can fire earlier or
    /// later than operators expect in wall-clock seconds, whereas a
    /// `uint64` nanosecond timestamp is unambiguous (the Ethereum
    /// post-Merge upgrade-activation switch was motivated by the same
    /// observation).
    SoftwareUpgrade {
        activate_at_timestamp_ns: u64,
        expected_version: u16,
    },
    /// ADR-049: add a new signature algorithm to the on-chain algorithm
    /// registry.  Execution inserts a fresh `AlgEntry`.  Dispatch-side note:
    /// the `PqVerifier` match is compiled against a fixed list of `AlgId`
    /// variants — a freshly added algorithm will not be *usable* until the
    /// node binary is upgraded to recognize its `AlgId`.  Governance can
    /// reserve the slot and land the metadata in one place; wiring is code.
    AddAlgorithm(AddAlgorithmProposal),
    /// ADR-050 (ADR-042 §16): add a new slashing-evidence-type entry to the
    /// pluggable slashing-verifier registry.  Governance can reserve a slot
    /// and land the metadata; the actual evidence-handler dispatch in
    /// `apply` is still code — new evidence types need a node-software
    /// upgrade to be usable.
    AddSlashingVerifier(SlashingVerifierProposal),
    /// ADR-053 §T1.4: add a new hash function to the on-chain hash registry.
    /// Execution inserts a `HashEntry`. Dispatch on `HashId` is not yet
    /// wired in any call site (launch ships SHAKE-256-only) — a future
    /// `SoftwareUpgrade` activates dispatch for newly governance-reserved
    /// hash ids.
    AddHash(AddHashProposal),
    /// ADR-053 §T3.5: add a new auth template to the on-chain
    /// auth-template registry (used by `Account::verifier_template_id`).
    /// Execution inserts an `AuthTemplateEntry`. Dispatching against a
    /// freshly added template requires a `SoftwareUpgrade` that wires the
    /// template-specific apply-side verifier — governance reserves the
    /// slot and metadata; the verifier code itself is a binary upgrade.
    /// Genesis ships only with `verifier_template_id = 0x0001`
    /// (EOA-equivalent — see [`crate::account::VERIFIER_TEMPLATE_ID_EOA`]).
    AddAuthTemplate(AddAuthTemplateProposal),
}

/// Payload of a governance `AddAlgorithm` proposal — ADR-049.
///
/// Validation at apply-time (see `apply/governance.rs`):
/// - `alg_id` must not already be registered (`AlgorithmAlreadyRegistered`)
/// - `alg_id` must not be in the reserved range `0x0000..=0x000F`
///   (`ReservedAlgIdRange`)
/// - `pk_size` and `sig_size` must be `> 0` and `< 256 KB`
///   (`InvalidSize`)
/// - `initial_lifecycle` must be `Active` or `Discouraged`
///   (`InvalidInitialLifecycle`) — registering a freshly-deprecated or
///   banned algorithm is rejected as a nonsense transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddAlgorithmProposal {
    pub alg_id: u16,
    /// Human-readable spec reference, e.g. `"FIPS 206"`.
    pub spec_ref: String,
    pub pk_size: u32,
    pub sig_size: u32,
    pub sig_class: Option<u8>,
    pub min_fee: u64,
    pub benchmark_verify_per_sec: u32,
    pub initial_lifecycle: Lifecycle,
}

impl AddAlgorithmProposal {
    /// Decode the byte into a `SigClass`.  Returns `None` for unknown bytes.
    pub fn decode_sig_class(raw: u8) -> Option<Option<SigClass>> {
        match raw {
            0 => Some(None),
            1 => Some(Some(SigClass::Reduced)),
            2 => Some(Some(SigClass::Standard)),
            3 => Some(Some(SigClass::Premium)),
            _ => None,
        }
    }
}

/// Payload of a governance `AddAuthTemplate` proposal — ADR-053 §T3.5.
///
/// Validation at apply-time (see `apply/governance.rs`):
/// - `template_id` must not be `0x0000` (sentinel) and must not be in
///   `0x0001..=0x000F` (core, code-governed — see
///   [`crate::account::VERIFIER_TEMPLATE_CORE_RESERVED_MAX`])
///   → `ReservedAuthTemplateRange`
/// - `template_id` must not already be registered →
///   `AuthTemplateAlreadyRegistered`
/// - `lifecycle` must be `Active` or `Discouraged` →
///   `InvalidInitialLifecycle`
///
/// Dispatching against a non-default template at apply-time requires a
/// node-software upgrade that adds a verifier match arm; governance
/// reserves the slot and metadata, the verifier itself is code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddAuthTemplateProposal {
    pub template_id: u16,
    /// Human-readable spec reference, e.g. `"SPEC-MULTISIG-002"`.
    pub spec_ref: String,
    pub lifecycle: Lifecycle,
}

/// Payload of a governance `AddHash` proposal — ADR-053 §T1.4.
///
/// Validation at apply-time (see `apply/governance.rs`):
/// - `hash_id` must not be `0x00` (sentinel) or in `0x01..=0x0F` (core,
///   code-governed) → `ReservedHashIdRange`
/// - `hash_id` must not already be registered → `HashAlreadyRegistered`
/// - `output_size_bytes` must be `> 0` and `< 256 KB` → `InvalidSize`
/// - `initial_lifecycle` must be `Active` or `Discouraged`
///   → `InvalidInitialLifecycle`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddHashProposal {
    pub hash_id: HashId,
    /// Human-readable spec reference, e.g. `"FIPS 202 (SHAKE-256)"`.
    pub spec_ref: String,
    pub output_size_bytes: u32,
    pub initial_lifecycle: Lifecycle,
}

/// Payload of a governance `AddSlashingVerifier` proposal — ADR-050.
///
/// Validation at apply-time:
/// - `evidence_type` must not be `0x00` (invalid sentinel) or in
///   `0x01..=0x0F` (core types, governance cannot override)
///   → `ReservedSlashingEvidenceType`
/// - `evidence_type` must not already be registered
///   → `DuplicateSlashingVerifier`
/// - `slash_fraction_bps` must be ≤ 10_000 → `InvalidSlashingFraction`
/// - `lifecycle` must be `Active` or `Discouraged`
///   → `InvalidInitialLifecycle`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlashingVerifierProposal {
    pub evidence_type: u8,
    pub spec_ref: String,
    pub slash_fraction_bps: u16,
    pub jail_duration_blocks: u64,
    pub tombstone: bool,
    pub lifecycle: Lifecycle,
}

/// A single entry in the on-chain slashing-verifier registry — ADR-050 (ADR-042 §16).
///
/// Keyed by `evidence_type` (u8 discriminant).  At genesis the store seeds
/// entry `0x01` (equivocation) with `slash_fraction_bps = 500` (5%,
/// SPEC-SLASH-001 §10).  Governance can add further entries (data-withholding
/// 0x03, bias-attack 0x04, …) via `ProposalEffect::AddSlashingVerifier`.
/// Core evidence types `0x01..=0x0F` are reserved and cannot be overridden
/// by governance — they can only be added/updated by a coordinated
/// `SoftwareUpgrade` (ADR-031) that adds new match arms in apply logic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlashingVerifierEntry {
    pub evidence_type: u8,
    pub spec_ref: String,
    /// Slash fraction in basis points (500 = 5%).  Read by `apply_submit_*`
    /// at slash time, so governance can tune it over the chain's lifetime.
    /// Falls back to the hardcoded SPEC-SLASH-001 §10 constant when the
    /// registry is empty (e.g. during a migration from a pre-ADR-050
    /// checkpoint).
    pub slash_fraction_bps: u16,
    pub jail_duration_blocks: u64,
    /// Whether the validator is permanently tombstoned on a valid slash.
    /// `true` for equivocation (§9 Step 5); new evidence types may opt for
    /// reversible jailing instead.
    pub tombstone: bool,
    pub lifecycle: Lifecycle,
}

/// A scheduled binary upgrade recorded in state after a `SoftwareUpgrade`
/// governance proposal passes tally.  Stored in `StateStore::pending_upgrades`
/// and included in the state root (ADR-031 + ADR-053 §T2.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingUpgrade {
    /// The governance proposal that created this upgrade.
    pub proposal_id: TxHash,
    /// Wall-clock timestamp (u64 nanoseconds) at which the binary must
    /// be at `expected_version`. Compared against `BlockHeader.timestamp`.
    /// Switched from height to timestamp per ADR-053 §T2.3 because block
    /// times vary under load.
    pub activate_at_timestamp_ns: u64,
    /// The `STATE_FORMAT_VERSION` the upgraded binary must report.
    pub expected_version: u16,
}

/// A governance proposal that is in the voting or post-voting phase.
///
/// Created by `apply_governance_proposal`; updated by `apply_governance_vote`
/// and `process_governance_tallies`. Included in the incremental state root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingProposal {
    pub proposal_id: TxHash,
    pub proposal_type: GovernanceProposalType,
    pub proposer: Address,
    /// Inclusive last block height at which votes are accepted.
    pub voting_deadline: u64,
    /// First block height at which execution is permitted (voting_deadline + timelock).
    pub execute_after: u64,
    pub effect: ProposalEffect,
    /// `true` = yes vote, `false` = no vote. Keyed by voter address.
    pub votes: HashMap<Address, bool>,
    pub status: ProposalStatus,
    pub rationale_hash: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GovernanceReceipt {
    pub proposal_id: TxHash,
    pub proposal_type: GovernanceProposalType,
    pub proposer: Address,
    pub target_alg_id: AlgId,
    pub lifecycle_before: Lifecycle,
    pub lifecycle_after: Lifecycle,
    pub min_fee_before: u64,
    pub min_fee_after: u64,
    pub rationale_hash: [u8; 32],
    pub executed_at_height: u64,
}

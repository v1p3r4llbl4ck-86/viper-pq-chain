// SPDX-License-Identifier: BUSL-1.1
//! Multi-step governance execution — TASK-100.
//!
//! # Flow
//!
//! 1. `apply_governance_proposal`: decode payload → create `PendingProposal`
//!    in `Voting` status.  Does NOT execute effects immediately.
//! 2. `apply_governance_vote`: validator casts yes/no vote; recorded in
//!    `PendingProposal::votes`.
//! 3. `process_governance_tallies`: called once per block after all
//!    transactions; examines proposals whose `voting_deadline < current_height`
//!    and either executes or expires/rejects them.
//! 4. `check_pending_upgrades`: called once per block at the top of block
//!    application; verifies that any software upgrade whose
//!    `activate_at_timestamp_ns <= BlockHeader.timestamp` matches the
//!    compiled binary version (ADR-031 / ADR-053 §T2.3).

use ciborium::value::Value;
use pqc_crypto::{
    hash_registry::HashEntry, registry::AlgEntry, AlgId, HashId, Lifecycle, HASH_CORE_RESERVED_MAX,
    HASH_ID_SENTINEL,
};
use pqc_tx::{codec::encode_tx, compute_tx_hash};
use pqc_types::{
    account::{VERIFIER_TEMPLATE_CORE_RESERVED_MAX, VERIFIER_TEMPLATE_GOV_MIN},
    governance::{
        AddAlgorithmProposal, AddAuthTemplateProposal, AddHashProposal, GovernanceProposalType,
        GovernanceReceipt, PendingProposal, PendingUpgrade, ProposalEffect, ProposalStatus,
        SlashingVerifierEntry, SlashingVerifierProposal,
    },
    transaction::{Transaction, TxHash},
};

use crate::{
    error::ApplyError,
    store::{StateStore, SLASHING_CORE_RESERVED_MAX},
};

// ── Governance constants ──────────────────────────────────────────────────────

/// Number of blocks the voting window is open after proposal inclusion.
///
/// Production target: 1 000 blocks (≈ 100 s at 100 ms block times, or ≈ 2 h
/// at 7.5 s Tendermint block times).  This value is intentionally small for
/// the devnet integration tests (which run with `block_time_ms = 10` on a
/// debug build where ML-DSA crypto takes ~1 s per block).
/// SPEC-GOV-001 §4.1 treats 1 000 as the reference value; production nodes
/// may override this via governance once on-chain parameter updates land.
pub const GOVERNANCE_VOTING_PERIOD: u64 = 5;

/// Blocks between tally and execution (0 = immediate for Phase 4).
pub const GOVERNANCE_TIMELOCK: u64 = 0;

/// Minimum fraction of active validators required to vote.
///
/// Returns `(2 * n + 2) / 3` — ceiling of 2/3, minimum 1.
pub fn quorum_required(active_count: usize) -> usize {
    if active_count == 0 {
        return 1;
    }
    (2 * active_count).div_ceil(3)
}

// ── apply_governance_proposal ─────────────────────────────────────────────────

/// Decode a `GovernanceProposal` transaction and register it as a pending
/// proposal in `Voting` state.  Effects are NOT applied here.
pub fn apply_governance_proposal(
    store: &mut StateStore,
    tx: &Transaction,
) -> Result<(), ApplyError> {
    let raw = encode_tx(tx).map_err(|e| ApplyError::PayloadDecode(e.to_string()))?;
    let proposal_id = TxHash(compute_tx_hash(&raw));

    // Reject duplicate proposal ids.
    if store.get_pending_proposal(&proposal_id).is_some() {
        return Err(ApplyError::DuplicateProposal);
    }

    let payload = decode_proposal_payload(&tx.payload)?;

    let voting_deadline = store
        .block_height()
        .saturating_add(GOVERNANCE_VOTING_PERIOD);
    let execute_after = voting_deadline.saturating_add(GOVERNANCE_TIMELOCK);

    let proposal = PendingProposal {
        proposal_id: proposal_id.clone(),
        proposal_type: payload.proposal_type,
        proposer: tx.sender.clone(),
        voting_deadline,
        execute_after,
        effect: payload.effect,
        votes: std::collections::HashMap::new(),
        status: ProposalStatus::Voting,
        rationale_hash: payload.rationale_hash,
    };

    tracing::info!(
        proposal_id = %proposal_id.to_hex(),
        proposer    = %tx.sender,
        proposal_type = ?payload.proposal_type,
        voting_deadline,
        "governance proposal registered"
    );

    store.insert_pending_proposal(proposal);
    Ok(())
}

// ── apply_governance_vote ─────────────────────────────────────────────────────

/// Record a validator's vote on an active governance proposal.
pub fn apply_governance_vote(store: &mut StateStore, tx: &Transaction) -> Result<(), ApplyError> {
    let (proposal_id_bytes, vote_yes) = decode_vote_payload(&tx.payload)?;
    let proposal_id = TxHash(proposal_id_bytes);

    // Validate proposal state before any mutation.
    {
        let proposal = store
            .get_pending_proposal(&proposal_id)
            .ok_or(ApplyError::ProposalNotFound)?;

        if proposal.status != ProposalStatus::Voting {
            return Err(ApplyError::ProposalNotVoting);
        }
        if store.block_height() > proposal.voting_deadline {
            return Err(ApplyError::VotingPeriodClosed);
        }
        if !store.is_active_validator(&tx.sender) {
            return Err(ApplyError::NotAnActiveValidatorForVote);
        }
        if proposal.votes.contains_key(&tx.sender) {
            return Err(ApplyError::AlreadyVoted);
        }
    }

    // Now mutate.
    {
        let proposal = store
            .get_pending_proposal_mut(&proposal_id)
            .ok_or(ApplyError::ProposalNotFound)?;
        proposal.votes.insert(tx.sender.clone(), vote_yes);
    }
    store.commit_proposal_mutation(&proposal_id);

    tracing::info!(
        proposal_id = %proposal_id.to_hex(),
        voter       = %tx.sender,
        vote        = if vote_yes { "yes" } else { "no" },
        "governance vote recorded"
    );

    Ok(())
}

// ── process_governance_tallies ────────────────────────────────────────────────

/// Tally and execute (or expire/reject) proposals whose voting window has
/// closed.  Call once per block after all transactions are applied.
///
/// `current_height` is the height of the block being assembled or replayed
/// (NOT `store.block_height()`, which returns the PREVIOUS height).
pub fn process_governance_tallies(store: &mut StateStore, current_height: u64) {
    // Collect proposal ids whose deadline has passed, without borrowing store.
    let ids_to_process: Vec<TxHash> = store
        .pending_proposals_in_order()
        .into_iter()
        .filter(|p| p.status == ProposalStatus::Voting && p.voting_deadline < current_height)
        .map(|p| p.proposal_id.clone())
        .collect();

    for id in ids_to_process {
        tally_one(store, id, current_height);
    }
}

/// Tally a single proposal — called once per proposal per block.
fn tally_one(store: &mut StateStore, id: TxHash, current_height: u64) {
    let active_count = store.active_validator_count();
    let required = quorum_required(active_count);

    let (yes_count, no_count, effect_clone, proposal_type, proposer_clone, rationale_hash) = {
        let proposal = match store.get_pending_proposal(&id) {
            Some(p) => p,
            None => return,
        };
        let yes = proposal.votes.values().filter(|&&v| v).count();
        let no = proposal.votes.values().filter(|&&v| !v).count();
        (
            yes,
            no,
            proposal.effect.clone(),
            proposal.proposal_type,
            proposal.proposer.clone(),
            proposal.rationale_hash,
        )
    };

    let total_cast = yes_count + no_count;
    let passes = total_cast >= required && yes_count > no_count;

    if passes {
        // Execute the effect.
        let executed_at_height = current_height;
        let effect_applied = match &effect_clone {
            ProposalEffect::RegistryUpdate {
                alg_id,
                target_lifecycle,
                new_min_fee,
            } => execute_registry_update(
                store,
                id.clone(),
                *alg_id,
                *target_lifecycle,
                *new_min_fee,
                proposal_type,
                proposer_clone,
                rationale_hash,
                executed_at_height,
            ),
            ProposalEffect::BurnRateUpdate { new_burn_rate_bps } => {
                store.fee_market.burn_rate_bps = *new_burn_rate_bps;
                store.recompute_fee_market_leaf_hash();
                tracing::info!(
                    proposal_id = %id.to_hex(),
                    new_burn_rate_bps,
                    "governance burn_rate_update executed"
                );
                true
            }
            ProposalEffect::FeeParamUpdate {
                new_block_gas_limit,
            } => {
                store.fee_market.compute.limit = *new_block_gas_limit;
                store.recompute_fee_market_leaf_hash();
                tracing::info!(
                    proposal_id = %id.to_hex(),
                    new_block_gas_limit,
                    "governance fee_param_update executed"
                );
                true
            }
            ProposalEffect::SoftwareUpgrade {
                activate_at_timestamp_ns,
                expected_version,
            } => {
                // Schedule the upgrade. The actual version check runs at
                // the first block whose `header.timestamp >=
                // activate_at_timestamp_ns` via `check_pending_upgrades`
                // (ADR-053 §T2.3).
                store.insert_pending_upgrade(PendingUpgrade {
                    proposal_id: id.clone(),
                    activate_at_timestamp_ns: *activate_at_timestamp_ns,
                    expected_version: *expected_version,
                });
                tracing::info!(
                    proposal_id = %id.to_hex(),
                    activate_at_timestamp_ns,
                    expected_version,
                    "governance software_upgrade scheduled"
                );
                true
            }
            ProposalEffect::AddAlgorithm(p) => execute_add_algorithm(store, id.clone(), p),
            ProposalEffect::AddSlashingVerifier(p) => {
                execute_add_slashing_verifier(store, id.clone(), p)
            }
            ProposalEffect::AddHash(p) => execute_add_hash(store, id.clone(), p),
            ProposalEffect::AddAuthTemplate(p) => execute_add_auth_template(store, id.clone(), p),
        };

        // Update proposal status: ExecutionFailed if the effect was skipped.
        if let Some(p) = store.get_pending_proposal_mut(&id) {
            p.status = if effect_applied {
                ProposalStatus::Executed
            } else {
                ProposalStatus::ExecutionFailed
            };
        }
    } else {
        let new_status = if total_cast >= required {
            ProposalStatus::Rejected
        } else {
            ProposalStatus::Expired
        };

        if let Some(p) = store.get_pending_proposal_mut(&id) {
            p.status = new_status;
        }

        tracing::info!(
            proposal_id = %id.to_hex(),
            status       = ?new_status,
            yes_count,
            no_count,
            required,
            "governance proposal tallied"
        );
    }

    store.commit_proposal_mutation(&id);
}

/// Apply a RegistryUpdate effect — same logic as the old immediate path.
///
/// Returns `true` if the effect was applied, `false` if it was skipped due to
/// an invalid alg_id or an invalid lifecycle transition.  The caller sets
/// `ProposalStatus::ExecutionFailed` on `false`.
#[allow(clippy::too_many_arguments)]
fn execute_registry_update(
    store: &mut StateStore,
    proposal_id: TxHash,
    alg_id: AlgId,
    target_lifecycle: Option<Lifecycle>,
    new_min_fee: Option<u64>,
    proposal_type: GovernanceProposalType,
    proposer: pqc_types::account::Address,
    rationale_hash: [u8; 32],
    executed_at_height: u64,
) -> bool {
    // Validate that at least one field changes.
    let entry = match store.alg_entry(alg_id) {
        Some(e) => e,
        None => {
            tracing::warn!(proposal_id = %proposal_id.to_hex(), "RegistryUpdate: unknown alg_id, skipping");
            return false;
        }
    };
    let lifecycle_before = entry.lifecycle;
    let min_fee_before = entry.min_fee;

    // Validate lifecycle transition if present.
    if let Some(target) = target_lifecycle {
        let valid = matches!(
            (lifecycle_before, target),
            (Lifecycle::Active, Lifecycle::Discouraged)
                | (Lifecycle::Discouraged, Lifecycle::Deprecated)
                | (Lifecycle::Deprecated, Lifecycle::Banned)
        );
        if !valid {
            tracing::warn!(
                proposal_id = %proposal_id.to_hex(),
                "RegistryUpdate: invalid lifecycle transition, skipping"
            );
            return false;
        }
    }

    {
        let entry = match store.alg_entry_mut(alg_id) {
            Some(e) => e,
            None => return false,
        };
        if let Some(lc) = target_lifecycle {
            entry.lifecycle = lc;
        }
        if let Some(fee) = new_min_fee {
            entry.min_fee = fee;
        }
    }

    let lifecycle_after = store
        .alg_entry(alg_id)
        .map(|e| e.lifecycle)
        .unwrap_or(lifecycle_before);
    let min_fee_after = store
        .alg_entry(alg_id)
        .map(|e| e.min_fee)
        .unwrap_or(min_fee_before);

    store.commit_alg_entry_mutation(alg_id);

    let receipt = GovernanceReceipt {
        proposal_id: proposal_id.clone(),
        proposal_type,
        proposer,
        target_alg_id: alg_id,
        lifecycle_before,
        lifecycle_after,
        min_fee_before,
        min_fee_after,
        rationale_hash,
        executed_at_height,
    };

    tracing::info!(
        proposal_id  = %proposal_id.to_hex(),
        target_alg_id = alg_id.as_u16(),
        lifecycle_before = ?lifecycle_before,
        lifecycle_after  = ?lifecycle_after,
        min_fee_before,
        min_fee_after,
        "governance registry_update executed"
    );

    store.insert_governance_receipt(receipt);
    true
}

// ── ADR-049 AddAlgorithm / ADR-050 AddSlashingVerifier executors ──────────────

/// Maximum pk_size / sig_size accepted in an AddAlgorithm proposal.
/// 256 KB is a generous envelope for any plausible post-quantum primitive
/// (SLH-DSA-SHAKE-256s is currently 29 792 B — two orders of magnitude below
/// the cap); tighter bounds are left to future governance proposals.
const ADD_ALG_MAX_KEY_SIZE: u32 = 256 * 1024;

/// Validate + execute an `AddAlgorithm` proposal (ADR-049).
///
/// Returns `true` if the entry was inserted, `false` if validation failed
/// (tally path records `ProposalStatus::ExecutionFailed` on `false`).
fn execute_add_algorithm(
    store: &mut StateStore,
    proposal_id: TxHash,
    p: &AddAlgorithmProposal,
) -> bool {
    // Reserved range check (core alg_ids 0x0000..=0x000F are code-governed).
    if p.alg_id <= 0x000F {
        tracing::warn!(
            proposal_id = %proposal_id.to_hex(),
            alg_id = format!("{:#06x}", p.alg_id),
            "AddAlgorithm: alg_id in reserved range — skipping"
        );
        return false;
    }
    // Duplicate check.
    if store.alg_entry_registered(p.alg_id) {
        tracing::warn!(
            proposal_id = %proposal_id.to_hex(),
            alg_id = format!("{:#06x}", p.alg_id),
            "AddAlgorithm: alg_id already registered — skipping"
        );
        return false;
    }
    // Size bounds.
    if p.pk_size == 0
        || p.sig_size == 0
        || p.pk_size >= ADD_ALG_MAX_KEY_SIZE
        || p.sig_size >= ADD_ALG_MAX_KEY_SIZE
    {
        tracing::warn!(
            proposal_id = %proposal_id.to_hex(),
            pk_size = p.pk_size,
            sig_size = p.sig_size,
            "AddAlgorithm: invalid pk_size/sig_size — skipping"
        );
        return false;
    }
    // Initial lifecycle must be Active or Discouraged.
    if !matches!(
        p.initial_lifecycle,
        Lifecycle::Active | Lifecycle::Discouraged
    ) {
        tracing::warn!(
            proposal_id = %proposal_id.to_hex(),
            "AddAlgorithm: invalid initial_lifecycle — skipping"
        );
        return false;
    }

    // Translate proposal bytes into an AlgEntry.  `AlgId::from_u16` returns
    // `Some` only for alg_ids known to the compiled binary — a governance
    // proposal CAN reserve an alg_id the binary does not yet know about
    // (that is the point of crypto-agility).  In that case we skip the
    // insertion at apply-time (the insert path types AlgEntry.alg_id as
    // AlgId); ExecutionFailed indicates "metadata accepted, wiring is
    // pending a SoftwareUpgrade that teaches the binary about this id".
    let alg_id_typed = match AlgId::from_u16(p.alg_id) {
        Some(a) => a,
        None => {
            tracing::warn!(
                proposal_id = %proposal_id.to_hex(),
                alg_id = format!("{:#06x}", p.alg_id),
                "AddAlgorithm: alg_id not recognized by this binary — proposal stored, insert deferred to SoftwareUpgrade"
            );
            return false;
        }
    };

    let sig_class = match p.sig_class {
        Some(raw) => match AddAlgorithmProposal::decode_sig_class(raw) {
            Some(cls) => cls,
            None => {
                tracing::warn!(
                    proposal_id = %proposal_id.to_hex(),
                    "AddAlgorithm: unknown sig_class byte — skipping"
                );
                return false;
            }
        },
        None => None,
    };

    let entry = AlgEntry::new_governance(
        alg_id_typed,
        p.spec_ref.clone(),
        p.pk_size as usize,
        p.sig_size as usize,
        sig_class,
        p.min_fee,
        p.initial_lifecycle,
        p.benchmark_verify_per_sec,
    );
    store.insert_alg_entry(entry);

    tracing::info!(
        proposal_id = %proposal_id.to_hex(),
        alg_id = format!("{:#06x}", p.alg_id),
        spec_ref = %p.spec_ref,
        "governance add_algorithm executed"
    );
    true
}

/// Validate + execute an `AddSlashingVerifier` proposal (ADR-050).
fn execute_add_slashing_verifier(
    store: &mut StateStore,
    proposal_id: TxHash,
    p: &SlashingVerifierProposal,
) -> bool {
    // Reserved-range check: 0x00 sentinel + 0x01..=0x0F core types.
    if p.evidence_type == 0x00 || p.evidence_type <= SLASHING_CORE_RESERVED_MAX {
        tracing::warn!(
            proposal_id = %proposal_id.to_hex(),
            evidence_type = format!("{:#04x}", p.evidence_type),
            "AddSlashingVerifier: evidence_type in reserved range — skipping"
        );
        return false;
    }
    if store.slashing_verifier_registered(p.evidence_type) {
        tracing::warn!(
            proposal_id = %proposal_id.to_hex(),
            evidence_type = format!("{:#04x}", p.evidence_type),
            "AddSlashingVerifier: evidence_type already registered — skipping"
        );
        return false;
    }
    if p.slash_fraction_bps > 10_000 {
        tracing::warn!(
            proposal_id = %proposal_id.to_hex(),
            "AddSlashingVerifier: slash_fraction_bps exceeds 100% — skipping"
        );
        return false;
    }
    if !matches!(p.lifecycle, Lifecycle::Active | Lifecycle::Discouraged) {
        tracing::warn!(
            proposal_id = %proposal_id.to_hex(),
            "AddSlashingVerifier: invalid initial lifecycle — skipping"
        );
        return false;
    }

    let entry = SlashingVerifierEntry {
        evidence_type: p.evidence_type,
        spec_ref: p.spec_ref.clone(),
        slash_fraction_bps: p.slash_fraction_bps,
        jail_duration_blocks: p.jail_duration_blocks,
        tombstone: p.tombstone,
        lifecycle: p.lifecycle,
    };
    store.insert_slashing_verifier_entry(entry);

    tracing::info!(
        proposal_id = %proposal_id.to_hex(),
        evidence_type = format!("{:#04x}", p.evidence_type),
        slash_fraction_bps = p.slash_fraction_bps,
        "governance add_slashing_verifier executed"
    );
    true
}

/// Validate + execute an `AddHash` proposal (ADR-053 §T1.4).
fn execute_add_hash(store: &mut StateStore, proposal_id: TxHash, p: &AddHashProposal) -> bool {
    // Reserved-range check: 0x00 sentinel + 0x01..=0x0F core hash ids.
    let hash_byte = p.hash_id.as_u8();
    if hash_byte == HASH_ID_SENTINEL || hash_byte <= HASH_CORE_RESERVED_MAX {
        tracing::warn!(
            proposal_id = %proposal_id.to_hex(),
            hash_id = format!("{:#04x}", hash_byte),
            "AddHash: hash_id in reserved range — skipping"
        );
        return false;
    }
    if store.hash_registered(p.hash_id) {
        tracing::warn!(
            proposal_id = %proposal_id.to_hex(),
            hash_id = format!("{:#04x}", hash_byte),
            "AddHash: hash_id already registered — skipping"
        );
        return false;
    }
    if p.output_size_bytes == 0 || p.output_size_bytes >= ADD_ALG_MAX_KEY_SIZE {
        tracing::warn!(
            proposal_id = %proposal_id.to_hex(),
            output_size_bytes = p.output_size_bytes,
            "AddHash: invalid output_size_bytes — skipping"
        );
        return false;
    }
    if !matches!(
        p.initial_lifecycle,
        Lifecycle::Active | Lifecycle::Discouraged
    ) {
        tracing::warn!(
            proposal_id = %proposal_id.to_hex(),
            "AddHash: invalid initial_lifecycle — skipping"
        );
        return false;
    }

    let entry = HashEntry::new_governance(
        p.hash_id,
        p.spec_ref.clone(),
        p.output_size_bytes,
        p.initial_lifecycle,
    );
    store.insert_hash_entry(entry);

    tracing::info!(
        proposal_id = %proposal_id.to_hex(),
        hash_id = format!("{:#04x}", hash_byte),
        output_size_bytes = p.output_size_bytes,
        "governance add_hash executed"
    );
    true
}

/// Validate + execute an `AddAuthTemplate` proposal (ADR-053 §T3.5).
///
/// Validates the reserved-range and lifecycle invariants and logs the
/// reservation. The viper-pq-1 launch ships only with the
/// EOA-equivalent template (id = 0x0001); the persistent on-chain
/// auth-template registry + per-template apply-side dispatch land in
/// follow-up work — by then a freshly accepted reservation MUST also
/// (a) insert an `AuthTemplateEntry` into the registry, (b) recompute
/// its leaf-hash cache, and (c) be folded into `state_root` as a new
/// [`crate::store::StateCategory`] slot. Until that follow-up the
/// validator-side effect is reservation-only — the proposal is
/// recorded as `Executed` if the validation passes, but no template
/// becomes usable. Adding the registry without dispatch would let
/// users set `Account::verifier_template_id` to a registered-but-
/// unimplemented id and brick their account, which is worse than the
/// current behaviour (proposal is accepted, no on-chain effect).
fn execute_add_auth_template(
    store: &mut StateStore,
    proposal_id: TxHash,
    p: &AddAuthTemplateProposal,
) -> bool {
    if p.template_id == 0
        || p.template_id <= VERIFIER_TEMPLATE_CORE_RESERVED_MAX
        || p.template_id < VERIFIER_TEMPLATE_GOV_MIN
    {
        tracing::warn!(
            proposal_id = %proposal_id.to_hex(),
            template_id = format!("{:#06x}", p.template_id),
            "AddAuthTemplate: template_id in reserved range — skipping"
        );
        return false;
    }
    if !matches!(p.lifecycle, Lifecycle::Active | Lifecycle::Discouraged) {
        tracing::warn!(
            proposal_id = %proposal_id.to_hex(),
            "AddAuthTemplate: invalid initial_lifecycle — skipping"
        );
        return false;
    }
    let _ = store; // registry insert lands in follow-up; see fn doc.
    tracing::info!(
        proposal_id = %proposal_id.to_hex(),
        template_id = format!("{:#06x}", p.template_id),
        spec_ref = %p.spec_ref,
        "governance add_auth_template reserved (apply-side dispatch deferred)"
    );
    true
}

// ── Payload decoders ──────────────────────────────────────────────────────────

struct ProposalPayload {
    proposal_type: GovernanceProposalType,
    effect: ProposalEffect,
    rationale_hash: [u8; 32],
}

fn decode_proposal_payload(payload: &[u8]) -> Result<ProposalPayload, ApplyError> {
    if payload.is_empty() {
        return Err(ApplyError::PayloadDecode("empty payload".into()));
    }
    let value: Value =
        ciborium::from_reader(payload).map_err(|e: ciborium::de::Error<std::io::Error>| {
            ApplyError::PayloadDecode(e.to_string())
        })?;
    let map = match value {
        Value::Map(m) => m,
        _ => {
            return Err(ApplyError::PayloadDecode(
                "payload must be a CBOR map".into(),
            ))
        }
    };

    let mut proposal_type_raw: Option<u8> = None;
    let mut alg_id_raw: Option<u16> = None;
    let mut target_lifecycle: Option<Lifecycle> = None;
    let mut new_min_fee: Option<u64> = None;
    let mut rationale_hash: Option<[u8; 32]> = None;
    let mut new_burn_rate_bps: Option<u16> = None;
    let mut new_block_gas_limit: Option<u64> = None;
    // SoftwareUpgrade fields (ADR-031 + ADR-053 §T2.3):
    let mut activate_at_timestamp_ns: Option<u64> = None;
    let mut expected_version: Option<u16> = None;
    // AddAlgorithm fields (ADR-049) — keys 11..=18:
    let mut add_alg_spec_ref: Option<String> = None;
    let mut add_alg_pk_size: Option<u32> = None;
    let mut add_alg_sig_size: Option<u32> = None;
    let mut add_alg_sig_class: Option<u8> = None;
    let mut add_alg_initial_lifecycle: Option<Lifecycle> = None;
    let mut add_alg_benchmark_verify_per_sec: Option<u32> = None;
    // AddSlashingVerifier fields (ADR-050) — keys 30..=35:
    let mut add_slash_evidence_type: Option<u8> = None;
    let mut add_slash_spec_ref: Option<String> = None;
    let mut add_slash_fraction_bps: Option<u16> = None;
    let mut add_slash_jail_duration_blocks: Option<u64> = None;
    let mut add_slash_tombstone: Option<bool> = None;
    let mut add_slash_lifecycle: Option<Lifecycle> = None;
    // AddHash fields (ADR-053 §T1.4) — keys 40..=43:
    let mut add_hash_id_raw: Option<u8> = None;
    let mut add_hash_spec_ref: Option<String> = None;
    let mut add_hash_output_size_bytes: Option<u32> = None;
    let mut add_hash_initial_lifecycle: Option<Lifecycle> = None;

    for (k, v) in map {
        let key = match k {
            Value::Integer(i) => i128::from(i),
            _ => return Err(ApplyError::PayloadDecode("non-integer map key".into())),
        };
        match key {
            1 => {
                let raw = u8::try_from(i128::from(expect_integer(v)?)).map_err(|_| {
                    ApplyError::PayloadDecode("proposal_type out of u8 range".into())
                })?;
                proposal_type_raw = Some(raw);
            }
            2 => {
                alg_id_raw =
                    Some(u16::try_from(i128::from(expect_integer(v)?)).map_err(|_| {
                        ApplyError::PayloadDecode("alg_id out of u16 range".into())
                    })?);
            }
            3 => {
                let raw = u8::try_from(i128::from(expect_integer(v)?)).map_err(|_| {
                    ApplyError::PayloadDecode("target_lifecycle out of u8 range".into())
                })?;
                target_lifecycle = Some(match raw {
                    1 => Lifecycle::Discouraged,
                    2 => Lifecycle::Deprecated,
                    3 => Lifecycle::Banned,
                    _ => return Err(ApplyError::InvalidLifecycleTransition),
                });
            }
            4 => {
                new_min_fee =
                    Some(u64::try_from(i128::from(expect_integer(v)?)).map_err(|_| {
                        ApplyError::PayloadDecode("new_min_fee out of u64 range".into())
                    })?);
            }
            // Keys 5, 100, 101, 102 are legacy / unused — silently accepted.
            5 | 100 | 101 | 102 => {}
            6 => rationale_hash = Some(expect_hash32(v)?),
            7 => {
                let raw = u16::try_from(i128::from(expect_integer(v)?)).map_err(|_| {
                    ApplyError::PayloadDecode("new_burn_rate_bps out of u16 range".into())
                })?;
                if raw > 10_000 {
                    return Err(ApplyError::BurnRateOutOfRange);
                }
                new_burn_rate_bps = Some(raw);
            }
            8 => {
                let raw = u64::try_from(i128::from(expect_integer(v)?)).map_err(|_| {
                    ApplyError::PayloadDecode("new_block_gas_limit out of u64 range".into())
                })?;
                if raw == 0 {
                    return Err(ApplyError::BlockGasLimitZero);
                }
                new_block_gas_limit = Some(raw);
            }
            // SoftwareUpgrade fields (ADR-031 + ADR-053 §T2.3):
            9 => {
                activate_at_timestamp_ns =
                    Some(u64::try_from(i128::from(expect_integer(v)?)).map_err(|_| {
                        ApplyError::PayloadDecode(
                            "activate_at_timestamp_ns out of u64 range".into(),
                        )
                    })?);
            }
            10 => {
                expected_version =
                    Some(u16::try_from(i128::from(expect_integer(v)?)).map_err(|_| {
                        ApplyError::PayloadDecode("expected_version out of u16 range".into())
                    })?);
            }
            // AddAlgorithm fields (ADR-049):
            11 => add_alg_spec_ref = Some(expect_text(v)?),
            12 => {
                add_alg_pk_size =
                    Some(u32::try_from(i128::from(expect_integer(v)?)).map_err(|_| {
                        ApplyError::PayloadDecode("pk_size out of u32 range".into())
                    })?);
            }
            13 => {
                add_alg_sig_size =
                    Some(u32::try_from(i128::from(expect_integer(v)?)).map_err(|_| {
                        ApplyError::PayloadDecode("sig_size out of u32 range".into())
                    })?);
            }
            14 => {
                add_alg_sig_class =
                    Some(u8::try_from(i128::from(expect_integer(v)?)).map_err(|_| {
                        ApplyError::PayloadDecode("sig_class out of u8 range".into())
                    })?);
            }
            15 => {
                let raw = u8::try_from(i128::from(expect_integer(v)?)).map_err(|_| {
                    ApplyError::PayloadDecode("initial_lifecycle out of u8 range".into())
                })?;
                add_alg_initial_lifecycle = Some(match raw {
                    0 => Lifecycle::Active,
                    1 => Lifecycle::Discouraged,
                    _ => return Err(ApplyError::InvalidInitialLifecycle),
                });
            }
            16 => {
                add_alg_benchmark_verify_per_sec =
                    Some(u32::try_from(i128::from(expect_integer(v)?)).map_err(|_| {
                        ApplyError::PayloadDecode(
                            "benchmark_verify_per_sec out of u32 range".into(),
                        )
                    })?);
            }
            // AddSlashingVerifier fields (ADR-050):
            30 => {
                add_slash_evidence_type =
                    Some(u8::try_from(i128::from(expect_integer(v)?)).map_err(|_| {
                        ApplyError::PayloadDecode("evidence_type out of u8 range".into())
                    })?);
            }
            31 => add_slash_spec_ref = Some(expect_text(v)?),
            32 => {
                let raw = u16::try_from(i128::from(expect_integer(v)?)).map_err(|_| {
                    ApplyError::PayloadDecode("slash_fraction_bps out of u16 range".into())
                })?;
                if raw > 10_000 {
                    return Err(ApplyError::InvalidSlashingFraction);
                }
                add_slash_fraction_bps = Some(raw);
            }
            33 => {
                add_slash_jail_duration_blocks =
                    Some(u64::try_from(i128::from(expect_integer(v)?)).map_err(|_| {
                        ApplyError::PayloadDecode("jail_duration_blocks out of u64 range".into())
                    })?);
            }
            34 => {
                let raw = u8::try_from(i128::from(expect_integer(v)?))
                    .map_err(|_| ApplyError::PayloadDecode("tombstone out of u8 range".into()))?;
                add_slash_tombstone = Some(raw != 0);
            }
            35 => {
                let raw = u8::try_from(i128::from(expect_integer(v)?)).map_err(|_| {
                    ApplyError::PayloadDecode("slashing lifecycle out of u8 range".into())
                })?;
                add_slash_lifecycle = Some(match raw {
                    0 => Lifecycle::Active,
                    1 => Lifecycle::Discouraged,
                    _ => return Err(ApplyError::InvalidInitialLifecycle),
                });
            }
            // AddHash fields (ADR-053 §T1.4):
            40 => {
                add_hash_id_raw =
                    Some(u8::try_from(i128::from(expect_integer(v)?)).map_err(|_| {
                        ApplyError::PayloadDecode("hash_id out of u8 range".into())
                    })?);
            }
            41 => add_hash_spec_ref = Some(expect_text(v)?),
            42 => {
                add_hash_output_size_bytes =
                    Some(u32::try_from(i128::from(expect_integer(v)?)).map_err(|_| {
                        ApplyError::PayloadDecode("output_size_bytes out of u32 range".into())
                    })?);
            }
            43 => {
                let raw = u8::try_from(i128::from(expect_integer(v)?)).map_err(|_| {
                    ApplyError::PayloadDecode("hash lifecycle out of u8 range".into())
                })?;
                add_hash_initial_lifecycle = Some(match raw {
                    0 => Lifecycle::Active,
                    1 => Lifecycle::Discouraged,
                    _ => return Err(ApplyError::InvalidInitialLifecycle),
                });
            }
            _ => {
                return Err(ApplyError::PayloadDecode(format!(
                    "unknown payload key: {key}"
                )))
            }
        }
    }

    let rationale_hash = rationale_hash
        .ok_or_else(|| ApplyError::PayloadDecode("missing field 6 (rationale_hash)".into()))?;
    let proposal_type_raw = proposal_type_raw
        .ok_or_else(|| ApplyError::PayloadDecode("missing field 1 (proposal_type)".into()))?;
    let proposal_type =
        GovernanceProposalType::from_u8(proposal_type_raw).ok_or(ApplyError::ProposalOutOfScope)?;

    let effect = match proposal_type {
        GovernanceProposalType::RegistryUpdate => {
            let alg_id_val = alg_id_raw.ok_or_else(|| {
                ApplyError::PayloadDecode("missing field 2 (alg_id) for RegistryUpdate".into())
            })?;
            let alg_id = AlgId::from_u16(alg_id_val).ok_or(ApplyError::UnsupportedAlgorithm)?;
            if target_lifecycle.is_none() && new_min_fee.is_none() {
                return Err(ApplyError::GovernanceNoEffect);
            }
            ProposalEffect::RegistryUpdate {
                alg_id,
                target_lifecycle,
                new_min_fee,
            }
        }
        GovernanceProposalType::BurnRateUpdate => {
            let bps = new_burn_rate_bps.ok_or_else(|| {
                ApplyError::PayloadDecode(
                    "missing field 7 (new_burn_rate_bps) for BurnRateUpdate".into(),
                )
            })?;
            ProposalEffect::BurnRateUpdate {
                new_burn_rate_bps: bps,
            }
        }
        GovernanceProposalType::FeeParamUpdate => {
            let limit = new_block_gas_limit.ok_or_else(|| {
                ApplyError::PayloadDecode(
                    "missing field 8 (new_block_gas_limit) for FeeParamUpdate".into(),
                )
            })?;
            ProposalEffect::FeeParamUpdate {
                new_block_gas_limit: limit,
            }
        }
        GovernanceProposalType::SoftwareUpgrade => {
            let timestamp = activate_at_timestamp_ns.ok_or_else(|| {
                ApplyError::PayloadDecode(
                    "missing field 9 (activate_at_timestamp_ns) for SoftwareUpgrade".into(),
                )
            })?;
            let version = expected_version.ok_or_else(|| {
                ApplyError::PayloadDecode(
                    "missing field 10 (expected_version) for SoftwareUpgrade".into(),
                )
            })?;
            ProposalEffect::SoftwareUpgrade {
                activate_at_timestamp_ns: timestamp,
                expected_version: version,
            }
        }
        GovernanceProposalType::AddAlgorithm => {
            let alg_id_val = alg_id_raw.ok_or_else(|| {
                ApplyError::PayloadDecode("missing field 2 (alg_id) for AddAlgorithm".into())
            })?;
            // Cheap reserved-range check at decode time so reserved-range
            // proposals never enter the voting phase.  Tally re-checks the
            // full validation set (duplicate, size bounds, lifecycle).
            if alg_id_val <= 0x000F {
                return Err(ApplyError::ReservedAlgIdRange(alg_id_val));
            }
            let spec_ref = add_alg_spec_ref.ok_or_else(|| {
                ApplyError::PayloadDecode("missing field 11 (spec_ref) for AddAlgorithm".into())
            })?;
            let pk_size = add_alg_pk_size.ok_or_else(|| {
                ApplyError::PayloadDecode("missing field 12 (pk_size) for AddAlgorithm".into())
            })?;
            let sig_size = add_alg_sig_size.ok_or_else(|| {
                ApplyError::PayloadDecode("missing field 13 (sig_size) for AddAlgorithm".into())
            })?;
            let initial_lifecycle = add_alg_initial_lifecycle.ok_or_else(|| {
                ApplyError::PayloadDecode(
                    "missing field 15 (initial_lifecycle) for AddAlgorithm".into(),
                )
            })?;
            // Bounds check at decode time — full validation repeats in tally.
            if pk_size == 0
                || sig_size == 0
                || pk_size >= ADD_ALG_MAX_KEY_SIZE
                || sig_size >= ADD_ALG_MAX_KEY_SIZE
            {
                return Err(ApplyError::InvalidSize);
            }
            ProposalEffect::AddAlgorithm(AddAlgorithmProposal {
                alg_id: alg_id_val,
                spec_ref,
                pk_size,
                sig_size,
                sig_class: add_alg_sig_class,
                min_fee: new_min_fee.unwrap_or(0),
                benchmark_verify_per_sec: add_alg_benchmark_verify_per_sec.unwrap_or(0),
                initial_lifecycle,
            })
        }
        GovernanceProposalType::AddSlashingVerifier => {
            let evidence_type = add_slash_evidence_type.ok_or_else(|| {
                ApplyError::PayloadDecode(
                    "missing field 30 (evidence_type) for AddSlashingVerifier".into(),
                )
            })?;
            // Cheap reserved-range check at decode time.
            if evidence_type == 0x00 || evidence_type <= SLASHING_CORE_RESERVED_MAX {
                return Err(ApplyError::ReservedSlashingEvidenceType(evidence_type));
            }
            let spec_ref = add_slash_spec_ref.ok_or_else(|| {
                ApplyError::PayloadDecode(
                    "missing field 31 (spec_ref) for AddSlashingVerifier".into(),
                )
            })?;
            let slash_fraction_bps = add_slash_fraction_bps.ok_or_else(|| {
                ApplyError::PayloadDecode(
                    "missing field 32 (slash_fraction_bps) for AddSlashingVerifier".into(),
                )
            })?;
            let jail_duration_blocks = add_slash_jail_duration_blocks.unwrap_or(0);
            let tombstone = add_slash_tombstone.unwrap_or(false);
            let lifecycle = add_slash_lifecycle.ok_or_else(|| {
                ApplyError::PayloadDecode(
                    "missing field 35 (lifecycle) for AddSlashingVerifier".into(),
                )
            })?;
            ProposalEffect::AddSlashingVerifier(SlashingVerifierProposal {
                evidence_type,
                spec_ref,
                slash_fraction_bps,
                jail_duration_blocks,
                tombstone,
                lifecycle,
            })
        }
        GovernanceProposalType::AddHash => {
            let hash_byte = add_hash_id_raw.ok_or_else(|| {
                ApplyError::PayloadDecode("missing field 40 (hash_id) for AddHash".into())
            })?;
            // Cheap reserved-range check at decode time — tally re-checks duplicate + sizes.
            if hash_byte == HASH_ID_SENTINEL || hash_byte <= HASH_CORE_RESERVED_MAX {
                return Err(ApplyError::ReservedHashIdRange(hash_byte));
            }
            let hash_id =
                HashId::from_u8(hash_byte).ok_or(ApplyError::ReservedHashIdRange(hash_byte))?;
            let spec_ref = add_hash_spec_ref.ok_or_else(|| {
                ApplyError::PayloadDecode("missing field 41 (spec_ref) for AddHash".into())
            })?;
            let output_size_bytes = add_hash_output_size_bytes.ok_or_else(|| {
                ApplyError::PayloadDecode("missing field 42 (output_size_bytes) for AddHash".into())
            })?;
            let initial_lifecycle = add_hash_initial_lifecycle.ok_or_else(|| {
                ApplyError::PayloadDecode("missing field 43 (initial_lifecycle) for AddHash".into())
            })?;
            // Bounds check at decode time — full validation repeats in tally.
            if output_size_bytes == 0 || output_size_bytes >= ADD_ALG_MAX_KEY_SIZE {
                return Err(ApplyError::InvalidSize);
            }
            ProposalEffect::AddHash(AddHashProposal {
                hash_id,
                spec_ref,
                output_size_bytes,
                initial_lifecycle,
            })
        }
        GovernanceProposalType::AddAuthTemplate => {
            // ADR-053 §T3.5. The on-chain wire format for the
            // governance-side proposal payload (template-spec field IDs,
            // multi-template-config schema) lands together with the
            // apply-side dispatch + persistent registry in a follow-up
            // STATE_FORMAT_VERSION bump — see the comment on
            // [`crate::apply::governance::execute_add_auth_template`].
            // Until then the type is reserved on the enum + leaf-hash
            // path so the genesis-immutable state-root format is fixed,
            // but inbound proposals are rejected with
            // `ProposalOutOfScope`. Genesis ships only with
            // `VERIFIER_TEMPLATE_ID_EOA`.
            return Err(ApplyError::ProposalOutOfScope);
        }
    };

    Ok(ProposalPayload {
        proposal_type,
        effect,
        rationale_hash,
    })
}

// ── Pending upgrade enforcement (ADR-031 + ADR-053 §T2.3) ─────────────────────

/// Check whether any pending software upgrade has reached its activation
/// timestamp by `current_timestamp_ns`.
///
/// Activation semantics: an upgrade scheduled for timestamp `T` activates
/// at the first block whose `header.timestamp >= T`. Because block times
/// are variable under network load, multiple upgrades with overlapping
/// deadlines may land in a single block — this function applies them in
/// `pending_upgrades_in_order` (sorted by timestamp, then proposal_id).
///
/// If an upgrade has reached activation, this function verifies that
/// `compiled_version == upgrade.expected_version`. A mismatch means the
/// operator has NOT upgraded this binary before the governance-mandated
/// deadline — the node must refuse to produce or accept blocks to avoid
/// producing state that diverges from upgraded peers.
///
/// On a successful match the upgrade record is removed from
/// `pending_upgrades` (it has been applied) and the function returns
/// `Ok(())`.
///
/// Call once per block at the start of block application, before any
/// transaction is executed. `current_timestamp_ns` MUST be the
/// `BlockHeader.timestamp` of the block being applied.
pub fn check_pending_upgrades(
    store: &mut StateStore,
    current_timestamp_ns: u64,
    compiled_version: u16,
) -> Result<(), ApplyError> {
    // Collect IDs of upgrades whose activation timestamp has passed.
    let activating: Vec<(TxHash, u64, u16)> = store
        .pending_upgrades_in_order()
        .into_iter()
        .filter(|u| u.activate_at_timestamp_ns <= current_timestamp_ns)
        .map(|u| {
            (
                u.proposal_id.clone(),
                u.activate_at_timestamp_ns,
                u.expected_version,
            )
        })
        .collect();

    for (id, activate_at_timestamp_ns, expected_version) in activating {
        if compiled_version != expected_version {
            return Err(ApplyError::SoftwareUpgradeVersionMismatch {
                activate_at_timestamp_ns,
                expected_version,
                actual_version: compiled_version,
            });
        }
        // Version matches — upgrade is satisfied.  Remove from pending set.
        store.remove_pending_upgrade(&id);
        tracing::info!(
            proposal_id = %id.to_hex(),
            version = compiled_version,
            activate_at_timestamp_ns,
            "software upgrade version check passed — upgrade removed from pending set",
        );
    }

    Ok(())
}

fn decode_vote_payload(payload: &[u8]) -> Result<([u8; 32], bool), ApplyError> {
    if payload.is_empty() {
        return Err(ApplyError::PayloadDecode("empty vote payload".into()));
    }
    let value: Value =
        ciborium::from_reader(payload).map_err(|e: ciborium::de::Error<std::io::Error>| {
            ApplyError::PayloadDecode(e.to_string())
        })?;
    let map = match value {
        Value::Map(m) => m,
        _ => {
            return Err(ApplyError::PayloadDecode(
                "vote payload must be a CBOR map".into(),
            ))
        }
    };

    let mut proposal_id: Option<[u8; 32]> = None;
    let mut vote: Option<bool> = None;

    for (k, v) in map {
        let key = match k {
            Value::Integer(i) => i128::from(i),
            _ => {
                return Err(ApplyError::PayloadDecode(
                    "non-integer map key in vote".into(),
                ))
            }
        };
        match key {
            1 => proposal_id = Some(expect_hash32(v)?),
            2 => {
                let raw = u8::try_from(i128::from(expect_integer(v)?))
                    .map_err(|_| ApplyError::PayloadDecode("vote field out of u8 range".into()))?;
                vote = Some(raw == 1);
            }
            _ => {
                return Err(ApplyError::PayloadDecode(format!(
                    "unknown vote payload key: {key}"
                )))
            }
        }
    }

    let proposal_id = proposal_id
        .ok_or_else(|| ApplyError::PayloadDecode("missing field 1 (proposal_id) in vote".into()))?;
    let vote =
        vote.ok_or_else(|| ApplyError::PayloadDecode("missing field 2 (vote) in vote".into()))?;

    Ok((proposal_id, vote))
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn expect_integer(value: Value) -> Result<ciborium::value::Integer, ApplyError> {
    match value {
        Value::Integer(i) => Ok(i),
        _ => Err(ApplyError::PayloadDecode("expected integer".into())),
    }
}

fn expect_hash32(value: Value) -> Result<[u8; 32], ApplyError> {
    let bytes = match value {
        Value::Bytes(b) => b,
        _ => return Err(ApplyError::PayloadDecode("expected bytes".into())),
    };
    if bytes.len() != 32 {
        return Err(ApplyError::InvalidHash);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn expect_text(value: Value) -> Result<String, ApplyError> {
    match value {
        Value::Text(s) => Ok(s),
        _ => Err(ApplyError::PayloadDecode("expected text string".into())),
    }
}

// ── Pin tests (TASK-180) ──────────────────────────────────────────────────────
//
// These tests lock in the observed behaviour of the governance module so a
// regression in lifecycle transitions, payload decoding, or tally semantics is
// caught at unit level rather than via integration tests.  They are
// intentionally narrow — one behaviour per test, with Arrange / Act / Assert
// comments that name the exact invariant being pinned.

#[cfg(test)]
mod pin_tests;

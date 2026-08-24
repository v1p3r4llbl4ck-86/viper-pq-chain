// SPDX-License-Identifier: BUSL-1.1
//! Per-StateCategory leaf-hash helpers used by `StateStore::state_root`.
//!
//! Extracted from `store.rs` 2026-05-10. 18 `compute_*_leaf_hash`
//! private helpers, one per StateCategory variant. Each fn mirrors a
//! V1 serialisation format and tags it with a per-category domain
//! separator so no two entity kinds can collide at the leaf level.
//!
//! `use super::*;` brings every type alias / struct / const referenced
//! by the leaf bodies into scope (Account, Attestation, AlgEntry,
//! ProofAnchor, ConsensusKeyRotation, GovernanceReceipt, ValidatorRecord,
//! StorageFundState, FeeMarketState, RecentSlashEntry, PendingProposal,
//! PendingUpgrade, HashEntry, SlashingVerifierEntry, plus the
//! TaggedHasher wrapper). The parent re-exports via `use state_merkle::*;`
//! so impl-StateStore call sites keep their original call shape.

use super::*;

// ── Leaf hash computation — mirrors the V1 serialization format for each entity ──
//
// These are private helpers. The domain separator per entity type ensures no two
// entity kinds can produce the same leaf hash for different data.

pub(super) fn compute_account_leaf_hash(account: &Account) -> [u8; 32] {
    use pqc_types::keyset::KeyStatus;
    let mut d = TaggedHasher::new(b"PQC-ACCOUNT-LEAF-V1");
    d.push_chunk(account.address.as_bytes());
    d.push_chunk(&account.balance.to_be_bytes());
    d.push_chunk(&account.nonce.to_be_bytes());
    let mut keys: Vec<_> = account.keys.0.iter().collect();
    keys.sort_by_key(|k| k.key_version);
    d.push_u64(keys.len() as u64);
    for key in keys {
        d.push_chunk(&key.alg_id.as_u16().to_be_bytes());
        d.push_chunk(&key.key_version.to_be_bytes());
        d.push_chunk(&key.valid_from_height.to_be_bytes());
        d.push_chunk(&[match key.status {
            KeyStatus::Pending => 0,
            KeyStatus::Active => 1,
            KeyStatus::Revoked => 2,
        }]);
        d.push_chunk(&key.allowed_tx_types.to_be_bytes());
        d.push_chunk(&key.pk_bytes);
    }
    d.push_chunk(&account.policy_version.to_be_bytes());
    match account.policy_hash {
        Some(h) => {
            d.push_chunk(&[1]);
            d.push_chunk(&h);
        }
        None => d.push_chunk(&[0]),
    }
    // ADR-053 §T3.5: unified smart-account model. Folded into the leaf hash
    // so a template change OR an auth_data update flows into state_root.
    d.push_chunk(&account.verifier_template_id.to_be_bytes());
    d.push_chunk(&account.auth_data);
    d.finish()
}

pub(super) fn compute_attestation_leaf_hash(attestation: &Attestation) -> [u8; 32] {
    use pqc_types::attestation::AttestationStatus;
    let mut d = TaggedHasher::new(b"PQC-ATTESTATION-LEAF-V1");
    d.push_chunk(&attestation.attestation_id.0);
    d.push_chunk(attestation.attester.as_bytes());
    d.push_chunk(&attestation.subject);
    d.push_chunk(&attestation.attestation_type.to_be_bytes());
    d.push_chunk(&attestation.content_hash);
    d.push_chunk(&attestation.schema_id);
    match attestation.metadata_hash {
        Some(h) => {
            d.push_chunk(&[1]);
            d.push_chunk(&h);
        }
        None => d.push_chunk(&[0]),
    }
    d.push_chunk(&attestation.anchor_height.to_be_bytes());
    match attestation.expires_at_height {
        Some(h) => {
            d.push_chunk(&[1]);
            d.push_chunk(&h.to_be_bytes());
        }
        None => d.push_chunk(&[0]),
    }
    d.push_chunk(&[match attestation.status {
        AttestationStatus::Active => 0,
        AttestationStatus::Revoked => 1,
    }]);
    match &attestation.revocation {
        Some(rev) => {
            d.push_chunk(&[1]);
            d.push_chunk(&rev.revoked_at_height.to_be_bytes());
            d.push_chunk(rev.revoker.as_bytes());
            match rev.revocation_reason_hash {
                Some(h) => {
                    d.push_chunk(&[1]);
                    d.push_chunk(&h);
                }
                None => d.push_chunk(&[0]),
            }
        }
        None => d.push_chunk(&[0]),
    }
    d.finish()
}

pub(super) fn compute_alg_leaf_hash(entry: &AlgEntry) -> [u8; 32] {
    use pqc_crypto::{Lifecycle, SigClass};
    let mut d = TaggedHasher::new(b"PQC-ALG-LEAF-V1");
    d.push_chunk(&entry.alg_id.as_u16().to_be_bytes());
    d.push_chunk(entry.spec_ref.as_bytes());
    d.push_u64(entry.pk_size as u64);
    d.push_u64(entry.sig_size as u64);
    d.push_chunk(&entry.min_fee.to_be_bytes());
    d.push_chunk(&[match entry.lifecycle {
        Lifecycle::Active => 0,
        Lifecycle::Discouraged => 1,
        Lifecycle::Deprecated => 2,
        Lifecycle::Banned => 3,
    }]);
    d.push_chunk(&[match entry.sig_class {
        Some(SigClass::Reduced) => 1,
        Some(SigClass::Standard) => 2,
        Some(SigClass::Premium) => 3,
        None => 0,
    }]);
    d.push_chunk(&entry.benchmark_verify_per_sec.to_be_bytes());
    d.finish()
}

pub(super) fn compute_proof_anchor_leaf_hash(anchor: &ProofAnchor) -> [u8; 32] {
    let mut d = TaggedHasher::new(b"PQC-PROOF-ANCHOR-LEAF-V1");
    d.push_chunk(&anchor.anchor_id.0);
    d.push_chunk(anchor.claimer.as_bytes());
    d.push_chunk(&anchor.claim_type.to_be_bytes());
    d.push_chunk(&anchor.asset_id_hash);
    d.push_chunk(&anchor.proof_hash);
    match anchor.schema_id {
        Some(s) => {
            d.push_chunk(&[1]);
            d.push_chunk(&s);
        }
        None => d.push_chunk(&[0]),
    }
    d.push_chunk(&anchor.anchor_height.to_be_bytes());
    d.finish()
}

pub(super) fn compute_consensus_rotation_leaf_hash(rotation: &ConsensusKeyRotation) -> [u8; 32] {
    let mut d = TaggedHasher::new(b"PQC-CONSENSUS-ROTATE-LEAF-V1");
    d.push_chunk(rotation.operator.as_bytes());
    d.push_chunk(&rotation.new_alg_id.as_u16().to_be_bytes());
    d.push_chunk(&(rotation.new_pk_bytes.len() as u64).to_be_bytes());
    d.push_chunk(&rotation.new_pk_bytes);
    d.push_chunk(&rotation.rotation_start_height.to_be_bytes());
    d.push_chunk(&rotation.recorded_at_height.to_be_bytes());
    d.finish()
}

pub(super) fn compute_receipt_leaf_hash(receipt: &GovernanceReceipt) -> [u8; 32] {
    use pqc_crypto::Lifecycle;
    let mut d = TaggedHasher::new(b"PQC-RECEIPT-LEAF-V1");
    d.push_chunk(&receipt.proposal_id.0);
    d.push_chunk(&[receipt.proposal_type.as_u8()]);
    d.push_chunk(receipt.proposer.as_bytes());
    d.push_chunk(&receipt.target_alg_id.as_u16().to_be_bytes());
    d.push_chunk(&[match receipt.lifecycle_before {
        Lifecycle::Active => 0,
        Lifecycle::Discouraged => 1,
        Lifecycle::Deprecated => 2,
        Lifecycle::Banned => 3,
    }]);
    d.push_chunk(&[match receipt.lifecycle_after {
        Lifecycle::Active => 0,
        Lifecycle::Discouraged => 1,
        Lifecycle::Deprecated => 2,
        Lifecycle::Banned => 3,
    }]);
    d.push_chunk(&receipt.min_fee_before.to_be_bytes());
    d.push_chunk(&receipt.min_fee_after.to_be_bytes());
    d.push_chunk(&receipt.rationale_hash);
    d.push_chunk(&receipt.executed_at_height.to_be_bytes());
    d.finish()
}

/// Leaf hash for a single on-chain PeerId binding — ADR-047, D-03, TASK-159.
///
/// Domain separator: `"PQC-PEER-ID-BINDING-LEAF-V1"`. Each binding is an
/// independent leaf so rotating one binding only recomputes that one hash.
/// Empty peer_id is never representable — callers never store an empty binding.
pub(super) fn compute_peer_id_binding_leaf_hash(operator: &Address, peer_id: &[u8]) -> [u8; 32] {
    let mut d = TaggedHasher::new(b"PQC-PEER-ID-BINDING-LEAF-V1");
    d.push_chunk(operator.as_bytes());
    d.push_u64(peer_id.len() as u64);
    d.push_chunk(peer_id);
    d.finish()
}

pub(super) fn compute_validator_leaf_hash(record: &ValidatorRecord) -> [u8; 32] {
    let mut d = TaggedHasher::new(b"PQC-VALIDATOR-LEAF-V1");
    d.push_chunk(record.operator.as_bytes());
    d.push_chunk(record.node_id.as_bytes());
    d.push_chunk(&record.consensus_alg_id.as_u16().to_be_bytes());
    d.push_u64(record.consensus_pk.len() as u64);
    d.push_chunk(&record.consensus_pk);
    d.push_chunk(&record.self_bond.to_be_bytes());
    d.push_chunk(&record.registered_height.to_be_bytes());
    d.push_chunk(&[match &record.status {
        ValidatorStatus::Candidate => 0,
        ValidatorStatus::Active => 1,
        ValidatorStatus::Jailed => 2,
        ValidatorStatus::Unbonding { .. } => 3,
        ValidatorStatus::Exited => 4,
    }]);
    if let ValidatorStatus::Unbonding { start_height } = &record.status {
        d.push_chunk(&start_height.to_be_bytes());
    }
    // F-001: include tombstoned flag in leaf hash so the state root commits
    // to the tombstone state. Without this, two validators differing only in
    // tombstoned would produce identical leaf hashes and state roots.
    d.push_chunk(&[if record.tombstoned { 1u8 } else { 0u8 }]);
    d.finish()
}

/// Leaf hash for the storage fund — ADR-053 §T2.2.
///
/// Domain separator: `"VIPER-STORAGE-FUND-V1"`. Field order:
/// `balance (u128) || perpetual_cost_per_byte (u64) || rebate_fraction_bps (u16, widened to u64)`.
/// Any reordering or addition breaks replay determinism and requires
/// an ADR per P-COMPAT-001.
///
/// Elided in tokenless builds — viper-research-1 has no storage_fund
/// at all, neither in StateStore nor in state_root.
#[cfg(feature = "token_economics")]
pub(super) fn compute_storage_fund_leaf_hash(
    fund: &crate::storage_fund::StorageFundState,
) -> [u8; 32] {
    let mut d = TaggedHasher::new(b"VIPER-STORAGE-FUND-V1");
    d.push_chunk(&fund.balance.to_be_bytes());
    d.push_chunk(&fund.perpetual_cost_per_byte.to_be_bytes());
    d.push_chunk(&(fund.rebate_fraction_bps as u64).to_be_bytes());
    d.finish()
}

/// Leaf hash for the multi-dimensional fee market state — SPEC-FEE-002
/// revised §10 + ADR-053 §T2.1.
///
/// Domain separator: `"VIPER-FEE-MARKET-V1"`. Changing this string, the
/// field order, or the hash algorithm breaks replay determinism and
/// requires a new ADR. The four dimensions are absorbed in fixed order
/// (compute → storage → witness → contention); within each dimension
/// the field order is `base_fee, limit, target, excess, reserve_floor,
/// update_fraction` — all u64 big-endian.
pub(super) fn compute_fee_market_leaf_hash(state: &FeeMarketState) -> [u8; 32] {
    fn push_dim(d: &mut TaggedHasher, dim: &FeeMarketDimension) {
        d.push_chunk(&dim.base_fee.to_be_bytes());
        d.push_chunk(&dim.limit.to_be_bytes());
        d.push_chunk(&dim.target.to_be_bytes());
        d.push_chunk(&dim.excess.to_be_bytes());
        d.push_chunk(&dim.reserve_floor.to_be_bytes());
        d.push_chunk(&dim.update_fraction.to_be_bytes());
    }
    let mut d = TaggedHasher::new(b"VIPER-FEE-MARKET-V1");
    push_dim(&mut d, &state.compute);
    push_dim(&mut d, &state.storage);
    push_dim(&mut d, &state.witness);
    push_dim(&mut d, &state.contention);
    d.push_chunk(&(state.burn_rate_bps as u64).to_be_bytes());
    d.finish()
}

/// Leaf hash for the sliding-window correlation penalty ledger — ADR-048.
///
/// Domain separator: `"VIPER-RECENT-SLASHES-V1"`. Any change to the encoding
/// breaks replay determinism and requires a new ADR + state-format bump.
pub(super) fn compute_recent_slashes_leaf_hash(entries: &VecDeque<RecentSlashEntry>) -> [u8; 32] {
    let mut d = TaggedHasher::new(b"VIPER-RECENT-SLASHES-V1");
    d.push_u64(entries.len() as u64);
    for entry in entries {
        d.push_chunk(&entry.height.to_be_bytes());
        d.push_chunk(&entry.slashed_stake.to_be_bytes());
    }
    d.finish()
}

/// Leaf hash for a pending governance proposal — TASK-100.
///
/// Domain separator: `"PQC-PROPOSAL-LEAF-V1"`. Any change to the field
/// order or hash algorithm breaks replay determinism and requires an ADR.
pub(super) fn compute_proposal_leaf_hash(proposal: &PendingProposal) -> [u8; 32] {
    let mut d = TaggedHasher::new(b"PQC-PROPOSAL-LEAF-V1");
    d.push_chunk(&proposal.proposal_id.0);
    d.push_chunk(&[proposal.proposal_type.as_u8()]);
    d.push_chunk(&[match proposal.status {
        ProposalStatus::Voting => 0,
        ProposalStatus::Executed => 1,
        ProposalStatus::Expired => 2,
        ProposalStatus::Rejected => 3,
        ProposalStatus::ExecutionFailed => 4,
    }]);
    d.push_chunk(&proposal.voting_deadline.to_be_bytes());
    d.push_chunk(&proposal.execute_after.to_be_bytes());

    // Votes — sorted by voter address for determinism.
    let mut votes: Vec<(&Address, &bool)> = proposal.votes.iter().collect();
    votes.sort_by_key(|(addr, _)| addr.0);
    d.push_u64(votes.len() as u64);
    for (addr, yes) in &votes {
        d.push_chunk(&addr.0);
        d.push_chunk(&[if **yes { 1 } else { 0 }]);
    }

    // Effect bytes — deterministic encoding per effect variant.
    match &proposal.effect {
        ProposalEffect::RegistryUpdate {
            alg_id,
            target_lifecycle,
            new_min_fee,
        } => {
            d.push_chunk(&[0x01]);
            d.push_chunk(&alg_id.as_u16().to_be_bytes());
            match target_lifecycle {
                Some(lc) => {
                    d.push_chunk(&[1, encode_lifecycle_byte(*lc)]);
                }
                None => d.push_chunk(&[0]),
            }
            match new_min_fee {
                Some(fee) => {
                    d.push_chunk(&[1]);
                    d.push_chunk(&fee.to_be_bytes());
                }
                None => d.push_chunk(&[0]),
            }
        }
        ProposalEffect::BurnRateUpdate { new_burn_rate_bps } => {
            d.push_chunk(&[0x02]);
            d.push_chunk(&new_burn_rate_bps.to_be_bytes());
        }
        ProposalEffect::FeeParamUpdate {
            new_block_gas_limit,
        } => {
            d.push_chunk(&[0x03]);
            d.push_chunk(&new_block_gas_limit.to_be_bytes());
        }
        ProposalEffect::SoftwareUpgrade {
            activate_at_timestamp_ns,
            expected_version,
        } => {
            d.push_chunk(&[0x04]);
            d.push_chunk(&activate_at_timestamp_ns.to_be_bytes());
            d.push_chunk(&expected_version.to_be_bytes());
        }
        ProposalEffect::AddAlgorithm(p) => {
            d.push_chunk(&[0x05]);
            d.push_chunk(&p.alg_id.to_be_bytes());
            d.push_u64(p.spec_ref.len() as u64);
            d.push_chunk(p.spec_ref.as_bytes());
            d.push_chunk(&p.pk_size.to_be_bytes());
            d.push_chunk(&p.sig_size.to_be_bytes());
            d.push_chunk(&[p.sig_class.unwrap_or(0)]);
            d.push_chunk(&p.min_fee.to_be_bytes());
            d.push_chunk(&p.benchmark_verify_per_sec.to_be_bytes());
            d.push_chunk(&[encode_lifecycle_byte(p.initial_lifecycle)]);
        }
        ProposalEffect::AddSlashingVerifier(p) => {
            d.push_chunk(&[0x06]);
            d.push_chunk(&[p.evidence_type]);
            d.push_u64(p.spec_ref.len() as u64);
            d.push_chunk(p.spec_ref.as_bytes());
            d.push_chunk(&p.slash_fraction_bps.to_be_bytes());
            d.push_chunk(&p.jail_duration_blocks.to_be_bytes());
            d.push_chunk(&[if p.tombstone { 1u8 } else { 0u8 }]);
            d.push_chunk(&[encode_lifecycle_byte(p.lifecycle)]);
        }
        ProposalEffect::AddHash(p) => {
            d.push_chunk(&[0x07]);
            d.push_chunk(&[p.hash_id.as_u8()]);
            d.push_u64(p.spec_ref.len() as u64);
            d.push_chunk(p.spec_ref.as_bytes());
            d.push_chunk(&p.output_size_bytes.to_be_bytes());
            d.push_chunk(&[encode_lifecycle_byte(p.initial_lifecycle)]);
        }
        ProposalEffect::AddAuthTemplate(p) => {
            // ADR-053 §T3.5. Discriminant 0x08 reserves the slot at launch
            // even though apply-side dispatch + the on-chain registry land
            // in follow-up; the leaf encoding is part of the genesis-
            // immutable state-root format.
            d.push_chunk(&[0x08]);
            d.push_chunk(&p.template_id.to_be_bytes());
            d.push_u64(p.spec_ref.len() as u64);
            d.push_chunk(p.spec_ref.as_bytes());
            d.push_chunk(&[encode_lifecycle_byte(p.lifecycle)]);
        }
    }

    d.push_chunk(&proposal.rationale_hash);
    d.finish()
}

/// Leaf hash for a pending software upgrade — ADR-031 + ADR-053 §T2.3.
///
/// Domain separator: `"PQC-UPGRADE-LEAF-V1"`. Any change to field order or
/// hash algorithm breaks replay determinism and requires an ADR. The
/// `activate_at_timestamp_ns` field replaces the pre-ADR-053
/// `activate_at_height` at the same wire position (both u64 big-endian),
/// so the leaf hash preimage shape is unchanged — only the semantic
/// meaning of the byte group changed from block-height to wall-clock
/// nanosecond timestamp.
pub(super) fn compute_upgrade_leaf_hash(upgrade: &PendingUpgrade) -> [u8; 32] {
    let mut d = TaggedHasher::new(b"PQC-UPGRADE-LEAF-V1");
    d.push_chunk(&upgrade.proposal_id.0);
    d.push_chunk(&upgrade.activate_at_timestamp_ns.to_be_bytes());
    d.push_chunk(&upgrade.expected_version.to_be_bytes());
    d.finish()
}

/// Encode a `Lifecycle` to a single byte — shared by leaf hash functions.
pub(super) fn encode_lifecycle_byte(lc: pqc_crypto::Lifecycle) -> u8 {
    match lc {
        pqc_crypto::Lifecycle::Active => 0,
        pqc_crypto::Lifecycle::Discouraged => 1,
        pqc_crypto::Lifecycle::Deprecated => 2,
        pqc_crypto::Lifecycle::Banned => 3,
    }
}

/// Leaf hash for a single hash-registry entry — ADR-053 §T1.4.
///
/// Domain separator: `"VIPER-HASH-REGISTRY-V1"`. Any change to the
/// encoding breaks replay determinism and requires a new ADR + state-format
/// bump. The encoding mirrors `compute_alg_leaf_hash` / `compute_slashing_verifier_leaf_hash`:
/// u8 hash_id, length-prefixed spec_ref, output_size_bytes, lifecycle byte.
pub(super) fn compute_hash_registry_leaf_hash(entry: &HashEntry) -> [u8; 32] {
    let mut d = TaggedHasher::new(b"VIPER-HASH-REGISTRY-V1");
    d.push_chunk(&[entry.hash_id.as_u8()]);
    d.push_u64(entry.spec_ref.len() as u64);
    d.push_chunk(entry.spec_ref.as_bytes());
    d.push_chunk(&entry.output_size_bytes.to_be_bytes());
    d.push_chunk(&[encode_lifecycle_byte(entry.lifecycle)]);
    d.finish()
}

/// Leaf hash for a single slashing-verifier registry entry — ADR-050, D-01.
///
/// Domain separator: `"VIPER-SLASHING-REGISTRY-V1"`. Any change to the
/// encoding breaks replay determinism and requires a new ADR + state-format
/// bump.  The encoding mirrors `compute_alg_leaf_hash` in spirit: u8
/// evidence_type, length-prefixed spec_ref, slash_fraction_bps, jail
/// duration, tombstone flag, lifecycle byte.
pub(super) fn compute_slashing_verifier_leaf_hash(entry: &SlashingVerifierEntry) -> [u8; 32] {
    let mut d = TaggedHasher::new(b"VIPER-SLASHING-REGISTRY-V1");
    d.push_chunk(&[entry.evidence_type]);
    d.push_u64(entry.spec_ref.len() as u64);
    d.push_chunk(entry.spec_ref.as_bytes());
    d.push_chunk(&entry.slash_fraction_bps.to_be_bytes());
    d.push_chunk(&entry.jail_duration_blocks.to_be_bytes());
    d.push_chunk(&[if entry.tombstone { 1u8 } else { 0u8 }]);
    d.push_chunk(&[encode_lifecycle_byte(entry.lifecycle)]);
    d.finish()
}

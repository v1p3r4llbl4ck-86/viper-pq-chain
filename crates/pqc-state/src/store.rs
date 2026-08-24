// SPDX-License-Identifier: BUSL-1.1
//! State storage interface.
//!
//! In-memory implementation for devnet / testing.
//! RocksDB backend wired in Phase 2 (CONVENTIONS.md — Recommended Implementation Stack).
//!
//! # Incremental state root (TASK-047)
//!
//! Each entity (account, attestation, governance receipt, alg registry entry)
//! maintains a pre-computed **leaf hash** — a 32-byte SHAKE-256 digest over its
//! full serialization. On mutation only the touched entity's leaf hash is
//! recomputed. The final `state_root()` combines the sorted 32-byte leaf hashes,
//! making the hot path O(N×32 bytes) instead of O(N×serialized_entity_size).
//!
//! This is semantically equivalent to the previous full-scan algorithm under the
//! new "V2" domain separator. Both algorithms produce the same value given the
//! same state (verified by the equivalence test in `pqc-consensus`).

use pqc_crypto::{
    binary_merkle_root,
    hash_registry::{phase1_hash_registry, HashEntry},
    registry::AlgEntry,
    tagged_hash, AlgId, HashId, Lifecycle, SigClass, TaggedHasher,
};
use pqc_types::keyset::KeyStatus;
use pqc_types::{
    account::{Account, Address},
    attestation::{Attestation, AttestationId},
    churn::{stake_weighted_activation_limit, ChurnConfig},
    consensus_rotation::ConsensusKeyRotation,
    governance::{
        GovernanceReceipt, PendingProposal, PendingUpgrade, ProposalEffect, ProposalStatus,
        SlashingVerifierEntry,
    },
    proof_anchor::{AnchorId, ProofAnchor},
    slashing::RecentSlashEntry,
    transaction::TxHash,
    validator::{ValidatorRecord, ValidatorStatus, VALIDATOR_UNBONDING_PERIOD},
};
use std::collections::{HashMap, VecDeque};

// ── State Merkle tree domains — ADR-053 §T3.1 ───────────────────────────────

/// Outer leaf-tagging domain for the binary state Merkle tree
/// (ADR-053 §T3.1). Every leaf entering the tree is wrapped as
/// `tagged_hash(STATE_LEAF_DOMAIN, category_id || sort_key || category_leaf_hash)`.
/// Distinct from [`STATE_BRANCH_DOMAIN`] so leaf hashes can never collide
/// with internal-node hashes (CVE-2012-2459 protection).
pub const STATE_LEAF_DOMAIN: &[u8] = b"VIPER-STATE-LEAF-V1";

/// Branch-tagging domain for the binary state Merkle tree
/// (ADR-053 §T3.1). Internal nodes are
/// `tagged_hash(STATE_BRANCH_DOMAIN, left || right)`. Distinct from
/// [`STATE_LEAF_DOMAIN`] — see CVE-2012-2459.
pub const STATE_BRANCH_DOMAIN: &[u8] = b"VIPER-STATE-BRANCH-V1";

/// Per-category 1-byte discriminant prefixed onto every state Merkle leaf
/// (ADR-053 §T3.1). Values are stable from viper-pq-1 genesis: never
/// renumber. New categories must take a fresh slot above the current
/// maximum and land via P-COMPAT-001 (the state-root format is
/// Tier-1-immutable in practice — every category change is a state
/// migration on the order of Ethereum's Verkle abandonment).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum StateCategory {
    BlockHeight = 0x00,
    Account = 0x01,
    Attestation = 0x02,
    ProofAnchor = 0x03,
    ConsensusRotation = 0x04,
    AlgRegistry = 0x05,
    Receipt = 0x06,
    Validator = 0x07,
    Proposal = 0x08,
    Upgrade = 0x09,
    FeeMarket = 0x0A,
    StorageFund = 0x0B,
    RecentSlashes = 0x0C,
    PeerIdBinding = 0x0D,
    SlashingRegistry = 0x0E,
    HashRegistry = 0x0F,
    ArchivalRecord = 0x10,
    ArchivalKey = 0x11,
}

/// Build one leaf of the state Merkle tree (ADR-053 §T3.1).
///
/// Wraps `category_id || sort_key || category_leaf_hash` under the
/// [`STATE_LEAF_DOMAIN`] tag. The category id and sort_key together pin the
/// leaf's position in the canonical sort order; `category_leaf_hash` is the
/// already-domain-separated 32-byte hash from the per-category cache (e.g.
/// [`compute_account_leaf_hash`]). Re-wrapping under the outer leaf domain
/// is what makes the assembled tree CVE-2012-2459-safe even though the
/// per-category hashes use their own domains.
fn state_merkle_leaf(category: StateCategory, sort_key: &[u8], leaf_hash: &[u8]) -> [u8; 32] {
    let mut payload = Vec::with_capacity(1 + sort_key.len() + leaf_hash.len());
    payload.push(category as u8);
    payload.extend_from_slice(sort_key);
    payload.extend_from_slice(leaf_hash);
    tagged_hash(STATE_LEAF_DOMAIN, &payload)
}

/// Default slash fraction (basis points) applied when the slashing-verifier
/// registry has no seeded entry — e.g. during checkpoint restore from a
/// pre-ADR-050 on-disk format.  Matches the hardcoded
/// `SLASH_FRACTION_BPS = 500` in `apply/slashing.rs` (SPEC-SLASH-001 §10).
pub const DEFAULT_EQUIVOCATION_SLASH_FRACTION_BPS: u16 = 500;

/// Evidence-type discriminants reserved for core slashing offenses — ADR-050.
///
/// `0x00` is reserved as an invalid sentinel (prevents accidentally matching
/// an uninitialized u8).  `0x01..=0x0F` are the core types; governance
/// proposals targeting these discriminants are rejected with
/// `ReservedSlashingEvidenceType`.  Governance-added types must use
/// `0x10..=0xFF`.
pub const SLASHING_EVIDENCE_TYPE_EQUIVOCATION: u8 = 0x01;
pub const SLASHING_EVIDENCE_TYPE_DOWNTIME: u8 = 0x02;
pub const SLASHING_CORE_RESERVED_MAX: u8 = 0x0F;

// ── On-chain Verifier Registry — ADR-044 ─────────────────────────────────────

/// A single entry in the on-chain Verifier Registry (ADR-044).
///
/// Returned by `StateStore::verifier_entry()` and `active_verifier_entries()`.
/// External consumers (consensus engine, mempool) use this to validate that a
/// given algorithm is active and to check its signature / public key sizes
/// without holding a reference into the store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifierRegistryEntry {
    pub alg_id: AlgId,
    pub lifecycle: Lifecycle,
    pub sig_class: Option<SigClass>,
    /// Expected public key size in bytes.
    pub pk_size: usize,
    /// Expected signature size in bytes (0 for KEM algorithms).
    pub sig_size: usize,
    /// Whether this algorithm is usable for consensus validator keys (ADR-043).
    pub consensus_allowed: bool,
}

impl VerifierRegistryEntry {
    fn from_alg_entry(e: &AlgEntry) -> Self {
        Self {
            alg_id: e.alg_id,
            lifecycle: e.lifecycle,
            sig_class: e.sig_class,
            pk_size: e.pk_size,
            sig_size: e.sig_size,
            consensus_allowed: e.alg_id.allowed_for_consensus(),
        }
    }

    pub fn admits_transactions(&self) -> bool {
        self.lifecycle.admits_transactions()
    }
}

// ── Fee market constants — ADR-053 §T2.1 (SPEC-FEE-002 revision) ────────────
//
// The fee market was AIMD (additive increase, multiplicative decrease) on a
// single `base_fee` — SPEC-FEE-002 §6.2. ADR-053 §T2.1 replaces that with the
// EIP-4844 exponential blob-fee update `base_fee = fake_exponential(MIN,
// excess, MIN × UPDATE_FRACTION)` accumulated via `excess = max(0,
// prev_excess + used − target)`, plus a non-zero reserve-price floor that
// governance cannot set to zero (addresses the 2024 EIP-7918 $78M revenue-
// miss). The fee market is structurally four-dimensional — compute,
// storage, witness, contention — but only `compute` is wired to real tx
// activity at launch; the other three dimensions are reserved slots with
// `target = 0` so `excess` never grows and `base_fee` stays at
// `RESERVE_FLOOR`. A future P-COMPAT-001 upgrade activates them by
// populating their targets.
//
// AIMD constants are retained below as deprecated (see `AIMD_*_DEPRECATED`)
// while the downstream tx-validation path continues to read `compute_base_fee`
// via `base_fee_dynamic()` for drop-in compatibility.
/// Non-zero reserve-price floor for the compute dimension (venom).
/// Governance MUST NOT set the compute base fee below this value (ADR-053
/// §T2.1, lesson from EIP-7918). This is a compile-time ungovernable
/// constant — there is no on-chain knob to lower it.
pub const COMPUTE_RESERVE_FLOOR: u64 = 100;
/// Legacy alias — `BASE_FEE_MIN` historically exported the same semantic
/// as `COMPUTE_RESERVE_FLOOR`. Retained so downstream crates that read it
/// do not break; new code SHOULD use `COMPUTE_RESERVE_FLOOR`.
pub const BASE_FEE_MIN: u64 = COMPUTE_RESERVE_FLOOR;
/// Maximum adaptive base fee (venom). Upper ceiling on any single dimension.
pub const BASE_FEE_MAX: u64 = 10_000_000;
/// Default block gas limit for the compute dimension, governance-tunable
/// (SPEC-FEE-002 §5).
pub const DEFAULT_BLOCK_GAS_LIMIT: u64 = 10_000_000;
/// Default initial base fee for the compute dimension on a fresh store.
/// Zero so that early genesis states without explicit `FeeParams` still
/// accept transactions. Production nodes override from genesis config.
pub const DEFAULT_BASE_FEE: u64 = 0;

/// EIP-4844 fee-update fraction for the compute dimension. Tuning this
/// governs the reactivity of the exponential base-fee curve: higher values
/// mean slower growth per unit of excess usage. Same spirit as EIP-4844's
/// `BLOB_BASE_FEE_UPDATE_FRACTION = 3_338_477`.
pub const COMPUTE_FEE_UPDATE_FRACTION: u64 = 3_338_477;
/// Compute-dimension target gas per block — half of the default block gas
/// limit, matching EIP-1559 / EIP-4844 convention. `excess = max(0,
/// prev_excess + used − target)` drives the exponential update.
pub const DEFAULT_COMPUTE_TARGET: u64 = DEFAULT_BLOCK_GAS_LIMIT / 2;

/// One dimension of the fee market — ADR-053 §T2.1.
///
/// Each dimension (compute, storage, witness, contention) is priced
/// independently via the EIP-4844 exponential curve
/// `base_fee = max(reserve_floor, fake_exponential(reserve_floor, excess,
/// reserve_floor × update_fraction))` where `excess` accumulates via
/// `new_excess = saturating_sub(prev_excess + used, target)`. A dimension
/// with `target = 0` is inactive — excess can only grow or stay at zero,
/// so its base fee never moves off the floor. This is the genesis state
/// for `storage`, `witness`, and `contention`; a future P-COMPAT-001
/// upgrade activates them by populating `target`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FeeMarketDimension {
    /// Current base fee (venom), derived from `excess` each update.
    pub base_fee: u64,
    /// Hard per-block cap; governance-tunable (SPEC-FEE-002 §5.3).
    pub limit: u64,
    /// EIP-4844 target per-block utilisation. Zero disables the dimension
    /// (base fee stays at `reserve_floor` forever).
    pub target: u64,
    /// Accumulated excess usage (used − target, floored at 0) since the
    /// last time the dimension was underutilised.
    pub excess: u64,
    /// Non-zero reserve-price floor; ungovernable-to-zero (ADR-053 §T2.1).
    pub reserve_floor: u64,
    /// EIP-4844 update fraction; controls the reactivity of the
    /// exponential curve.
    pub update_fraction: u64,
}

impl FeeMarketDimension {
    /// Compute dimension at launch — wired to tx gas_used, reserve floor
    /// `COMPUTE_RESERVE_FLOOR`, target 50% of block gas limit, EIP-4844
    /// update fraction.
    pub const fn compute_default() -> Self {
        Self {
            base_fee: DEFAULT_BASE_FEE,
            limit: DEFAULT_BLOCK_GAS_LIMIT,
            target: DEFAULT_COMPUTE_TARGET,
            excess: 0,
            reserve_floor: COMPUTE_RESERVE_FLOOR,
            update_fraction: COMPUTE_FEE_UPDATE_FRACTION,
        }
    }

    /// Reserved dimension — inactive at genesis. `target = 0` so `excess`
    /// never accumulates and `base_fee` remains pinned at the floor.
    /// Activation happens via a future P-COMPAT-001 upgrade that sets
    /// `target` to a non-zero value.
    pub const fn reserved_default(reserve_floor: u64) -> Self {
        Self {
            base_fee: reserve_floor,
            limit: 0,
            target: 0,
            excess: 0,
            reserve_floor,
            update_fraction: 1,
        }
    }
}

/// Multi-dimensional fee market state — ADR-053 §T2.1 + SPEC-FEE-002.
///
/// The compute dimension is active at launch; storage, witness, and
/// contention are reserved slots pinned at their reserve floors (see
/// [`FeeMarketDimension::reserved_default`]). Stored in `StateStore` and
/// included in the state root under the `"VIPER-FEE-MARKET-V1"` leaf
/// domain.
///
/// Backwards-compatible aliases (`base_fee`, `block_gas_limit`) mirror the
/// compute dimension so `StateStore::base_fee_dynamic()` and existing tx
/// validation callers continue to work without wiring changes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FeeMarketState {
    /// Compute-gas dimension — tx execution cost.
    pub compute: FeeMarketDimension,
    /// Storage-growth dimension (bytes × epoch lifetime). Reserved at launch.
    pub storage: FeeMarketDimension,
    /// Witness-size dimension for future stateless-client support.
    /// Reserved at launch (ADR-053 §T2.1, forward-compat for SPEC-STATELESS).
    pub witness: FeeMarketDimension,
    /// Per-account contention dimension. Reserved at launch.
    pub contention: FeeMarketDimension,
    /// Burn rate in basis points; 0 at launch, activated by governance later.
    pub burn_rate_bps: u16,
}

impl FeeMarketState {
    /// Backwards-compatible accessor — returns the compute-dimension base
    /// fee. Downstream callers that used `fee_market.base_fee` before
    /// ADR-053 §T2.1 should migrate to `fee_market.compute.base_fee`, but
    /// this field-style getter is kept for drop-in compatibility.
    pub fn base_fee(&self) -> u64 {
        self.compute.base_fee
    }

    /// Backwards-compatible mutator for the compute base fee.
    pub fn set_base_fee(&mut self, value: u64) {
        self.compute.base_fee = value;
    }

    /// Backwards-compatible accessor for the compute block gas limit.
    pub fn block_gas_limit(&self) -> u64 {
        self.compute.limit
    }
}

impl Default for FeeMarketState {
    fn default() -> Self {
        Self {
            compute: FeeMarketDimension::compute_default(),
            storage: FeeMarketDimension::reserved_default(COMPUTE_RESERVE_FLOOR),
            witness: FeeMarketDimension::reserved_default(COMPUTE_RESERVE_FLOOR),
            contention: FeeMarketDimension::reserved_default(COMPUTE_RESERVE_FLOOR),
            burn_rate_bps: 0,
        }
    }
}

/// EIP-4844 Taylor-series approximation of `factor × e^(numerator / denominator)`.
///
/// Same algorithm as the Ethereum `fake_exponential` used in the blob-fee
/// update (EIP-4844 §Fee update rule). Runs in `u128` to avoid overflow on
/// realistic inputs and converges in < 30 iterations for the parameter
/// ranges we use. Callers MUST pass `denominator > 0`; `numerator` may be
/// zero (returns `factor`). Output is clamped to `u64::MAX`.
pub fn fake_exponential(factor: u64, numerator: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        return factor;
    }
    let factor_u = factor as u128;
    let numerator_u = numerator as u128;
    let denominator_u = denominator as u128;
    let mut output: u128 = 0;
    let mut numerator_accum: u128 = factor_u.saturating_mul(denominator_u);
    let mut i: u128 = 1;
    while numerator_accum > 0 {
        output = output.saturating_add(numerator_accum);
        numerator_accum =
            numerator_accum.saturating_mul(numerator_u) / denominator_u.saturating_mul(i);
        i += 1;
        if i > 128 {
            break; // defensive bound; real convergence is < 30 for our params
        }
    }
    let clamped = output / denominator_u;
    clamped.min(u64::MAX as u128) as u64
}

#[derive(Clone, Debug)]
pub struct StateStore {
    accounts: HashMap<[u8; 32], Account>,
    attestations: HashMap<AttestationId, Attestation>,
    proof_anchors: HashMap<AnchorId, ProofAnchor>,
    consensus_key_rotations: HashMap<[u8; 32], ConsensusKeyRotation>,
    governance_receipts: HashMap<TxHash, GovernanceReceipt>,
    /// On-chain validator registry — keyed by operator address bytes (TASK-064, SPEC-VAL-001).
    validators: HashMap<[u8; 32], ValidatorRecord>,
    /// On-chain libp2p PeerId bindings per validator — ADR-047, D-03, TASK-159.
    ///
    /// Populated on `ValidatorRegister` (when payload includes field 5) and on
    /// `ValidatorRotatePeerId`. Value is the libp2p PeerId multihash (≤ 64 bytes).
    /// An operator without an entry has no on-chain binding — the expected
    /// state for pre-ADR-047 devnet-2 genesis validators.
    peer_id_bindings: HashMap<[u8; 32], Vec<u8>>,
    /// Cached leaf hash per peer_id binding, domain `"PQC-PEER-ID-BINDING-LEAF-V1"`.
    peer_id_binding_leaf_hashes: HashMap<[u8; 32], [u8; 32]>,
    block_height: u64,
    alg_registry: HashMap<u16, AlgEntry>,
    /// Chain identifier — set from genesis config. Empty in tests that do not
    /// exercise chain_id validation (test txs use Vec::new(), which matches).
    chain_id: Vec<u8>,
    /// AIMD adaptive fee market state — SPEC-FEE-002. Updated once per block.
    pub fee_market: FeeMarketState,
    /// Storage fund (Sui-style upfront perpetual) — ADR-053 §T2.2.
    /// Credited on state-create, debited on state-delete rebate. Framework
    /// only at launch; tx-path wiring lands in a P-COMPAT-001 follow-up.
    /// Elided in tokenless builds (viper-research-1) — see
    /// the private planning notes
    #[cfg(feature = "token_economics")]
    pub storage_fund: crate::storage_fund::StorageFundState,

    // ── Incremental state root leaf hash caches ───────────────────────────────
    // Each cache maps the entity's natural key to its pre-computed 32-byte leaf hash.
    // Updated on every mutation so `state_root()` only needs to hash N × 32 bytes.
    account_leaf_hashes: HashMap<[u8; 32], [u8; 32]>,
    attestation_leaf_hashes: HashMap<AttestationId, [u8; 32]>,
    proof_anchor_leaf_hashes: HashMap<AnchorId, [u8; 32]>,
    consensus_rotation_leaf_hashes: HashMap<[u8; 32], [u8; 32]>,
    receipt_leaf_hashes: HashMap<TxHash, [u8; 32]>,
    alg_leaf_hashes: HashMap<u16, [u8; 32]>,
    validator_leaf_hashes: HashMap<[u8; 32], [u8; 32]>,
    /// Cached leaf hash for `fee_market`. Recomputed on every AIMD update.
    fee_market_leaf_hash: [u8; 32],
    /// Cached leaf hash for `storage_fund`. Recomputed on every balance
    /// credit/debit or parameter change. Elided in tokenless builds.
    #[cfg(feature = "token_economics")]
    storage_fund_leaf_hash: [u8; 32],

    // ── Multi-step governance (TASK-100) ─────────────────────────────────────
    /// Active pending proposals keyed by proposal_id bytes.
    pending_proposals: HashMap<TxHash, PendingProposal>,
    /// Pre-computed 32-byte leaf hash per pending proposal. Updated on every
    /// mutation so `state_root()` only needs to fold N × 32 bytes.
    proposal_leaf_hashes: HashMap<TxHash, [u8; 32]>,

    // ── Archival overlay (SPEC-ARCHIVAL-001, ADR-045, TASK-161) ──────────────
    /// On-chain archival records keyed by epoch_number — SPEC-ARCHIVAL-001 §4.4.
    /// First-writer-wins per epoch (duplicates are rejected at apply-time).
    archival_records: HashMap<u64, pqc_types::archival::ArchivalRecord>,
    /// Cached leaf hash per archival record — domain `VIPER-ARCHIVAL-RECORDS-V1`.
    archival_record_leaf_hashes: HashMap<u64, [u8; 32]>,
    /// Per-validator archival public keys — SPEC-ARCHIVAL-001 §4.5.
    /// Rotation is by resubmission of `ValidatorRegisterArchivalKey`.
    archival_keys: HashMap<[u8; 32], pqc_types::archival::ValidatorArchivalKey>,
    /// Cached leaf hash per archival key — domain `VIPER-ARCHIVAL-KEYS-V1`.
    archival_key_leaf_hashes: HashMap<[u8; 32], [u8; 32]>,
    /// Archival signer set — SPEC-ARCHIVAL-001 §4.2.
    ///
    /// Default is "all Active validators with a registered archival key" when
    /// this set is empty (bootstrap behaviour at genesis); an explicit set is
    /// populated by governance via `ProposalEffect::UpdateArchivalSignerSet`
    /// (not wired in M4.2 — see SPEC §14 O4).
    archival_signer_set: std::collections::BTreeSet<[u8; 32]>,
    /// Archival threshold `(m, n)` — SPEC-ARCHIVAL-001 §4.3.
    /// `None` means "derive from signer-set at apply time".
    archival_threshold_m_of_n: Option<(u16, u16)>,
    /// Governance-registered archival_renewer addresses — SPEC-ARCHIVAL-001 §8.3.
    /// Allowed to submit `ArchivalRecordRenew` without being Active validators.
    archival_renewers: std::collections::BTreeSet<[u8; 32]>,

    // ── Governance-scheduled software upgrades (ADR-031) ─────────────────────
    /// Pending binary upgrades voted through governance.  Keyed by proposal_id.
    /// Each entry is checked against `BlockHeader.timestamp` at its
    /// `activate_at_timestamp_ns` during block application (ADR-053 §T2.3).
    pending_upgrades: HashMap<TxHash, PendingUpgrade>,
    /// Pre-computed leaf hash per pending upgrade.  Included in state_root.
    upgrade_leaf_hashes: HashMap<TxHash, [u8; 32]>,

    // ── Correlation penalty ledger (ADR-048, SPEC-SLASH-001 §17, D-02) ───────
    /// Rolling window of recent slashes, sorted ascending by height. Used to
    /// compute the Ethereum-style correlation multiplier: a new slash inspects
    /// the sum of `slashed_stake` over the last `CORRELATION_WINDOW_BLOCKS`
    /// blocks and scales its penalty fraction accordingly. Entries older than
    /// the window are pruned lazily on each slash application.
    ///
    /// This is consensus-critical state: the leaf hash below is folded into
    /// `state_root()` so every validator agrees on the multiplier.
    recent_slashes: VecDeque<RecentSlashEntry>,
    /// Cached leaf hash for `recent_slashes`. Recomputed on every push/prune.
    recent_slashes_leaf_hash: [u8; 32],

    // ── Pluggable slashing-verifier registry (ADR-050, ADR-042 §16, D-01) ────
    /// On-chain registry of slashing-evidence handlers, keyed by the single
    /// byte `evidence_type` discriminant.  At genesis this is seeded with
    /// entry `0x01` (equivocation) at 500 bps.  Governance can add new
    /// evidence types via `ProposalEffect::AddSlashingVerifier` in the
    /// `0x10..=0xFF` range — core types `0x01..=0x0F` are code-governed.
    ///
    /// Folded into `state_root()` under leaf domain
    /// `VIPER-SLASHING-REGISTRY-V1` so every validator agrees on the
    /// governance-tunable slash fraction at slash-application time.
    slashing_registry: HashMap<u8, SlashingVerifierEntry>,
    /// Cached leaf hash per slashing-verifier entry — mirrors the other
    /// leaf-hash caches (one hash per entry, recomputed on mutation).
    slashing_registry_leaf_hashes: HashMap<u8, [u8; 32]>,

    // ── Hash-function registry (ADR-053 §T1.4) ──────────────────────────────
    /// On-chain registry of hash functions, keyed by `HashId` byte.  At
    /// genesis this is seeded with entry `0x01` (SHAKE-256, FIPS 202).
    /// Governance can add new entries via `ProposalEffect::AddHash` in
    /// the `0x10..=0xFF` range — core hash ids `0x01..=0x0F` are
    /// code-governed (a `SoftwareUpgrade` is required to wire dispatch
    /// on `HashId` at each call site).
    ///
    /// Folded into `state_root()` under leaf domain
    /// `VIPER-HASH-REGISTRY-V1` so every validator agrees on the
    /// governance-tunable hash registry at block-apply time.
    hash_registry: HashMap<u8, HashEntry>,
    /// Cached leaf hash per hash-registry entry.
    hash_registry_leaf_hashes: HashMap<u8, [u8; 32]>,
}

mod state_merkle;
use state_merkle::*;

impl StateStore {
    pub fn new() -> Self {
        use pqc_crypto::registry::phase1_registry;
        let entries = phase1_registry();
        let alg_leaf_hashes = entries
            .iter()
            .map(|e| (e.alg_id.as_u16(), compute_alg_leaf_hash(e)))
            .collect();
        let alg_registry = entries
            .into_iter()
            .map(|e| (e.alg_id.as_u16(), e))
            .collect();
        let fee_market = FeeMarketState::default();
        let fee_market_leaf_hash = compute_fee_market_leaf_hash(&fee_market);
        #[cfg(feature = "token_economics")]
        let storage_fund = crate::storage_fund::StorageFundState::default();
        #[cfg(feature = "token_economics")]
        let storage_fund_leaf_hash = compute_storage_fund_leaf_hash(&storage_fund);
        let recent_slashes: VecDeque<RecentSlashEntry> = VecDeque::new();
        let recent_slashes_leaf_hash = compute_recent_slashes_leaf_hash(&recent_slashes);

        // ── Seed the pluggable slashing-verifier registry — ADR-050 ──────────
        // Entry 0x01 (equivocation) matches SPEC-SLASH-001 §10 verbatim so
        // `apply_submit_equivocation_evidence` reads the same 500 bps it
        // had hardcoded pre-ADR-050.  Governance can tune the fraction via
        // `ProposalEffect::RegistryUpdate`-style updates in a future ADR;
        // the seeded shape keeps state_root byte-stable with D-02 tests.
        let mut slashing_registry: HashMap<u8, SlashingVerifierEntry> = HashMap::new();
        let mut slashing_registry_leaf_hashes: HashMap<u8, [u8; 32]> = HashMap::new();
        let equivocation_entry = SlashingVerifierEntry {
            evidence_type: SLASHING_EVIDENCE_TYPE_EQUIVOCATION,
            spec_ref: "SPEC-SLASH-001 §10 (equivocation, ADR-024)".to_string(),
            slash_fraction_bps: DEFAULT_EQUIVOCATION_SLASH_FRACTION_BPS,
            jail_duration_blocks: 0, // equivocation tombstones permanently
            tombstone: true,
            lifecycle: Lifecycle::Active,
        };
        slashing_registry_leaf_hashes.insert(
            SLASHING_EVIDENCE_TYPE_EQUIVOCATION,
            compute_slashing_verifier_leaf_hash(&equivocation_entry),
        );
        slashing_registry.insert(SLASHING_EVIDENCE_TYPE_EQUIVOCATION, equivocation_entry);

        // ── Seed the hash-function registry — ADR-053 §T1.4 ──────────────────
        // Single genesis entry: 0x01 = SHAKE-256 (FIPS 202, 32-byte digest).
        // Every hash-using call site still hard-codes SHAKE-256 at launch;
        // the registry reserves on-chain the shape so a future Tier-3
        // `SoftwareUpgrade` can wire dispatch on `HashId` without a
        // state-format migration.
        let mut hash_registry: HashMap<u8, HashEntry> = HashMap::new();
        let mut hash_registry_leaf_hashes: HashMap<u8, [u8; 32]> = HashMap::new();
        for entry in phase1_hash_registry() {
            let key = entry.hash_id.as_u8();
            hash_registry_leaf_hashes.insert(key, compute_hash_registry_leaf_hash(&entry));
            hash_registry.insert(key, entry);
        }

        Self {
            accounts: HashMap::new(),
            attestations: HashMap::new(),
            proof_anchors: HashMap::new(),
            consensus_key_rotations: HashMap::new(),
            governance_receipts: HashMap::new(),
            validators: HashMap::new(),
            peer_id_bindings: HashMap::new(),
            peer_id_binding_leaf_hashes: HashMap::new(),
            block_height: 0,
            alg_registry,
            chain_id: Vec::new(),
            fee_market,
            #[cfg(feature = "token_economics")]
            storage_fund,
            #[cfg(feature = "token_economics")]
            storage_fund_leaf_hash,
            account_leaf_hashes: HashMap::new(),
            attestation_leaf_hashes: HashMap::new(),
            proof_anchor_leaf_hashes: HashMap::new(),
            consensus_rotation_leaf_hashes: HashMap::new(),
            receipt_leaf_hashes: HashMap::new(),
            alg_leaf_hashes,
            validator_leaf_hashes: HashMap::new(),
            fee_market_leaf_hash,
            pending_proposals: HashMap::new(),
            proposal_leaf_hashes: HashMap::new(),
            pending_upgrades: HashMap::new(),
            upgrade_leaf_hashes: HashMap::new(),
            recent_slashes,
            recent_slashes_leaf_hash,
            slashing_registry,
            slashing_registry_leaf_hashes,
            hash_registry,
            hash_registry_leaf_hashes,
            archival_records: HashMap::new(),
            archival_record_leaf_hashes: HashMap::new(),
            archival_keys: HashMap::new(),
            archival_key_leaf_hashes: HashMap::new(),
            archival_signer_set: std::collections::BTreeSet::new(),
            archival_threshold_m_of_n: None,
            archival_renewers: std::collections::BTreeSet::new(),
        }
    }

    /// Rebuild a state snapshot from explicit account data, a known height, and
    /// the genesis chain identifier.
    ///
    /// The current prototype still treats the algorithm registry as part of the
    /// static phase-1 genesis baseline, so snapshot restore rebuilds that
    /// registry via `StateStore::new()` and overlays account, height, and
    /// chain_id data.
    ///
    /// `chain_id` must match the genesis config value. Pass `Vec::new()` only
    /// in tests whose transactions also use an empty chain_id.
    pub fn from_snapshot_accounts(
        accounts: Vec<Account>,
        block_height: u64,
        chain_id: Vec<u8>,
    ) -> Self {
        Self::from_snapshot(accounts, Vec::new(), block_height, chain_id)
    }

    /// Rebuild a state snapshot from explicit account and attestation data.
    pub fn from_snapshot(
        accounts: Vec<Account>,
        attestations: Vec<Attestation>,
        block_height: u64,
        chain_id: Vec<u8>,
    ) -> Self {
        Self::from_snapshot_full(
            accounts,
            attestations,
            Vec::new(),
            pqc_crypto::registry::phase1_registry(),
            block_height,
            chain_id,
        )
    }

    /// Rebuild a state snapshot from explicit account, attestation, proof anchor,
    /// governance, and algorithm-registry data.
    pub fn from_snapshot_full(
        accounts: Vec<Account>,
        attestations: Vec<Attestation>,
        governance_receipts: Vec<GovernanceReceipt>,
        alg_registry_entries: Vec<AlgEntry>,
        block_height: u64,
        chain_id: Vec<u8>,
    ) -> Self {
        Self::from_snapshot_full_with_proofs(
            accounts,
            attestations,
            Vec::new(),
            governance_receipts,
            alg_registry_entries,
            block_height,
            chain_id,
        )
    }

    /// Rebuild a state snapshot from all entity collections including proof anchors.
    pub fn from_snapshot_full_with_proofs(
        accounts: Vec<Account>,
        attestations: Vec<Attestation>,
        proof_anchors: Vec<ProofAnchor>,
        governance_receipts: Vec<GovernanceReceipt>,
        alg_registry_entries: Vec<AlgEntry>,
        block_height: u64,
        chain_id: Vec<u8>,
    ) -> Self {
        let mut store = Self::new();
        for account in accounts {
            let leaf = compute_account_leaf_hash(&account);
            store.account_leaf_hashes.insert(account.address.0, leaf);
            store.accounts.insert(account.address.0, account);
        }
        for attestation in attestations {
            let leaf = compute_attestation_leaf_hash(&attestation);
            store
                .attestation_leaf_hashes
                .insert(attestation.attestation_id, leaf);
            store
                .attestations
                .insert(attestation.attestation_id, attestation);
        }
        for anchor in proof_anchors {
            let leaf = compute_proof_anchor_leaf_hash(&anchor);
            store
                .proof_anchor_leaf_hashes
                .insert(anchor.anchor_id, leaf);
            store.proof_anchors.insert(anchor.anchor_id, anchor);
        }
        for receipt in governance_receipts {
            let leaf = compute_receipt_leaf_hash(&receipt);
            store
                .receipt_leaf_hashes
                .insert(receipt.proposal_id.clone(), leaf);
            store
                .governance_receipts
                .insert(receipt.proposal_id.clone(), receipt);
        }
        // Override alg_registry and leaf hashes built by Self::new()
        store.alg_registry.clear();
        store.alg_leaf_hashes.clear();
        for entry in alg_registry_entries {
            let leaf = compute_alg_leaf_hash(&entry);
            store.alg_leaf_hashes.insert(entry.alg_id.as_u16(), leaf);
            store.alg_registry.insert(entry.alg_id.as_u16(), entry);
        }
        store.block_height = block_height;
        store.chain_id = chain_id;
        store
    }

    pub fn alg_entry(&self, alg_id: AlgId) -> Option<&AlgEntry> {
        self.alg_registry.get(&alg_id.as_u16())
    }

    pub fn alg_entry_mut(&mut self, alg_id: AlgId) -> Option<&mut AlgEntry> {
        self.alg_registry.get_mut(&alg_id.as_u16())
    }

    /// Update the algorithm registry entry and recompute its leaf hash.
    ///
    /// Callers that mutate an `AlgEntry` via `alg_entry_mut()` must call this
    /// afterwards to keep the incremental state root consistent. The governance
    /// apply path uses this exclusively.
    pub fn commit_alg_entry_mutation(&mut self, alg_id: AlgId) {
        if let Some(entry) = self.alg_registry.get(&alg_id.as_u16()) {
            let leaf = compute_alg_leaf_hash(entry);
            self.alg_leaf_hashes.insert(alg_id.as_u16(), leaf);
        }
    }

    pub fn alg_min_fee(&self, alg_id: AlgId) -> Option<u64> {
        self.alg_entry(alg_id).map(|entry| entry.min_fee)
    }

    /// Insert a freshly-added algorithm registry entry — ADR-049 (governance
    /// `AddAlgorithm` proposal).  Called from the tally path after validation
    /// succeeds.  Computes the leaf hash so `state_root()` folds the new
    /// entry on the next call.
    ///
    /// The caller is responsible for rejecting duplicate `alg_id`s (the
    /// tally path does this before calling); inserting an existing id here
    /// would overwrite silently.
    pub fn insert_alg_entry(&mut self, entry: AlgEntry) {
        let leaf = compute_alg_leaf_hash(&entry);
        let key = entry.alg_id.as_u16();
        self.alg_leaf_hashes.insert(key, leaf);
        self.alg_registry.insert(key, entry);
    }

    /// Return `true` if `alg_id` (raw u16) is already registered.
    pub fn alg_entry_registered(&self, alg_id_raw: u16) -> bool {
        self.alg_registry.contains_key(&alg_id_raw)
    }

    pub fn get_account(&self, addr: &Address) -> Option<&Account> {
        self.accounts.get(&addr.0)
    }

    pub fn get_account_mut(&mut self, addr: &Address) -> Option<&mut Account> {
        self.accounts.get_mut(&addr.0)
    }

    /// Recompute the leaf hash for an account after mutation via `get_account_mut`.
    ///
    /// Every apply-path function that calls `get_account_mut` and mutates the
    /// returned account **must** call this before returning. Omitting it leaves
    /// a stale leaf hash in the cache, making `state_root()` incorrect.
    pub fn commit_account_mutation(&mut self, addr: &Address) {
        if let Some(account) = self.accounts.get(&addr.0) {
            let leaf = compute_account_leaf_hash(account);
            self.account_leaf_hashes.insert(addr.0, leaf);
        }
    }

    pub fn insert_account(&mut self, account: Account) {
        let leaf = compute_account_leaf_hash(&account);
        self.account_leaf_hashes.insert(account.address.0, leaf);
        self.accounts.insert(account.address.0, account);
    }

    pub fn get_attestation(&self, id: &AttestationId) -> Option<&Attestation> {
        self.attestations.get(id)
    }

    pub fn insert_attestation(&mut self, attestation: Attestation) {
        let leaf = compute_attestation_leaf_hash(&attestation);
        self.attestation_leaf_hashes
            .insert(attestation.attestation_id, leaf);
        self.attestations
            .insert(attestation.attestation_id, attestation);
    }

    pub fn get_proof_anchor(&self, id: &AnchorId) -> Option<&ProofAnchor> {
        self.proof_anchors.get(id)
    }

    pub fn insert_proof_anchor(&mut self, anchor: ProofAnchor) {
        let leaf = compute_proof_anchor_leaf_hash(&anchor);
        self.proof_anchor_leaf_hashes.insert(anchor.anchor_id, leaf);
        self.proof_anchors.insert(anchor.anchor_id, anchor);
    }

    pub fn get_consensus_key_rotation(&self, operator: &Address) -> Option<&ConsensusKeyRotation> {
        self.consensus_key_rotations.get(&operator.0)
    }

    pub fn insert_consensus_key_rotation(&mut self, rotation: ConsensusKeyRotation) {
        let leaf = compute_consensus_rotation_leaf_hash(&rotation);
        self.consensus_rotation_leaf_hashes
            .insert(rotation.operator.0, leaf);
        self.consensus_key_rotations
            .insert(rotation.operator.0, rotation);
    }

    /// All pending consensus key rotation records sorted by operator address.
    pub fn consensus_key_rotations_in_order(&self) -> Vec<&ConsensusKeyRotation> {
        let mut rotations: Vec<&ConsensusKeyRotation> =
            self.consensus_key_rotations.values().collect();
        rotations.sort_by_key(|r| r.operator.0);
        rotations
    }

    /// TASK-223 — activate any pending consensus-key rotations whose
    /// `rotation_start_height` has been reached.
    ///
    /// Called once per block, immediately after
    /// [`Self::process_validator_unbonding_expirations`]. For every pending
    /// rotation with `rotation_start_height <= current_height`:
    ///
    /// 1. Find the matching `ValidatorRecord` (rotation has no effect if the
    ///    operator is not a registered validator — the rotation record stays
    ///    in state until the validator registers OR the operator's account
    ///    is purged).
    /// 2. Replace `record.consensus_alg_id` and `record.consensus_pk` with
    ///    the rotation's new values.
    /// 3. Remove the rotation record from the pending map.
    /// 4. Remove the corresponding cached leaf hash from the rotation
    ///    leaf-hash table so the state-root fold reflects the removal.
    /// 5. Recompute the validator-record leaf hash (the consensus_pk is
    ///    folded into it).
    ///
    /// Returns the list of `(operator, new_alg_id)` tuples for the
    /// activations that fired, ordered by operator address. Used by the
    /// caller (engine + replay) for telemetry and for invalidating
    /// keystore-resident signing material.
    ///
    /// # Slashing semantics
    ///
    /// Activation is atomic at the block level. A `CommitSig` for block N
    /// is verified against `ValidatorRecord.consensus_pk` *as it stood at
    /// block N* — meaning the OLD key for blocks `< rotation_start_height`
    /// and the NEW key for blocks `≥ rotation_start_height`. Equivocation
    /// evidence submitted with the old key for a block before activation
    /// MUST be admitted before the activation height (otherwise the chain
    /// can no longer verify the old-key signature). The unbonding period
    /// upper-bounds the evidence window per ADR-050; operators are
    /// expected to keep `rotation_start_height >= current + ROTATION_WINDOW`
    /// (already enforced at apply time, see `apply_consensus_key_rotate`).
    pub fn activate_pending_consensus_key_rotations(
        &mut self,
        current_height: u64,
    ) -> Vec<(Address, AlgId)> {
        // Walk the pending rotations and collect operators whose rotation
        // height has been reached. We can't mutate `validators` while
        // iterating `consensus_key_rotations`, so two-pass.
        let mut due: Vec<[u8; 32]> = self
            .consensus_key_rotations
            .iter()
            .filter_map(|(addr, r)| {
                if r.rotation_start_height <= current_height {
                    Some(*addr)
                } else {
                    None
                }
            })
            .collect();
        due.sort_by_key(|a| *a);

        let mut activations: Vec<(Address, AlgId)> = Vec::new();
        for addr in due {
            // Remove the rotation record + its leaf-hash entry so the
            // state-root fold no longer counts it.
            let rotation = match self.consensus_key_rotations.remove(&addr) {
                Some(r) => r,
                None => continue,
            };
            self.consensus_rotation_leaf_hashes.remove(&addr);

            // Apply to validator-record. If the operator is not a
            // registered validator, the rotation request was effectively
            // a no-op — log at WARN so operators can spot the mis-issue.
            match self.validators.get_mut(&addr) {
                Some(record) => {
                    let new_alg = rotation.new_alg_id;
                    record.consensus_alg_id = new_alg;
                    record.consensus_pk = rotation.new_pk_bytes;
                    activations.push((rotation.operator.clone(), new_alg));
                }
                None => {
                    tracing::warn!(
                        operator = %rotation.operator,
                        rotation_start_height = rotation.rotation_start_height,
                        "consensus_key_rotate activation skipped: operator is not a registered validator (record dropped)"
                    );
                }
            }

            // Re-fold the validator-leaf cache for any record that was
            // mutated. For a missing validator we skip — the leaf cache
            // never had an entry to begin with.
            if let Some(record) = self.validators.get(&addr) {
                let leaf = compute_validator_leaf_hash(record);
                self.validator_leaf_hashes.insert(addr, leaf);
            }
        }

        activations
    }

    // ── Validator registry (TASK-064, SPEC-VAL-001) ──────────────────────────

    pub fn get_validator(&self, operator: &Address) -> Option<&ValidatorRecord> {
        self.validators.get(&operator.0)
    }

    pub fn get_validator_mut(&mut self, operator: &Address) -> Option<&mut ValidatorRecord> {
        self.validators.get_mut(&operator.0)
    }

    /// Insert or replace a validator record and update its leaf hash.
    pub fn insert_validator(&mut self, record: ValidatorRecord) {
        let leaf = compute_validator_leaf_hash(&record);
        self.validator_leaf_hashes.insert(record.operator.0, leaf);
        self.validators.insert(record.operator.0, record);
    }

    /// Return the on-chain libp2p PeerId multihash bound to this validator — ADR-047.
    pub fn get_validator_peer_id(&self, operator: &Address) -> Option<&[u8]> {
        self.peer_id_bindings.get(&operator.0).map(|v| v.as_slice())
    }

    /// Record or replace the on-chain libp2p PeerId binding — ADR-047.
    ///
    /// Called by `apply_validator_register` and `apply_validator_rotate_peer_id`.
    /// Passing an empty slice removes the binding. Updates the cached leaf hash
    /// so `state_root()` stays consistent.
    pub fn set_validator_peer_id(&mut self, operator: &Address, peer_id: Vec<u8>) {
        if peer_id.is_empty() {
            self.peer_id_bindings.remove(&operator.0);
            self.peer_id_binding_leaf_hashes.remove(&operator.0);
            return;
        }
        let leaf = compute_peer_id_binding_leaf_hash(operator, &peer_id);
        self.peer_id_binding_leaf_hashes.insert(operator.0, leaf);
        self.peer_id_bindings.insert(operator.0, peer_id);
    }

    /// Returns `true` iff any Active/Candidate/Jailed validator binds this
    /// on-chain libp2p PeerId — ADR-047.
    pub fn peer_id_in_use(&self, peer_id: &[u8]) -> bool {
        if peer_id.is_empty() {
            return false;
        }
        self.peer_id_bindings.iter().any(|(op_bytes, bound)| {
            if bound.as_slice() != peer_id {
                return false;
            }
            matches!(
                self.validators.get(op_bytes).map(|v| &v.status),
                Some(
                    ValidatorStatus::Active | ValidatorStatus::Candidate | ValidatorStatus::Jailed
                )
            )
        })
    }

    /// Iterator over `(operator, peer_id)` for every validator with a non-empty
    /// on-chain PeerId binding — ADR-047.
    pub fn validator_peer_id_bindings(&self) -> impl Iterator<Item = (Address, &[u8])> {
        self.peer_id_bindings
            .iter()
            .map(|(op_bytes, peer_id)| (Address(*op_bytes), peer_id.as_slice()))
    }

    /// Recompute the leaf hash for an already-stored validator after in-place mutation.
    ///
    /// Call this after `get_validator_mut()` + field modifications to keep the
    /// incremental state root consistent.
    pub fn commit_validator_mutation(&mut self, operator: &Address) {
        if let Some(record) = self.validators.get(&operator.0) {
            let leaf = compute_validator_leaf_hash(record);
            self.validator_leaf_hashes.insert(operator.0, leaf);
        }
    }

    /// Candidate validators sorted by `registered_height` ascending, then operator address
    /// for tie-breaking. Used by epoch transition activation queue (ADR-042).
    pub fn validator_candidates_ordered(&self) -> Vec<Address> {
        let mut candidates: Vec<&ValidatorRecord> = self
            .validators
            .values()
            .filter(|v| v.status == ValidatorStatus::Candidate)
            .collect();
        candidates.sort_by(|a, b| {
            a.registered_height
                .cmp(&b.registered_height)
                .then_with(|| a.operator.0.cmp(&b.operator.0))
        });
        candidates.iter().map(|v| v.operator.clone()).collect()
    }

    /// Transition a Candidate validator to Active at `epoch_boundary_height`.
    ///
    /// No-op if the validator does not exist or is not in Candidate status.
    /// Recomputes the validator leaf hash after mutation.
    pub fn activate_validator(&mut self, operator: &Address, epoch_boundary_height: u64) {
        if let Some(record) = self.validators.get_mut(&operator.0) {
            if record.status == ValidatorStatus::Candidate {
                record.status = ValidatorStatus::Active;
                let _ = epoch_boundary_height; // recorded for future use / logging
                let leaf = compute_validator_leaf_hash(record);
                self.validator_leaf_hashes.insert(operator.0, leaf);
            }
        }
    }

    /// Process epoch boundary transitions — ADR-042 + ADR-053 §T1.5.
    ///
    /// At each epoch boundary, activates pending validators up to the
    /// stake-weighted churn limit (`active_stake * activation_target_bps /
    /// 10_000`, clamped below by `activation_min_stake`). Candidates are
    /// drained in FIFO order (`validator_candidates_ordered`) and their
    /// self-bond is accumulated; iteration stops when the next candidate
    /// would push the cumulative stake past the limit. One candidate is
    /// always activated when the queue is non-empty (progress guarantee),
    /// so a freshly-bootstrapped network with zero Active stake is never
    /// stuck.
    ///
    /// Called by the block assembler after `advance_height()` at epoch
    /// boundaries. `epoch_duration` and `unbonding_period` are passed as
    /// primitives to avoid a circular crate dependency (pqc-state cannot
    /// depend on pqc-consensus).
    pub fn process_epoch_transitions(
        &mut self,
        epoch_boundary_height: u64,
        _epoch_duration: u64,
        _unbonding_period: u64,
        churn: &ChurnConfig,
    ) {
        let active_stake = self.active_self_bond_total();
        let limit = stake_weighted_activation_limit(active_stake, churn);

        let ordered = self.validator_candidates_ordered();
        let mut candidates: Vec<Address> = Vec::new();
        let mut accumulated: u128 = 0;
        for operator in ordered {
            let Some(record) = self.validators.get(&operator.0) else {
                continue;
            };
            let next_total = accumulated.saturating_add(record.self_bond);
            if next_total > limit && !candidates.is_empty() {
                break;
            }
            accumulated = next_total;
            candidates.push(operator);
        }

        let activated = candidates.len();
        for operator in candidates {
            self.activate_validator(&operator, epoch_boundary_height);
        }

        if activated > 0 {
            tracing::info!(
                epoch_boundary_height,
                activated,
                limit,
                active_stake,
                "epoch transition: validator activations"
            );
        }
    }

    /// Sum of `self_bond` across all Active validators (ADR-053 §T1.5).
    pub fn active_self_bond_total(&self) -> u128 {
        self.validators
            .values()
            .filter(|v| v.status == ValidatorStatus::Active)
            .map(|v| v.self_bond)
            .fold(0u128, |acc, s| acc.saturating_add(s))
    }

    /// Active validators sorted by operator address (for CommitQuorumPolicy).
    pub fn active_validators(&self) -> Vec<&ValidatorRecord> {
        let mut records: Vec<&ValidatorRecord> = self
            .validators
            .values()
            .filter(|v| v.status == ValidatorStatus::Active)
            .collect();
        records.sort_by_key(|v| v.operator.0);
        records
    }

    /// Count of validators currently in the Active state.
    pub fn active_validator_count(&self) -> usize {
        self.validators
            .values()
            .filter(|v| v.status == ValidatorStatus::Active)
            .count()
    }

    /// All validator records sorted by operator address for deterministic hashing.
    pub fn validators_in_order(&self) -> Vec<&ValidatorRecord> {
        let mut records: Vec<&ValidatorRecord> = self.validators.values().collect();
        records.sort_by_key(|v| v.operator.0);
        records
    }

    /// Process height-based Unbonding → Exited transitions.
    ///
    /// Called once per block after all transactions are applied. Returns the list of
    /// `(operator_address, returned_bond)` pairs for accounts that completed unbonding
    /// so the caller can credit balances. The caller (engine) is responsible for
    /// actually crediting the returned stake to operator accounts.
    pub fn process_validator_unbonding_expirations(
        &mut self,
        current_height: u64,
    ) -> Vec<(Address, u128)> {
        let mut exits: Vec<(Address, u128)> = Vec::new();
        for record in self.validators.values_mut() {
            if let ValidatorStatus::Unbonding { start_height } = record.status {
                if current_height >= start_height.saturating_add(VALIDATOR_UNBONDING_PERIOD) {
                    let bond = record.self_bond;
                    record.status = ValidatorStatus::Exited;
                    exits.push((record.operator.clone(), bond));
                }
            }
        }
        // Recompute leaf hashes for all transitioned validators.
        for (operator, _) in &exits {
            if let Some(record) = self.validators.get(&operator.0) {
                let leaf = compute_validator_leaf_hash(record);
                self.validator_leaf_hashes.insert(operator.0, leaf);
            }
        }
        exits
    }

    /// Returns true if any active or candidate validator uses this consensus public key.
    ///
    /// Used during `ValidatorRegister` to enforce uniqueness of consensus keys
    /// across the active and candidate sets (SPEC-VAL-001 §5.4).
    pub fn consensus_key_in_use(&self, pk: &[u8]) -> bool {
        self.validators.values().any(|v| {
            matches!(
                v.status,
                ValidatorStatus::Active | ValidatorStatus::Candidate
            ) && v.consensus_pk.as_slice() == pk
        })
    }

    pub fn get_governance_receipt(&self, proposal_id: &TxHash) -> Option<&GovernanceReceipt> {
        self.governance_receipts.get(proposal_id)
    }

    pub fn insert_governance_receipt(&mut self, receipt: GovernanceReceipt) {
        let leaf = compute_receipt_leaf_hash(&receipt);
        self.receipt_leaf_hashes
            .insert(receipt.proposal_id.clone(), leaf);
        self.governance_receipts
            .insert(receipt.proposal_id.clone(), receipt);
    }

    // ── Multi-step governance (TASK-100) ─────────────────────────────────────

    /// Look up a pending proposal by its proposal_id (read-only).
    pub fn get_pending_proposal(&self, id: &TxHash) -> Option<&PendingProposal> {
        self.pending_proposals.get(id)
    }

    /// Look up a pending proposal for mutation.
    ///
    /// Callers must call `commit_proposal_mutation` after finishing mutations.
    pub fn get_pending_proposal_mut(&mut self, id: &TxHash) -> Option<&mut PendingProposal> {
        self.pending_proposals.get_mut(id)
    }

    /// Insert a new pending proposal and compute its initial leaf hash.
    pub fn insert_pending_proposal(&mut self, proposal: PendingProposal) {
        let leaf = compute_proposal_leaf_hash(&proposal);
        self.proposal_leaf_hashes
            .insert(proposal.proposal_id.clone(), leaf);
        self.pending_proposals
            .insert(proposal.proposal_id.clone(), proposal);
    }

    /// Recompute the leaf hash for a pending proposal after in-place mutation.
    ///
    /// Must be called after any `get_pending_proposal_mut` + field modification
    /// to keep the incremental state root consistent.
    pub fn commit_proposal_mutation(&mut self, id: &TxHash) {
        if let Some(proposal) = self.pending_proposals.get(id) {
            let leaf = compute_proposal_leaf_hash(proposal);
            self.proposal_leaf_hashes.insert(id.clone(), leaf);
        }
    }

    /// All pending proposals sorted by proposal_id bytes for deterministic ordering.
    pub fn pending_proposals_in_order(&self) -> Vec<&PendingProposal> {
        let mut proposals: Vec<&PendingProposal> = self.pending_proposals.values().collect();
        proposals.sort_by_key(|p| p.proposal_id.0);
        proposals
    }

    // ── Software-upgrade tracking (ADR-031) ───────────────────────────────────

    /// Insert a newly-scheduled software upgrade and compute its initial leaf hash.
    pub fn insert_pending_upgrade(&mut self, upgrade: PendingUpgrade) {
        let leaf = compute_upgrade_leaf_hash(&upgrade);
        self.upgrade_leaf_hashes
            .insert(upgrade.proposal_id.clone(), leaf);
        self.pending_upgrades
            .insert(upgrade.proposal_id.clone(), upgrade);
    }

    /// Remove a pending upgrade that has been activated or superseded.
    pub fn remove_pending_upgrade(&mut self, id: &TxHash) {
        self.pending_upgrades.remove(id);
        self.upgrade_leaf_hashes.remove(id);
    }

    /// All pending upgrades sorted by `activate_at_timestamp_ns` for
    /// deterministic ordering (ADR-053 §T2.3).
    pub fn pending_upgrades_in_order(&self) -> Vec<&PendingUpgrade> {
        let mut upgrades: Vec<&PendingUpgrade> = self.pending_upgrades.values().collect();
        upgrades.sort_by_key(|u| (u.activate_at_timestamp_ns, u.proposal_id.0));
        upgrades
    }

    // ── Correlation penalty ledger (ADR-048, SPEC-SLASH-001 §17, D-02) ────────

    /// Sum of `slashed_stake` over all entries whose `height` is within the last
    /// `window_blocks` blocks ending at `current_height` (inclusive on both ends).
    pub fn recent_slashed_stake_in_window(&self, current_height: u64, window_blocks: u64) -> u128 {
        let cutoff = current_height.saturating_sub(window_blocks);
        self.recent_slashes
            .iter()
            .filter(|e| e.height >= cutoff && e.height <= current_height)
            .fold(0u128, |acc, e| acc.saturating_add(e.slashed_stake))
    }

    /// Append a new slash to the correlation ledger and recompute the leaf hash.
    pub fn record_recent_slash(&mut self, entry: RecentSlashEntry) {
        self.recent_slashes.push_back(entry);
        self.recent_slashes_leaf_hash = compute_recent_slashes_leaf_hash(&self.recent_slashes);
    }

    /// Remove ledger entries older than `cutoff_height` (`height < cutoff_height`).
    pub fn prune_recent_slashes_before(&mut self, cutoff_height: u64) {
        let mut changed = false;
        while let Some(front) = self.recent_slashes.front() {
            if front.height < cutoff_height {
                self.recent_slashes.pop_front();
                changed = true;
            } else {
                break;
            }
        }
        if changed {
            self.recent_slashes_leaf_hash = compute_recent_slashes_leaf_hash(&self.recent_slashes);
        }
    }

    /// Ledger snapshot for tests and diagnostics.
    pub fn recent_slashes_snapshot(&self) -> Vec<RecentSlashEntry> {
        self.recent_slashes.iter().cloned().collect()
    }

    // ── Slashing-verifier registry (ADR-050, ADR-042 §16, D-01) ───────────────

    /// Look up the slashing-verifier entry for a given evidence type.
    pub fn slashing_verifier_entry(&self, evidence_type: u8) -> Option<&SlashingVerifierEntry> {
        self.slashing_registry.get(&evidence_type)
    }

    /// Insert a governance-added slashing-verifier entry.  Called only from
    /// the tally path after `AddSlashingVerifier` validation succeeds.
    pub fn insert_slashing_verifier_entry(&mut self, entry: SlashingVerifierEntry) {
        let leaf = compute_slashing_verifier_leaf_hash(&entry);
        let key = entry.evidence_type;
        self.slashing_registry_leaf_hashes.insert(key, leaf);
        self.slashing_registry.insert(key, entry);
    }

    /// Return `true` if `evidence_type` is already registered.
    pub fn slashing_verifier_registered(&self, evidence_type: u8) -> bool {
        self.slashing_registry.contains_key(&evidence_type)
    }

    /// Recompute the leaf hash after an in-place field mutation via
    /// `slashing_verifier_entry_mut`.  Call this whenever the
    /// `slash_fraction_bps`, `jail_duration_blocks`, or `lifecycle` of an
    /// existing entry is updated so `state_root()` stays consistent.
    pub fn commit_slashing_verifier_mutation(&mut self, evidence_type: u8) {
        if let Some(entry) = self.slashing_registry.get(&evidence_type) {
            let leaf = compute_slashing_verifier_leaf_hash(entry);
            self.slashing_registry_leaf_hashes
                .insert(evidence_type, leaf);
        }
    }

    /// Slashing-verifier entries sorted by `evidence_type` for deterministic
    /// ordering (state-root folding, diagnostics).
    pub fn slashing_verifier_entries_in_order(&self) -> Vec<&SlashingVerifierEntry> {
        let mut entries: Vec<&SlashingVerifierEntry> = self.slashing_registry.values().collect();
        entries.sort_by_key(|e| e.evidence_type);
        entries
    }

    // ── Hash-function registry (ADR-053 §T1.4) ────────────────────────────────

    /// Look up the hash-function registry entry for a given `HashId`.
    pub fn hash_entry(&self, hash_id: HashId) -> Option<&HashEntry> {
        self.hash_registry.get(&hash_id.as_u8())
    }

    /// Insert a governance-added `HashEntry`.  Called only from the tally
    /// path after `AddHash` validation succeeds.
    pub fn insert_hash_entry(&mut self, entry: HashEntry) {
        let leaf = compute_hash_registry_leaf_hash(&entry);
        let key = entry.hash_id.as_u8();
        self.hash_registry_leaf_hashes.insert(key, leaf);
        self.hash_registry.insert(key, entry);
    }

    /// Return `true` if `hash_id` is already registered.
    pub fn hash_registered(&self, hash_id: HashId) -> bool {
        self.hash_registry.contains_key(&hash_id.as_u8())
    }

    /// Hash-registry entries sorted by `hash_id` for deterministic ordering.
    pub fn hash_registry_entries_in_order(&self) -> Vec<&HashEntry> {
        let mut entries: Vec<&HashEntry> = self.hash_registry.values().collect();
        entries.sort_by_key(|e| e.hash_id);
        entries
    }

    /// Return the governance-tunable slash fraction (basis points) for the
    /// given evidence type, falling back to
    /// `DEFAULT_EQUIVOCATION_SLASH_FRACTION_BPS` when the registry has no
    /// entry for this type (e.g. during restore from a pre-ADR-050
    /// checkpoint where the registry was not yet materialized).
    ///
    /// `apply_submit_equivocation_evidence` (pqc-state::apply::slashing,
    /// D-02 / TASK-097) reads the equivocation fraction via this helper in
    /// the next wiring pass — see ADR-050 §Consequences for the two-phase
    /// rollout plan.
    pub fn effective_slash_fraction_bps(&self, evidence_type: u8) -> u16 {
        self.slashing_registry
            .get(&evidence_type)
            .map(|e| e.slash_fraction_bps)
            .unwrap_or(DEFAULT_EQUIVOCATION_SLASH_FRACTION_BPS)
    }

    /// Total `self_bond` over all currently-Active validators, in venom units.
    pub fn total_active_self_bond(&self) -> u128 {
        self.validators
            .values()
            .filter(|v| v.status == ValidatorStatus::Active)
            .fold(0u128, |acc, v| acc.saturating_add(v.self_bond))
    }

    /// Returns true if the given address is an Active validator.
    pub fn is_active_validator(&self, addr: &Address) -> bool {
        self.validators
            .get(&addr.0)
            .map(|v| v.status == ValidatorStatus::Active)
            .unwrap_or(false)
    }

    // ── Archival overlay accessors (SPEC-ARCHIVAL-001, TASK-161) ─────────────

    /// Look up the archival record for `epoch_number`, if any.
    pub fn get_archival_record(
        &self,
        epoch_number: u64,
    ) -> Option<&pqc_types::archival::ArchivalRecord> {
        self.archival_records.get(&epoch_number)
    }

    /// Insert a freshly-admitted archival record; computes and caches its leaf hash.
    ///
    /// First-writer-wins is enforced upstream in the apply path; calling this
    /// with an already-present `epoch_number` overwrites silently (matching
    /// the other `insert_*` helpers in this module).
    pub(crate) fn insert_archival_record(&mut self, record: pqc_types::archival::ArchivalRecord) {
        let leaf = crate::apply::archival::compute_archival_record_leaf_hash(&record);
        let epoch = record.epoch_number;
        self.archival_record_leaf_hashes.insert(epoch, leaf);
        self.archival_records.insert(epoch, record);
    }

    /// Append a `TimestampAnchor` to the record for `epoch_number` and
    /// recompute the cached leaf hash. No-op if the record is absent (the
    /// apply path checks `get_archival_record` before calling).
    pub(crate) fn push_archival_anchor(
        &mut self,
        epoch_number: u64,
        anchor: pqc_types::archival::TimestampAnchor,
    ) {
        if let Some(record) = self.archival_records.get_mut(&epoch_number) {
            record.timestamp_anchors.push(anchor);
            let leaf = crate::apply::archival::compute_archival_record_leaf_hash(record);
            self.archival_record_leaf_hashes.insert(epoch_number, leaf);
        }
    }

    /// Bump `evidence_record_version` by one on the record for `epoch_number`
    /// and recompute its leaf hash. Records the RFC 4998 ERS bundle hash
    /// opaquely as a synthetic `TimestampAnchor` (the chain does not
    /// interpret the bundle; verification is offline per §7.5).
    pub(crate) fn increment_archival_record_version(
        &mut self,
        epoch_number: u64,
        ers_bundle_hash: [u8; 32],
        current_block_height: u64,
    ) {
        if let Some(record) = self.archival_records.get_mut(&epoch_number) {
            record.evidence_record_version = record.evidence_record_version.saturating_add(1);
            record
                .timestamp_anchors
                .push(pqc_types::archival::TimestampAnchor {
                    kind: pqc_types::archival::AnchorKind::Rfc3161Tsa,
                    tsa_ref: None,
                    external_hash: ers_bundle_hash.to_vec(),
                    posted_at_height: current_block_height,
                });
            let leaf = crate::apply::archival::compute_archival_record_leaf_hash(record);
            self.archival_record_leaf_hashes.insert(epoch_number, leaf);
        }
    }

    /// Look up a validator's archival key, if registered.
    pub fn get_archival_key(
        &self,
        operator: &Address,
    ) -> Option<&pqc_types::archival::ValidatorArchivalKey> {
        self.archival_keys.get(&operator.0)
    }

    /// Upsert a validator's archival key (resubmission == rotation).
    pub(crate) fn insert_archival_key(&mut self, key: pqc_types::archival::ValidatorArchivalKey) {
        let leaf = crate::apply::archival::compute_archival_key_leaf_hash(&key);
        let addr_bytes = key.operator;
        self.archival_key_leaf_hashes.insert(addr_bytes, leaf);
        self.archival_keys.insert(addr_bytes, key);
    }

    /// Returns true if `addr` is an archival signer.
    ///
    /// Membership rule: if the explicit `archival_signer_set` is non-empty,
    /// it is the authoritative list. Otherwise (genesis default), any Active
    /// validator with a registered archival key is admitted. This mirrors
    /// the SPEC §4.2 "bootstrap = full Active set" language.
    pub fn is_archival_signer(&self, addr: &Address) -> bool {
        if !self.archival_signer_set.is_empty() {
            return self.archival_signer_set.contains(&addr.0);
        }
        self.is_active_validator(addr) && self.archival_keys.contains_key(&addr.0)
    }

    /// Return the effective `(m, n)` archival threshold.
    ///
    /// If governance has set an explicit value, it is returned verbatim.
    /// Otherwise the default is `(ceil(2n/3), n)` over the current signer
    /// set (SPEC §4.3).
    pub fn archival_threshold(&self) -> (u16, u16) {
        if let Some(t) = self.archival_threshold_m_of_n {
            return t;
        }
        let n = if !self.archival_signer_set.is_empty() {
            self.archival_signer_set.len()
        } else {
            // Bootstrap: active validators with registered archival keys.
            self.validators
                .values()
                .filter(|v| v.status == ValidatorStatus::Active)
                .filter(|v| self.archival_keys.contains_key(&v.operator.0))
                .count()
        };
        let n_u16 = u16::try_from(n).unwrap_or(u16::MAX);
        let m = n_u16.saturating_mul(2).saturating_add(2) / 3;
        (m, n_u16)
    }

    /// Returns true if `addr` is a governance-registered archival renewer.
    pub(crate) fn is_archival_renewer(&self, addr: &Address) -> bool {
        self.archival_renewers.contains(&addr.0)
    }

    /// Insert `addr` into the archival signer set (test-only helper).
    ///
    /// In production this mutation happens via
    /// `ProposalEffect::UpdateArchivalSignerSet` (SPEC §14 O4, not wired in
    /// M4.2). Exposed under `pub(crate)` so tests can pin signer membership.
    #[allow(dead_code)]
    pub(crate) fn add_archival_signer(&mut self, addr: &Address) {
        self.archival_signer_set.insert(addr.0);
    }

    /// Insert `addr` into the archival renewer set (test-only helper).
    #[allow(dead_code)]
    pub(crate) fn add_archival_renewer(&mut self, addr: &Address) {
        self.archival_renewers.insert(addr.0);
    }

    /// Archival records sorted by `epoch_number` ascending — deterministic order.
    pub fn archival_records_in_order(&self) -> Vec<&pqc_types::archival::ArchivalRecord> {
        let mut records: Vec<&pqc_types::archival::ArchivalRecord> =
            self.archival_records.values().collect();
        records.sort_by_key(|r| r.epoch_number);
        records
    }

    /// Archival keys sorted by operator address — deterministic order.
    #[allow(dead_code)]
    pub fn archival_keys_in_order(&self) -> Vec<&pqc_types::archival::ValidatorArchivalKey> {
        let mut keys: Vec<&pqc_types::archival::ValidatorArchivalKey> =
            self.archival_keys.values().collect();
        keys.sort_by_key(|k| k.operator);
        keys
    }

    pub fn block_height(&self) -> u64 {
        self.block_height
    }

    /// Accounts sorted by address bytes for deterministic block assembly and hashing.
    pub fn accounts_in_order(&self) -> Vec<&Account> {
        let mut accounts: Vec<&Account> = self.accounts.values().collect();
        accounts.sort_by_key(|account| account.address.0);
        accounts
    }

    /// Attestation records sorted by attestation id for deterministic hashing.
    pub fn attestations_in_order(&self) -> Vec<&Attestation> {
        let mut attestations: Vec<&Attestation> = self.attestations.values().collect();
        attestations.sort_by_key(|attestation| attestation.attestation_id);
        attestations
    }

    /// Proof anchor records sorted by anchor id for deterministic hashing.
    pub fn proof_anchors_in_order(&self) -> Vec<&ProofAnchor> {
        let mut anchors: Vec<&ProofAnchor> = self.proof_anchors.values().collect();
        anchors.sort_by_key(|anchor| anchor.anchor_id);
        anchors
    }

    /// Governance receipts sorted by proposal_id for deterministic hashing.
    pub fn governance_receipts_in_order(&self) -> Vec<&GovernanceReceipt> {
        let mut receipts: Vec<&GovernanceReceipt> = self.governance_receipts.values().collect();
        receipts.sort_by_key(|receipt| receipt.proposal_id.0);
        receipts
    }

    /// Algorithm registry entries sorted by `alg_id` for deterministic state hashing.
    pub fn alg_entries_in_order(&self) -> Vec<&AlgEntry> {
        let mut entries: Vec<&AlgEntry> = self.alg_registry.values().collect();
        entries.sort_by_key(|entry| entry.alg_id.as_u16());
        entries
    }

    /// On-chain verifier registry snapshot — ADR-044.
    ///
    /// Returns entries for algorithms whose lifecycle currently admits transactions.
    /// Use this to build a `PqVerifier` or to validate algorithm acceptability
    /// without re-reading the full `AlgEntry` metadata.
    pub fn active_verifier_entries(&self) -> Vec<VerifierRegistryEntry> {
        self.alg_registry
            .values()
            .filter(|e| e.lifecycle.admits_transactions())
            .map(VerifierRegistryEntry::from_alg_entry)
            .collect()
    }

    /// Look up a single verifier registry entry by algorithm ID.
    pub fn verifier_entry(&self, alg_id: AlgId) -> Option<VerifierRegistryEntry> {
        self.alg_registry
            .get(&alg_id.as_u16())
            .map(VerifierRegistryEntry::from_alg_entry)
    }

    pub fn chain_id(&self) -> &[u8] {
        &self.chain_id
    }

    /// Set the host chain_id. Used by test fixtures and node-init paths that
    /// build an in-memory `StateStore` before applying any tx; ADR-053 §T1.3
    /// address derivation reads this value via `derive_address(store.chain_id(), …)`.
    pub fn set_chain_id(&mut self, chain_id: Vec<u8>) {
        self.chain_id = chain_id;
    }

    /// Compute the state root via a binary Merkle tree (ADR-053 §T3.1).
    ///
    /// # Algorithm (VIPER-STATE-ROOT-V3)
    ///
    /// 1. Build a canonically-ordered list of pre-tagged Merkle leaves.
    ///    Each leaf is `tagged_hash("VIPER-STATE-LEAF-V1", category_id ||
    ///    sort_key || category_leaf_hash)` where `category_id` is a 1-byte
    ///    discriminant from [`StateCategory`], and `sort_key` is the
    ///    canonical key for that category (e.g. address bytes for accounts,
    ///    `AttestationId` bytes for attestations, big-endian byte-encoded
    ///    integers for u8/u16/u64 keyspaces). Singleton categories
    ///    (block_height, fee_market, storage_fund, recent_slashes) carry
    ///    an empty sort_key.
    /// 2. Sort: categories enumerated in numeric `category_id` order; within
    ///    each category, leaves sorted by their natural key.
    /// 3. Fold: `binary_merkle_root` over the resulting `Vec<[u8; 32]>` with
    ///    branch domain `"VIPER-STATE-BRANCH-V1"`.
    ///
    /// # Topology and CVE-2012-2459
    ///
    /// Branching factor 2; odd nodes pair with self at each layer. The leaf
    /// and branch domains differ (`"VIPER-STATE-LEAF-V1"` vs
    /// `"VIPER-STATE-BRANCH-V1"`), so a leaf hash and an internal node hash
    /// can never collide — protecting the tree from the CVE-2012-2459
    /// attack class. The category-id prefix in each leaf payload also
    /// prevents cross-category collisions: an account leaf and an
    /// attestation leaf with byte-equal payloads are still distinct.
    ///
    /// # Stateless-client readiness
    ///
    /// The topology is "Tier-1-immutable in practice" per ADR-053 §T3.1 —
    /// once viper-pq-1 ships, the binary tree shape cannot change without
    /// state-migration effort on the order of Ethereum's Verkle → Binary
    /// abandonment. Witness generation against this tree is deferred per
    /// ADR-053 §T3.6 (the light client signs the root, not its members).
    ///
    /// # Cost
    ///
    /// O(N) leaf preparation + O(N) Merkle fold per call. The per-category
    /// caches (already populated on mutation) keep each leaf payload to 32
    /// bytes, so the dominant cost is the SHAKE-256 calls in the fold:
    /// roughly `2N` hashes for `N` total leaves.
    pub fn state_root(&self) -> [u8; 32] {
        let mut leaves: Vec<[u8; 32]> = Vec::new();

        // category 0x00: block_height (singleton, empty sort_key)
        leaves.push(state_merkle_leaf(
            StateCategory::BlockHeight,
            b"",
            &self.block_height.to_be_bytes(),
        ));

        // category 0x01: accounts (sort by 32-byte address)
        let mut account_leaves: Vec<(&[u8; 32], &[u8; 32])> =
            self.account_leaf_hashes.iter().collect();
        account_leaves.sort_by_key(|(addr, _)| *addr);
        for (addr, leaf) in &account_leaves {
            leaves.push(state_merkle_leaf(StateCategory::Account, *addr, *leaf));
        }

        // category 0x02: attestations (sort by AttestationId bytes)
        let mut attestation_leaves: Vec<(&AttestationId, &[u8; 32])> =
            self.attestation_leaf_hashes.iter().collect();
        attestation_leaves.sort_by_key(|(id, _)| *id);
        for (id, leaf) in &attestation_leaves {
            leaves.push(state_merkle_leaf(StateCategory::Attestation, &id.0, *leaf));
        }

        // category 0x03: proof anchors (sort by AnchorId bytes)
        let mut proof_anchor_leaves: Vec<(&AnchorId, &[u8; 32])> =
            self.proof_anchor_leaf_hashes.iter().collect();
        proof_anchor_leaves.sort_by_key(|(id, _)| *id);
        for (id, leaf) in &proof_anchor_leaves {
            leaves.push(state_merkle_leaf(StateCategory::ProofAnchor, &id.0, *leaf));
        }

        // category 0x04: consensus key rotations (sort by 32-byte address)
        let mut rotation_leaves: Vec<(&[u8; 32], &[u8; 32])> =
            self.consensus_rotation_leaf_hashes.iter().collect();
        rotation_leaves.sort_by_key(|(addr, _)| *addr);
        for (addr, leaf) in &rotation_leaves {
            leaves.push(state_merkle_leaf(
                StateCategory::ConsensusRotation,
                *addr,
                *leaf,
            ));
        }

        // category 0x05: algorithm registry (sort by u16 alg_id, big-endian)
        let mut alg_leaves: Vec<(&u16, &[u8; 32])> = self.alg_leaf_hashes.iter().collect();
        alg_leaves.sort_by_key(|(alg_id, _)| *alg_id);
        for (alg_id, leaf) in &alg_leaves {
            leaves.push(state_merkle_leaf(
                StateCategory::AlgRegistry,
                &alg_id.to_be_bytes(),
                *leaf,
            ));
        }

        // category 0x06: governance receipts (sort by TxHash bytes)
        let mut receipt_leaves: Vec<(&TxHash, &[u8; 32])> =
            self.receipt_leaf_hashes.iter().collect();
        receipt_leaves.sort_by_key(|(id, _)| id.0);
        for (id, leaf) in &receipt_leaves {
            leaves.push(state_merkle_leaf(StateCategory::Receipt, &id.0, *leaf));
        }

        // category 0x07: validators (sort by 32-byte address)
        let mut validator_leaves: Vec<(&[u8; 32], &[u8; 32])> =
            self.validator_leaf_hashes.iter().collect();
        validator_leaves.sort_by_key(|(addr, _)| *addr);
        for (addr, leaf) in &validator_leaves {
            leaves.push(state_merkle_leaf(StateCategory::Validator, *addr, *leaf));
        }

        // category 0x08: pending governance proposals (sort by TxHash bytes) — TASK-100
        let mut proposal_leaves: Vec<(&TxHash, &[u8; 32])> =
            self.proposal_leaf_hashes.iter().collect();
        proposal_leaves.sort_by_key(|(id, _)| id.0);
        for (id, leaf) in &proposal_leaves {
            leaves.push(state_merkle_leaf(StateCategory::Proposal, &id.0, *leaf));
        }

        // category 0x09: pending software upgrades (sort by TxHash bytes) — ADR-031
        let mut upgrade_leaves: Vec<(&TxHash, &[u8; 32])> =
            self.upgrade_leaf_hashes.iter().collect();
        upgrade_leaves.sort_by_key(|(id, _)| id.0);
        for (id, leaf) in &upgrade_leaves {
            leaves.push(state_merkle_leaf(StateCategory::Upgrade, &id.0, *leaf));
        }

        // category 0x0A: fee market (singleton) — SPEC-FEE-002 §10, ADR-053 §T2.1
        leaves.push(state_merkle_leaf(
            StateCategory::FeeMarket,
            b"",
            &self.fee_market_leaf_hash,
        ));

        // category 0x0B: storage fund (singleton) — ADR-053 §T2.2
        // Elided in tokenless builds — viper-research-1 state_root has no
        // storage-fund leaf, by design (different chain, different root).
        #[cfg(feature = "token_economics")]
        leaves.push(state_merkle_leaf(
            StateCategory::StorageFund,
            b"",
            &self.storage_fund_leaf_hash,
        ));

        // category 0x0C: recent-slashes ledger (singleton) — SPEC-SLASH-001 §17.4
        leaves.push(state_merkle_leaf(
            StateCategory::RecentSlashes,
            b"",
            &self.recent_slashes_leaf_hash,
        ));

        // category 0x0D: PeerId bindings (sort by 32-byte address) — ADR-047
        let mut peer_binding_leaves: Vec<(&[u8; 32], &[u8; 32])> =
            self.peer_id_binding_leaf_hashes.iter().collect();
        peer_binding_leaves.sort_by_key(|(addr, _)| *addr);
        for (addr, leaf) in &peer_binding_leaves {
            leaves.push(state_merkle_leaf(
                StateCategory::PeerIdBinding,
                *addr,
                *leaf,
            ));
        }

        // category 0x0E: slashing-verifier registry (sort by u8 evidence_type) — ADR-050
        let mut slashing_leaves: Vec<(&u8, &[u8; 32])> =
            self.slashing_registry_leaf_hashes.iter().collect();
        slashing_leaves.sort_by_key(|(ev_type, _)| *ev_type);
        for (ev_type, leaf) in &slashing_leaves {
            leaves.push(state_merkle_leaf(
                StateCategory::SlashingRegistry,
                std::slice::from_ref(*ev_type),
                *leaf,
            ));
        }

        // category 0x0F: hash-function registry (sort by u8 hash_id) — ADR-053 §T1.4
        let mut hash_leaves: Vec<(&u8, &[u8; 32])> =
            self.hash_registry_leaf_hashes.iter().collect();
        hash_leaves.sort_by_key(|(hash_id, _)| *hash_id);
        for (hash_id, leaf) in &hash_leaves {
            leaves.push(state_merkle_leaf(
                StateCategory::HashRegistry,
                std::slice::from_ref(*hash_id),
                *leaf,
            ));
        }

        // category 0x10: archival records (sort by u64 epoch, big-endian) — SPEC-ARCHIVAL-001 §5
        let mut archival_record_leaves: Vec<(&u64, &[u8; 32])> =
            self.archival_record_leaf_hashes.iter().collect();
        archival_record_leaves.sort_by_key(|(ep, _)| *ep);
        for (ep, leaf) in &archival_record_leaves {
            leaves.push(state_merkle_leaf(
                StateCategory::ArchivalRecord,
                &ep.to_be_bytes(),
                *leaf,
            ));
        }

        // category 0x11: archival keys (sort by 32-byte address) — SPEC-ARCHIVAL-001 §5
        let mut archival_key_leaves: Vec<(&[u8; 32], &[u8; 32])> =
            self.archival_key_leaf_hashes.iter().collect();
        archival_key_leaves.sort_by_key(|(addr, _)| *addr);
        for (addr, leaf) in &archival_key_leaves {
            leaves.push(state_merkle_leaf(StateCategory::ArchivalKey, *addr, *leaf));
        }

        binary_merkle_root(&leaves, STATE_BRANCH_DOMAIN)
    }

    /// Return the current adaptive base fee for the compute dimension
    /// (venom) — SPEC-FEE-002 §6 + ADR-053 §T2.1. Backwards-compatible
    /// scalar accessor; callers touching multi-dim features should read
    /// `self.fee_market.compute` directly.
    pub fn base_fee_dynamic(&self) -> u64 {
        self.fee_market.compute.base_fee
    }

    /// Restore the fee market state from a trusted checkpoint snapshot.
    ///
    /// MUST be called after `from_snapshot_full` / `from_snapshot_full_with_proofs`
    /// when deserializing a checkpoint that persisted `fee_market`. Recomputes
    /// the cached leaf hash so `state_root()` is consistent with the snapshot.
    ///
    /// Do NOT call this during normal block production — use `apply_aimd_update` instead.
    pub fn restore_fee_market(&mut self, fee_market: FeeMarketState) {
        self.fee_market_leaf_hash = compute_fee_market_leaf_hash(&fee_market);
        self.fee_market = fee_market;
    }

    /// Recompute the cached fee market leaf hash after a direct field mutation.
    ///
    /// Call after any direct write to `store.fee_market.*` fields (e.g., from
    /// governance tally execution). Using `apply_aimd_update` during block
    /// production automatically recomputes this — call this only when a
    /// governance effect directly changes `burn_rate_bps` or `block_gas_limit`.
    pub fn recompute_fee_market_leaf_hash(&mut self) {
        self.fee_market_leaf_hash = compute_fee_market_leaf_hash(&self.fee_market);
    }

    /// Restore the storage fund from a trusted checkpoint snapshot —
    /// ADR-053 §T2.2. Recomputes the cached leaf hash so `state_root()`
    /// stays consistent with the snapshot.
    #[cfg(feature = "token_economics")]
    pub fn restore_storage_fund(&mut self, fund: crate::storage_fund::StorageFundState) {
        self.storage_fund_leaf_hash = compute_storage_fund_leaf_hash(&fund);
        self.storage_fund = fund;
    }

    /// Recompute the cached storage fund leaf hash after a direct field
    /// mutation (e.g., parameter update from governance).
    #[cfg(feature = "token_economics")]
    pub fn recompute_storage_fund_leaf_hash(&mut self) {
        self.storage_fund_leaf_hash = compute_storage_fund_leaf_hash(&self.storage_fund);
    }

    /// Credit the storage fund (state-create path). Recomputes the
    /// cached leaf hash. Saturating on `u128` overflow.
    #[cfg(feature = "token_economics")]
    pub fn credit_storage_fund(&mut self, amount: u128) {
        self.storage_fund.credit(amount);
        self.recompute_storage_fund_leaf_hash();
    }

    /// Debit the storage fund (state-delete rebate path). Returns the
    /// amount actually debited (capped at current balance). Recomputes
    /// the cached leaf hash.
    #[cfg(feature = "token_economics")]
    pub fn debit_storage_fund(&mut self, amount: u128) -> u128 {
        let debited = self.storage_fund.debit(amount);
        self.recompute_storage_fund_leaf_hash();
        debited
    }

    /// Apply one round of the EIP-4844 exponential fee-market update
    /// (ADR-053 §T2.1 / SPEC-FEE-002 revised §6.2) to every active
    /// dimension.
    ///
    /// The caller passes per-dimension usage; only the compute dimension
    /// is wired to real tx activity at launch (`compute_used = block
    /// gas_used`). The other three dimensions receive 0 and — combined
    /// with `target = 0` — their excess never moves off zero and their
    /// base fee stays pinned at `reserve_floor` until a future
    /// P-COMPAT-001 upgrade activates them.
    ///
    /// Update rule per dimension:
    /// 1. `new_excess = saturating_sub(prev_excess + used, target)` —
    ///    excess accumulates above target, collapses to zero when under.
    /// 2. `new_base_fee = fake_exponential(reserve_floor, new_excess,
    ///    reserve_floor × update_fraction)` — EIP-4844 exponential curve.
    /// 3. Clamp into `[reserve_floor, BASE_FEE_MAX]`. The floor is
    ///    ungovernable (ADR-053 §T2.1).
    ///
    /// Must be called once per block after all `apply_tx` calls and
    /// `distribute_block_fees`, and before `advance_height()`.
    pub fn apply_fee_market_step(
        &mut self,
        compute_used: u64,
        storage_used: u64,
        witness_used: u64,
        contention_used: u64,
    ) {
        fn step(dim: &mut FeeMarketDimension, used: u64) {
            let sum = dim.excess.saturating_add(used);
            dim.excess = sum.saturating_sub(dim.target);
            let denom_mul = dim.reserve_floor.saturating_mul(dim.update_fraction);
            let raw = fake_exponential(dim.reserve_floor, dim.excess, denom_mul);
            dim.base_fee = raw.clamp(dim.reserve_floor, BASE_FEE_MAX);
        }
        step(&mut self.fee_market.compute, compute_used);
        step(&mut self.fee_market.storage, storage_used);
        step(&mut self.fee_market.witness, witness_used);
        step(&mut self.fee_market.contention, contention_used);
        self.fee_market_leaf_hash = compute_fee_market_leaf_hash(&self.fee_market);
    }

    /// Backward-compatible alias: drive the compute dimension only.
    /// Existing callers (engine, recovery) continue to pass the scalar
    /// block gas used; storage/witness/contention stay at zero.
    pub fn apply_aimd_update(&mut self, block_gas_used: u64) {
        self.apply_fee_market_step(block_gas_used, 0, 0, 0);
    }

    /// Advance the block height by one and activate any `Pending` keys whose
    /// `valid_from_height` has been reached.
    ///
    /// Uses `>=` so that a checkpoint restore at a height past the activation
    /// point still activates keys that were never explicitly advanced through.
    /// This is safe because `Revoked` keys are never re-activated (only
    /// `Pending` → `Active` is permitted here; `Active` and `Revoked` are left
    /// unchanged). SPEC-ACCOUNT-001 §4.
    pub fn advance_height(&mut self) {
        self.block_height += 1;
        // Collect addresses of accounts with keys that activate at this height.
        let activating: Vec<[u8; 32]> = self
            .accounts
            .values_mut()
            .filter_map(|account| {
                let mut changed = false;
                for key in account.keys.0.iter_mut() {
                    if key.status == KeyStatus::Pending
                        && self.block_height >= key.valid_from_height
                    {
                        key.status = KeyStatus::Active;
                        changed = true;
                    }
                }
                if changed {
                    Some(account.address.0)
                } else {
                    None
                }
            })
            .collect();
        // Recompute leaf hashes for all accounts that had keys activated.
        for addr in activating {
            if let Some(account) = self.accounts.get(&addr) {
                let leaf = compute_account_leaf_hash(account);
                self.account_leaf_hashes.insert(addr, leaf);
            }
        }
    }
}

impl Default for StateStore {
    fn default() -> Self {
        Self::new()
    }
}

/// `StateView` implementation for the in-memory StateStore.
///
/// `chain_id` is wired from genesis config via `from_snapshot_accounts`.
/// `StateStore::new()` leaves it empty, which is correct for tests whose
/// transactions also use an empty `chain_id`.
impl pqc_tx::state_view::StateView for StateStore {
    fn get_account(
        &self,
        addr: &pqc_types::account::Address,
    ) -> Option<&pqc_types::account::Account> {
        self.accounts.get(&addr.0)
    }

    fn alg_lifecycle(&self, alg_id: pqc_crypto::AlgId) -> Option<pqc_crypto::Lifecycle> {
        self.alg_registry.get(&alg_id.as_u16()).map(|e| e.lifecycle)
    }

    fn alg_sig_class(&self, alg_id: pqc_crypto::AlgId) -> Option<pqc_crypto::SigClass> {
        self.alg_registry
            .get(&alg_id.as_u16())
            .and_then(|e| e.sig_class)
    }

    fn alg_min_fee(&self, alg_id: pqc_crypto::AlgId) -> Option<u64> {
        self.alg_registry.get(&alg_id.as_u16()).map(|e| e.min_fee)
    }

    fn chain_id(&self) -> &[u8] {
        &self.chain_id
    }

    fn current_height(&self) -> u64 {
        self.block_height
    }

    fn base_fee_dynamic(&self) -> u64 {
        self.fee_market.compute.base_fee
    }
}

// ── EIP-4844 fee-market pin tests (ADR-053 §T2.1 / SPEC-FEE-002 revised) ─────
//
// These tests pin the `apply_fee_market_step()` / `fake_exponential()`
// implementation to the curve shape mandated by ADR-053 §T2.1:
// EIP-4844 exponential update driven by accumulated excess, with a
// non-zero reserve-price floor that governance MUST NOT set to zero.
// The AIMD-era Examples A–D are superseded — the update rule changed.

#[cfg(test)]
mod tests;

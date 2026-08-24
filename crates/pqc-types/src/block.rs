// SPDX-License-Identifier: Apache-2.0
//! Block and commit types — SPEC-VAL-001 §6, ADR-053 §T1.1.

use crate::transaction::TxHash;

/// 32-byte block hash / state root.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BlockHash(pub [u8; 32]);

/// `BlockHeader.header_version` for viper-pq-1 genesis onwards
/// (ADR-053 §T1.1). Every future mandatory-field-adding upgrade
/// bumps this via a P-COMPAT-001 dual-path landing — legacy readers
/// dispatch on the version, never on field count.
pub const HEADER_VERSION_V1: u16 = 1;

/// Canonical value of [`BlockHeader::extension_root`] when the
/// extension map is empty (ADR-053 §T1.1 + §T2.4). Computed as the
/// BIP340 double-tagged hash
/// `tagged_hash("VIPER-EXT-EMPTY-V1", &[])` and cached at first access.
///
/// The viper-pq-1 genesis block and every v1 block ships with this
/// value. A non-empty extension map appears only after a future
/// P-COMPAT-001 upgrade registers a new extension field.
pub fn empty_extension_root() -> [u8; 32] {
    static CACHE: std::sync::OnceLock<[u8; 32]> = std::sync::OnceLock::new();
    *CACHE.get_or_init(|| pqc_crypto::tagged_hash(b"VIPER-EXT-EMPTY-V1", &[]))
}

// === Reserved extension-root map keys (ADR-053 §T3.4) =====================
//
// Keys reserved at genesis under viper-pq-1 v1. None of them are
// implemented; the extension map is required to be empty (its root is
// always [`empty_extension_root`]) and any header populating these
// keys MUST fail validation in v1. They exist so a future
// P-COMPAT-001 upgrade can land ePBS / builder-bid commitments
// without re-renumbering the CBOR key allocation (see TASKS.md
// TASK-190 for the 0x20-0x2f reserved-range comment, and ADR-053
// §T3.4 for the rationale: "cost at genesis: two reserved keys; cost
// of adding later without reservation: a Pectra-magnitude
// header-layout-breaking hard fork").
//
// The keys are CBOR text-string keys (not the `u16` slot keys in the
// flat header struct) — the extension map is a separate `text -> bytes`
// CBOR map keyed by these constants. Renaming any of these strings
// is a Tier-1 protocol break and is guarded by the pin-tests below.

/// Reserved extension-root key — ePBS execution payload commitment
/// (ADR-053 §T3.4). NOT YET IMPLEMENTED. Reserved at genesis to avoid
/// a Pectra-magnitude hard fork if ePBS lands later. Any header
/// claiming this key MUST fail validation under viper-pq-1 v1 because
/// the extension map is required to be empty. The constant exists so
/// future ADR landings can grep this name and find the reservation.
pub const EXT_KEY_EXEC_PAYLOAD_ROOT: &str = "exec_payload_root";

/// Reserved extension-root key — proposer-builder separation bid
/// commitment (ADR-053 §T3.4). Same status as
/// [`EXT_KEY_EXEC_PAYLOAD_ROOT`]: reserved, not implemented, rejected
/// in v1.
pub const EXT_KEY_BUILDER_BID_COMMITMENT: &str = "builder_bid_commitment";

/// Block header — viper-pq-1 v1 layout (ADR-053 §T1.1).
///
/// ## Field-ordering discipline (P-COMPAT-001)
///
/// Fields are serialised in struct-declaration order (serde with
/// default CBOR codec). **Never** reorder existing fields; new
/// mandatory fields must land via a `header_version` bump + a dual-path
/// decoder (ADR-052 Policy P-COMPAT-001 §2). New optional fields
/// should be carried in [`Self::extension_root`] instead of
/// consuming a struct slot, unless there is a specific reason the
/// field must live in the flat layout.
///
/// ## `header_version`
///
/// The version tag that every consumer must read first. At launch
/// this is [`HEADER_VERSION_V1`]. A viper-pq-1-aware binary rejects
/// headers with versions it does not know how to decode.
///
/// ## `timestamp`
///
/// **Unix nanoseconds** at viper-pq-1 onwards (ADR-053 §T1.1). The
/// pre-viper-pq-1 convention of Unix *seconds* is retired — a `u64`
/// in nanoseconds carries well beyond year 2554 (Bitcoin's uint32
/// year-2106 problem reshapes), and the monotone-increase consensus
/// rule remains the authoritative ordering.
///
/// Monotone increase is enforced. The value is informational only;
/// it never drives consensus ordering.
///
/// ## `extension_root`
///
/// A 32-byte commitment to a future key→value extension map (ADR-053
/// §T1.1). At v1 launch this is always [`empty_extension_root`]; a
/// future P-COMPAT-001 upgrade that adds a new block-header
/// commitment writes the map root here. Two map keys are
/// pre-reserved at genesis for ePBS readiness (ADR-053 §T3.4):
/// [`EXT_KEY_EXEC_PAYLOAD_ROOT`] and [`EXT_KEY_BUILDER_BID_COMMITMENT`].
/// Both are unimplemented in v1 — they are name reservations only,
/// pinned by the unit tests in this module.
#[derive(Debug, Clone)]
pub struct BlockHeader {
    pub header_version: u16,
    pub height: u64,
    pub prev_hash: BlockHash,
    pub state_root: BlockHash,
    pub tx_root: BlockHash,
    pub timestamp: u64,
    pub proposer: Vec<u8>, // validator address (32 bytes)
    pub extension_root: [u8; 32],
}

impl Default for BlockHeader {
    /// Default header for test fixtures and builder patterns. Sets
    /// `header_version = HEADER_VERSION_V1` and
    /// `extension_root = empty_extension_root()` — both the values
    /// a real v1 producer would emit. Other fields are zero/empty
    /// so callers can override only the ones under test via struct
    /// update syntax (`BlockHeader { height, proposer, ..Default::default() }`).
    fn default() -> Self {
        Self {
            header_version: HEADER_VERSION_V1,
            height: 0,
            prev_hash: BlockHash([0u8; 32]),
            state_root: BlockHash([0u8; 32]),
            tx_root: BlockHash([0u8; 32]),
            timestamp: 0,
            proposer: Vec::new(),
            extension_root: empty_extension_root(),
        }
    }
}

/// A finalized block.
#[derive(Debug, Clone)]
pub struct Block {
    pub header: BlockHeader,
    pub tx_hashes: Vec<TxHash>,
    /// Aggregated commit signatures from the quorum.
    /// Size depends on algorithm: ML-DSA-65 at 24v ≈ 56 KB (SPEC-VAL-001 §5.2).
    pub commit_signatures: Vec<CommitSig>,
}

/// A single validator's commit signature for a block.
///
/// SPEC-CONSENSUS-001 §10.4 — "CommitSig is a Precommit message with a
/// valid signature". The `round` field carries the BFT round the
/// signer was in when the Precommit was signed; this is required so
/// §10.1 "Precommits from different rounds MAY be combined if they
/// all reference the same `block_hash(B)`" is implementable at
/// verification time (the verifier rebuilds the §8.4 vote preimage
/// per-sig using THAT sig's `round`).
///
/// For legacy devnet-2 blocks signed before ADR-051 (commit
/// preimage `"PQC-COMMIT-V1" || height || block_hash`), `round` is
/// NOT part of the preimage — the field is still present but ignored
/// by the legacy verification path (`CommitPreimageMode::Legacy`).
#[derive(Debug, Clone)]
pub struct CommitSig {
    pub validator_address: Vec<u8>,
    pub sig_alg_id: pqc_crypto::AlgId,
    /// BFT round this Precommit was signed at — SPEC-CONSENSUS-001
    /// §8.4 / §10.1 (ADR-051 / TASK-171). Zero on legacy-mode blocks
    /// (the field is present on the wire but does not participate in
    /// preimage construction for Legacy mode).
    pub round: u32,
    pub signature: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ADR-053 §T3.4 — the two reserved ePBS keys must be non-empty
    /// and distinct from each other. A regression here would mean
    /// somebody silenced one of the reservations or collapsed both
    /// into the same string.
    #[test]
    fn reserved_ext_keys_are_nonempty_and_distinct() {
        const _: () = assert!(!EXT_KEY_EXEC_PAYLOAD_ROOT.is_empty());
        const _: () = assert!(!EXT_KEY_BUILDER_BID_COMMITMENT.is_empty());
        assert_ne!(EXT_KEY_EXEC_PAYLOAD_ROOT, EXT_KEY_BUILDER_BID_COMMITMENT);
    }

    /// The reserved-key constants are name reservations only — they
    /// must not perturb the canonical empty-extension-root value.
    /// Adding a `pub const &str` cannot affect the cached
    /// `tagged_hash("VIPER-EXT-EMPTY-V1", &[])`, but pin it
    /// explicitly so a future refactor that (incorrectly) folds the
    /// keys into the empty-map preimage trips this test.
    #[test]
    fn empty_extension_root_unchanged_by_reservations() {
        let direct = pqc_crypto::tagged_hash(b"VIPER-EXT-EMPTY-V1", &[]);
        assert_eq!(empty_extension_root(), direct);
        // And calling it twice (cache hit) yields the same value.
        assert_eq!(empty_extension_root(), empty_extension_root());
    }

    /// Pin-test: the byte string of each reserved extension-map key.
    /// Renaming either constant — even cosmetically — is a Tier-1
    /// protocol break under viper-pq-1 mainnet-discipline (ADR-053
    /// §T3.4 / Policy P-COMPAT-001) and MUST trip this test loudly.
    /// If you legitimately need to change a key, that is a new ADR
    /// and a `header_version` bump.
    #[test]
    fn reserved_ext_keys_byte_pin() {
        assert_eq!(EXT_KEY_EXEC_PAYLOAD_ROOT.as_bytes(), b"exec_payload_root");
        assert_eq!(
            EXT_KEY_BUILDER_BID_COMMITMENT.as_bytes(),
            b"builder_bid_commitment"
        );
    }
}

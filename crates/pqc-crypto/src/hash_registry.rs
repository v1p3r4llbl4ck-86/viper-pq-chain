// SPDX-License-Identifier: Apache-2.0
//! On-chain hash-function registry — ADR-053 §T1.4.
//!
//! The registry maps a single-byte `HashId` discriminant to a `HashEntry`
//! describing the hash function's static parameters. `viper-pq-1` genesis
//! seeds a single entry `{0x01 = SHAKE-256}` (NIST FIPS 202); governance
//! can add further entries (BLAKE3, Poseidon, …) via
//! `ProposalEffect::AddHash` (symmetric to `AddAlgorithm`, ADR-049).
//!
//! At launch the protocol hard-codes SHAKE-256 in every hash-using call
//! site (via the primitives in [`super::hash`]). The registry is a
//! **forward-compatibility anchor**: it reserves on-chain the shape of
//! hash-function identity so a future Tier-3 change can dispatch on
//! `HashId` without a state-format migration. The Ethereum keccak-vs-SHA3
//! lesson: an unnamed hash function pins a chain forever.

use crate::alg::Lifecycle;
use std::borrow::Cow;

/// Sentinel: any `HashId == 0x00` must be rejected at every entry point.
pub const HASH_ID_SENTINEL: u8 = 0x00;

/// Genesis entry: SHAKE-256 (NIST FIPS 202) with 32-byte digest.
pub const HASH_ID_SHAKE_256: u8 = 0x01;

/// Inclusive upper bound of the core-reserved range `0x01..=0x0F`.
///
/// Entries in this range are code-governed: a coordinated
/// `SoftwareUpgrade` (ADR-031) is required to add/update them.
/// Governance `AddHash` proposals targeting the reserved range are
/// rejected at decode time (`ReservedHashIdRange`).
pub const HASH_CORE_RESERVED_MAX: u8 = 0x0F;

/// Single-byte identifier for a hash function in the on-chain registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct HashId(pub u8);

impl HashId {
    /// SHAKE-256 (NIST FIPS 202) — genesis entry.
    pub const SHAKE_256: HashId = HashId(HASH_ID_SHAKE_256);

    pub fn as_u8(self) -> u8 {
        self.0
    }

    pub fn from_u8(raw: u8) -> Option<Self> {
        if raw == HASH_ID_SENTINEL {
            None
        } else {
            Some(Self(raw))
        }
    }
}

/// Per-hash-function static parameters held on-chain.
///
/// `spec_ref` accepts either a `&'static str` (for the genesis hardcoded
/// baseline) or an owned `String` (for governance-added entries landed
/// via `ProposalEffect::AddHash`). Mirrors the `AlgEntry` shape so both
/// registries participate in the same governance machinery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashEntry {
    pub hash_id: HashId,
    pub spec_ref: Cow<'static, str>,
    /// Canonical output size in bytes. For an XOF (e.g. SHAKE-256) this is
    /// the protocol-default digest width, not the XOF's theoretical cap.
    pub output_size_bytes: u32,
    pub lifecycle: Lifecycle,
}

impl HashEntry {
    /// Construct a `HashEntry` from an owned `String` `spec_ref` — used by
    /// the governance `AddHash` proposal. Genesis callers should build the
    /// struct literal directly using `Cow::Borrowed(...)`.
    pub fn new_governance(
        hash_id: HashId,
        spec_ref: String,
        output_size_bytes: u32,
        lifecycle: Lifecycle,
    ) -> Self {
        Self {
            hash_id,
            spec_ref: Cow::Owned(spec_ref),
            output_size_bytes,
            lifecycle,
        }
    }
}

/// Genesis hash-function registry — seeded into `StateStore::new()`.
///
/// Single entry at launch: `{0x01 = SHAKE-256, output = 32 bytes, Active}`.
/// Any subsequent entry must arrive via `ProposalEffect::AddHash` (code
/// path also requires a `SoftwareUpgrade` since dispatch on `HashId` is
/// not yet wired at launch).
pub fn phase1_hash_registry() -> Vec<HashEntry> {
    vec![HashEntry {
        hash_id: HashId::SHAKE_256,
        spec_ref: Cow::Borrowed("FIPS 202 (SHAKE-256)"),
        output_size_bytes: 32,
        lifecycle: Lifecycle::Active,
    }]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sentinel_rejected() {
        assert_eq!(HashId::from_u8(HASH_ID_SENTINEL), None);
    }

    #[test]
    fn shake256_constant_matches() {
        assert_eq!(HashId::SHAKE_256.as_u8(), HASH_ID_SHAKE_256);
    }

    #[test]
    fn phase1_registry_is_single_shake256() {
        let r = phase1_hash_registry();
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].hash_id, HashId::SHAKE_256);
        assert_eq!(r[0].output_size_bytes, 32);
        assert_eq!(r[0].lifecycle, Lifecycle::Active);
    }

    #[test]
    fn reserved_range_is_contiguous_and_nonzero() {
        assert_eq!(HASH_ID_SENTINEL, 0x00);
        assert_eq!(HASH_ID_SHAKE_256, 0x01);
        assert_eq!(HASH_CORE_RESERVED_MAX, 0x0F);
        // First governance-assignable slot is 0x10.
        // Use static assertion so clippy::assertions_on_constants doesn't flag it.
        const _: () = assert!(HASH_CORE_RESERVED_MAX < 0x10);
    }
}

// SPDX-License-Identifier: Apache-2.0
//! Algorithm identifiers and lifecycle states.
//!
//! SPEC-ACCOUNT-001 §7 — Algorithm Registry initial entries.
//!
//! # Multicodec equivalence
//!
//! Viper's canonical algorithm encoding is the `u16_le` value embedded
//! in the TLV envelope (ADR-044). For cross-ecosystem tooling (IPFS,
//! libp2p stream protocols, multibase content addressing) a separate
//! multicodec varint identifier is reserved per algorithm — see
//! `docs/multicodec-mapping.md` (TASK-221) for the mapping table and
//! the upstream `multiformats/multicodec` PR template. The two
//! namespaces are intentionally separate; the multicodec value never
//! appears on Viper's wire — it exists only for cross-ecosystem
//! cross-references.

/// On-chain algorithm identifier (u16).
///
/// Values are assigned once and never reused, even after an algorithm is banned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum AlgId {
    /// ML-DSA-44 (FIPS 204, NIST Level 2). Multicodec: `mldsa44-pub`
    /// (proposed `0x1200`, pending upstream PR per `docs/multicodec-mapping.md`).
    MlDsa44 = 0x0001,
    /// ML-DSA-65 (FIPS 204, NIST Level 3) — default transaction signature
    /// algorithm. Multicodec: `mldsa65-pub` (proposed `0x1201`).
    MlDsa65 = 0x0002,
    /// ML-DSA-87 (FIPS 204, NIST Level 5). Multicodec: `mldsa87-pub`
    /// (proposed `0x1202`).
    MlDsa87 = 0x0003,
    /// FN-DSA-padded-512 (future FIPS 206, NIST Level 1) — reduced fee class.
    /// Reserved per ADR-067 ahead of FIPS 206 finalisation; pre-final adoption
    /// is excluded by policy. **No multicodec reservation requested** until
    /// the standard finalises (cross-arch FP-determinism contract not yet
    /// pinned upstream).
    FnDsaPadded512 = 0x0010,
    /// SLH-DSA-SHA2-128s (FIPS 205, NIST Level 1) — premium fee class;
    /// restricted use. Multicodec: `slhdsa-sha2-128s-pub` (proposed `0x1210`).
    SlhDsaSha2128s = 0x0020,
    /// SLH-DSA-SHAKE-192s (FIPS 205, NIST Level 3) — premium fee; consensus
    /// fallback per ADR-043. Multicodec: `slhdsa-shake-192s-pub` (proposed
    /// `0x1213`).
    SlhDsaShake192s = 0x0021,
    /// SLH-DSA-SHAKE-256s (FIPS 205, NIST Level 5) — premium fee; archival
    /// overlay only (ADR-045). Multicodec: `slhdsa-shake-256s-pub` (proposed
    /// `0x1214`).
    SlhDsaShake256s = 0x0022,
    /// SLH-DSA-SHAKE-128s (FIPS 205, NIST Level 1) — premium fee; restricted
    /// use (AA accounts). Multicodec: `slhdsa-shake-128s-pub` (proposed
    /// `0x1212`).
    SlhDsaShake128s = 0x0023,
    /// ML-KEM-768 (FIPS 203, NIST Level 3) — P2P key agreement only; not a
    /// signing algorithm. Multicodec: `mlkem768-pub` (proposed `0x1221`).
    MlKem768 = 0x0100,
}

impl AlgId {
    /// Parse a raw u16 into an AlgId, returning None for unknown values.
    pub fn from_u16(v: u16) -> Option<Self> {
        match v {
            0x0001 => Some(Self::MlDsa44),
            0x0002 => Some(Self::MlDsa65),
            0x0003 => Some(Self::MlDsa87),
            0x0010 => Some(Self::FnDsaPadded512),
            0x0020 => Some(Self::SlhDsaSha2128s),
            0x0021 => Some(Self::SlhDsaShake192s),
            0x0022 => Some(Self::SlhDsaShake256s),
            0x0023 => Some(Self::SlhDsaShake128s),
            0x0100 => Some(Self::MlKem768),
            _ => None,
        }
    }

    pub fn as_u16(self) -> u16 {
        self as u16
    }

    /// Returns true if this algorithm is allowed for validator consensus keys —
    /// ADR-043 + **ADR-046** (tightened 2026-04-22).
    ///
    /// Consensus keys must be post-quantum signature algorithms with NIST
    /// Level ≥ 3. ML-DSA-44 (Level 2) is **forbidden** for consensus per
    /// ADR-046 — it stays registered for non-consensus use but validator
    /// registration will reject it. Post-audit, re-admission is a governance
    /// parameter flip, not a code change.
    ///
    /// Allowed: ML-DSA-65 / ML-DSA-87 (lattice, Level 3 / Level 5),
    /// SLH-DSA-SHAKE-192s (hash-based fallback, Level 3, ADR-043).
    /// Rejected: ML-DSA-44 (Level 2, ADR-046), ML-KEM (KEM, not signing),
    /// SLH-DSA-SHA2-128s / SHAKE-128s / SHAKE-256s (restricted to AA
    /// accounts / archival anchors), FN-DSA (superseded by ADR-043).
    pub fn allowed_for_consensus(self) -> bool {
        matches!(self, Self::MlDsa65 | Self::MlDsa87 | Self::SlhDsaShake192s)
    }

    /// Returns true if this algorithm is allowed for the M4 archival overlay
    /// signing path — **ADR-045** (SPEC-ARCHIVAL-001 §4.7).
    ///
    /// The archival overlay requires a strong hash-based signature (NIST
    /// Level ≥ 3) so that an archived block's authenticity survives even a
    /// break of the lattice family used for consensus signatures. Only
    /// SLH-DSA-SHAKE-192s (Cat 3) and SLH-DSA-SHAKE-256s (Cat 5) are
    /// admitted — ML-DSA is deliberately excluded because the archival
    /// overlay must diversify families. SHAKE variants are preferred over
    /// SHA2 because the node's Merkle/transcript code already depends on
    /// the Keccak permutation, minimising code-surface for a family break.
    pub fn allowed_for_archival(self) -> bool {
        matches!(self, Self::SlhDsaShake192s | Self::SlhDsaShake256s)
    }
}

/// Algorithm lifecycle state — SPEC-ACCOUNT-001 §7.4.
///
/// Transitions are acyclic and strictly forward:
/// `Active` → `Discouraged` → `Deprecated` → `Banned`
///
/// No reactivation is possible once an algorithm moves past `Active`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lifecycle {
    Active,
    Discouraged,
    Deprecated,
    Banned,
}

impl Lifecycle {
    /// Returns true if transactions signed with this algorithm are accepted at mempool admission.
    ///
    /// Active and Discouraged algorithms are admitted. Deprecated and Banned
    /// algorithms are rejected at mempool admission.
    pub fn admits_transactions(self) -> bool {
        matches!(self, Self::Active | Self::Discouraged)
    }
}

/// Signature verification fee class — SPEC-FEE-001 §4.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigClass {
    /// V-A: reduced fee (FN-DSA-padded-512)
    Reduced,
    /// V-B: standard fee (ML-DSA variants) — reference class
    Standard,
    /// V-C: premium fee (SLH-DSA) — ~58× more expensive to verify than ML-DSA-65
    Premium,
}

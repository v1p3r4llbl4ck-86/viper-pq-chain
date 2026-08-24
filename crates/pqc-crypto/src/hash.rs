// SPDX-License-Identifier: Apache-2.0
//! SHAKE-256 hashing primitives for PQ Chain.
//!
//! SHAKE-256 is a variable-output extendable output function (XOF) defined in
//! FIPS 202. The protocol uses 32-byte output for all digest fields:
//! tx hashes (SPEC-TX-001 §10), address derivation (SPEC-ACCOUNT-001 §2.2),
//! and block roots (tx_root, state_root, block_hash).
//!
//! ## BIP340-style tagged hashing (ADR-053 §T2.4)
//!
//! The protocol adopts the Bitcoin BIP340 double-tagged hashing pattern for
//! every domain-separated hash: `H(H(tag) || H(tag) || data)`, implemented
//! here as [`tagged_hash`] and [`TaggedHasher`]. Compared to the simpler
//! `H(tag || data)` recipe, the double-tag construction is immune to the
//! CVE-2012-2459 class of attacks (leaf-vs-internal collision in Merkle
//! trees, domain-tag collision in signatures): an attacker cannot find any
//! `data'` such that `tag || data` and `tag' || data'` share the same
//! digest, because the inner `H(tag)` values each occupy a full hash block
//! and cannot be reached by crafting `data'` alone.
//!
//! Every genesis-relevant tagged-hash site in the workspace migrates from
//! `shake256_32(tag || body)` or `Shake256Hasher::new(tag).push_chunk(..)`
//! to `tagged_hash(tag, body)` or `TaggedHasher::new(tag).push_chunk(..)`.
//! Non-tagged SHAKE-256 (raw message digests with no domain) continues to
//! use [`shake256_32`] unchanged.

use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

/// Compute SHAKE-256 over a single contiguous preimage, producing 32 output bytes.
pub fn shake256_32(data: &[u8]) -> [u8; 32] {
    let mut hasher = Shake256::default();
    hasher.update(data);
    let mut reader = hasher.finalize_xof();
    let mut out = [0u8; 32];
    reader.read(&mut out);
    out
}

/// Compute SHAKE-256 over the concatenation of `chunks`, producing `N` output bytes.
///
/// Chunks are absorbed contiguously without length-prefixing — the caller is
/// responsible for any framing needed for domain separation. Used by callers
/// that need a non-standard output size (e.g. ADR-053 §T1.2 `ForkDigest` with
/// N=4) or that want to avoid a `Vec` allocation for the concatenation.
pub fn shake256_n<const N: usize>(chunks: &[&[u8]]) -> [u8; N] {
    let mut hasher = Shake256::default();
    for c in chunks {
        hasher.update(c);
    }
    let mut reader = hasher.finalize_xof();
    let mut out = [0u8; N];
    reader.read(&mut out);
    out
}

/// Streaming SHAKE-256 accumulator producing a 32-byte digest.
///
/// Encodes each chunk as `u64_be(len) || bytes` so that differently-structured
/// inputs with the same concatenated bytes produce distinct digests. Domain
/// separation is established by the first `push_chunk` call (typically a
/// protocol-level tag string).
pub struct Shake256Hasher(Shake256);

impl Shake256Hasher {
    /// Start a new hasher seeded with a domain-separation tag.
    ///
    /// The tag is absorbed as `u64_be(len(domain)) || domain`.
    pub fn new(domain: &[u8]) -> Self {
        let mut h = Self(Shake256::default());
        h.push_chunk(domain);
        h
    }

    /// Absorb a `u64` value as an 8-byte big-endian chunk.
    pub fn push_u64(&mut self, value: u64) {
        self.push_chunk(&value.to_be_bytes());
    }

    /// Absorb arbitrary bytes, length-prefixed with `u64_be(len)`.
    pub fn push_chunk(&mut self, bytes: &[u8]) {
        // Infallible on any 64-bit platform (usize ≤ u64::MAX); the fallback
        // to u64::MAX is a belt-and-suspenders guard for 128-bit exotic targets.
        let len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        self.0.update(&len.to_be_bytes());
        self.0.update(bytes);
    }

    /// Finalize the digest and return 32 output bytes.
    pub fn finish(self) -> [u8; 32] {
        let mut reader = self.0.finalize_xof();
        let mut out = [0u8; 32];
        reader.read(&mut out);
        out
    }
}

/// BIP340-style double-tagged hash (ADR-053 §T2.4): `H(H(tag) || H(tag) || data)`.
///
/// Computes SHAKE-256 of `H(tag) || H(tag) || data`, returning 32 bytes.
/// The `tag` is absorbed twice as a pre-computed 32-byte digest; the
/// resulting preimage is guaranteed to be ≥ 64 bytes before the data
/// contribution, which puts the data outside the first hash block and
/// prevents the CVE-2012-2459 collision class.
///
/// Hot-path callers that reuse the same tag across many invocations
/// SHOULD pre-compute `H(tag)` once via [`shake256_32`] and pass it to a
/// [`TaggedHasher`] via streaming absorption; this helper recomputes
/// `H(tag)` each call.
pub fn tagged_hash(tag: &[u8], data: &[u8]) -> [u8; 32] {
    let tag_hash = shake256_32(tag);
    let mut hasher = Shake256::default();
    hasher.update(&tag_hash);
    hasher.update(&tag_hash);
    hasher.update(data);
    let mut reader = hasher.finalize_xof();
    let mut out = [0u8; 32];
    reader.read(&mut out);
    out
}

/// Streaming BIP340-style double-tagged hasher producing a 32-byte digest
/// (ADR-053 §T2.4).
///
/// Seeds the internal SHAKE-256 accumulator with `H(tag) || H(tag)` (raw,
/// no length prefix — the two hashes have fixed 32-byte size and serve
/// as a rigid domain block). Subsequent [`push_chunk`](Self::push_chunk)
/// calls absorb user data with the same `u64_be(len) || bytes` framing
/// as [`Shake256Hasher`], so internal field boundaries remain unambiguous.
///
/// Prefer this over [`Shake256Hasher`] for any hash that domain-separates
/// on a literal protocol tag; use [`Shake256Hasher`] only for hashes where
/// the leading chunk is genuinely dynamic data rather than a fixed tag
/// (and even then, consider whether the dynamic prefix is conceptually a
/// tag that could be hashed once via [`tagged_hash`]).
pub struct TaggedHasher(Shake256);

impl TaggedHasher {
    /// Start a new tagged hasher for the given `tag` (ADR-053 §T2.4).
    ///
    /// Computes `H(tag)` once and absorbs it twice into the underlying
    /// SHAKE-256 state before returning.
    pub fn new(tag: &[u8]) -> Self {
        let tag_hash = shake256_32(tag);
        let mut inner = Shake256::default();
        inner.update(&tag_hash);
        inner.update(&tag_hash);
        Self(inner)
    }

    /// Absorb a `u64` value as an 8-byte big-endian chunk. Length-prefixed.
    pub fn push_u64(&mut self, value: u64) {
        self.push_chunk(&value.to_be_bytes());
    }

    /// Absorb arbitrary bytes, length-prefixed with `u64_be(len)`.
    pub fn push_chunk(&mut self, bytes: &[u8]) {
        let len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        self.0.update(&len.to_be_bytes());
        self.0.update(bytes);
    }

    /// Absorb arbitrary bytes raw (no length prefix). Use when the
    /// absorbed value is a known-size field like a hash output where
    /// caller and verifier agree on width.
    pub fn push_raw(&mut self, bytes: &[u8]) {
        self.0.update(bytes);
    }

    /// Finalize and return 32 output bytes.
    pub fn finish(self) -> [u8; 32] {
        let mut reader = self.0.finalize_xof();
        let mut out = [0u8; 32];
        reader.read(&mut out);
        out
    }
}

/// Compute the binary Merkle root over a sorted leaf list, where every
/// internal node is hashed under `branch_domain` via [`tagged_hash`]
/// (ADR-053 §T3.1).
///
/// **Topology**: branching factor 2. Layers fold pair-wise from the bottom
/// up. The bottom layer is `leaves` as-passed; each subsequent layer halves
/// the count by hashing `tagged_hash(branch_domain, left || right)` over
/// adjacent pairs of 32-byte digests. An odd-count layer pairs the trailing
/// node with itself.
///
/// **Empty tree**: `tagged_hash(branch_domain, &[])` — a deterministic
/// sentinel distinct from any non-empty root.
///
/// **Single leaf**: returned unchanged. Callers MUST therefore pre-tag
/// leaves under a domain DIFFERENT from `branch_domain` (e.g.
/// `"VIPER-STATE-LEAF-V1"` vs `"VIPER-STATE-BRANCH-V1"` per ADR-053 §T3.1)
/// — without that separation, an attacker could pass a 64-byte payload that
/// is decoded by one verifier as a 1-leaf tree and by another as a 2-leaf
/// tree of two synthetic 32-byte halves and have them agree on the root,
/// which is the original CVE-2012-2459 attack class. With distinct leaf
/// and branch domains, no leaf hash ever collides with an internal-node
/// hash.
///
/// **Odd-leaf duplication**: pairing a lone trailing leaf with itself is
/// safe in this setting because the leaf list is canonically sorted and
/// deduplicated by construction (callers prefix each leaf with a category
/// id + key + payload), so the Bitcoin-style malleation that motivated
/// CVE-2012-2459 cannot apply: an attacker cannot inject a duplicate leaf
/// at the end and still produce a valid sorted-and-keyed leaf list.
pub fn binary_merkle_root(leaves: &[[u8; 32]], branch_domain: &[u8]) -> [u8; 32] {
    if leaves.is_empty() {
        return tagged_hash(branch_domain, &[]);
    }
    let mut layer: Vec<[u8; 32]> = leaves.to_vec();
    let mut buf = [0u8; 64];
    while layer.len() > 1 {
        let mut next: Vec<[u8; 32]> = Vec::with_capacity(layer.len().div_ceil(2));
        for chunk in layer.chunks(2) {
            buf[..32].copy_from_slice(&chunk[0]);
            if chunk.len() == 2 {
                buf[32..].copy_from_slice(&chunk[1]);
            } else {
                buf[32..].copy_from_slice(&chunk[0]);
            }
            next.push(tagged_hash(branch_domain, &buf));
        }
        layer = next;
    }
    layer[0]
}

#[cfg(test)]
mod tagged_hash_tests;

#[cfg(test)]
mod binary_merkle_tests;

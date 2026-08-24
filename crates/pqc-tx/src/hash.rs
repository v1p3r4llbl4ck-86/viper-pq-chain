// SPDX-License-Identifier: Apache-2.0
//! Transaction hashing — SHAKE-256(raw_bytes, 32) per SPEC-TX-001 §10.

/// Compute `tx_hash = SHAKE-256(canonical_cbor_bytes, 32)`.
///
/// `raw_bytes` must be the deterministic CBOR encoding produced by
/// `pqc_tx::codec::encode_tx`. Callers must not pass partial or
/// re-encoded bytes.
pub fn compute_tx_hash(raw_bytes: &[u8]) -> [u8; 32] {
    pqc_crypto::shake256_32(raw_bytes)
}

// SPDX-License-Identifier: Apache-2.0
//! Signed preimage construction — SPEC-TX-001 §9 + ADR-053 §T1.2 + §T2.4.
//!
//! The signed preimage is:
//!   `tagged_hash("PQC-TX-V1", fork_digest[4] || CBOR({1: tx_version, 2: chain_id,
//!                           3: msg_type, 4: sender, 5: nonce, 6: fee,
//!                           7: fee_tip_or_zero, 8: gas_limit, 9: payload,
//!                           10: sig_alg_id, 11: sig_key_version}))`
//!
//! Field 7 (`fee_tip`) MUST appear as integer 0 when omitted from the envelope.
//! This ensures the preimage is fully determined by semantic intent, not by encoding choices.
//!
//! The 4-byte `fork_digest` prefix (ADR-053 §T1.2) scopes every tx signature
//! to a specific `(fork_version, genesis_validators_root)` pair so a signed
//! transaction on one chain cannot be replayed on any parallel/future chain.
//! The BIP340 double-tagged outer hash (ADR-053 §T2.4) defends against
//! CVE-2012-2459-class domain-tag collisions.
//!
//! The returned `Vec<u8>` is the 32-byte tagged-hash digest the signer
//! operates over; `ml_dsa_sign` / `.verify` treat it as an opaque message.

use ciborium::value::Value;
use pqc_crypto::tagged_hash;
use pqc_types::transaction::Transaction;
use pqc_types::ForkDigest;

/// Domain separator for transaction signed preimages (ADR-053 §T2.4 tag).
pub const DOMAIN_SEPARATOR: &[u8] = b"PQC-TX-V1";

/// Construct the signed preimage bytes for a transaction.
///
/// The returned bytes are the input to the signature verifier.
/// SPEC-TX-001 §9 + ADR-053 §T1.2.
pub fn build_preimage(
    fork_digest: &ForkDigest,
    tx: &Transaction,
) -> Result<Vec<u8>, PreimageError> {
    // Build the CBOR map with integer keys 1..11 in ascending order.
    // Deterministic CBOR requires map keys to be in canonical order (RFC 8949 §4.2.1).
    let map = Value::Map(vec![
        (
            Value::Integer(1u64.into()),
            Value::Integer(u64::from(tx.tx_version).into()),
        ),
        (
            Value::Integer(2u64.into()),
            Value::Bytes(tx.chain_id.clone()),
        ),
        (
            Value::Integer(3u64.into()),
            Value::Integer(u64::from(tx.msg_type as u16).into()),
        ),
        (
            Value::Integer(4u64.into()),
            Value::Bytes(tx.sender.0.to_vec()),
        ),
        (Value::Integer(5u64.into()), Value::Integer(tx.nonce.into())),
        (Value::Integer(6u64.into()), Value::Integer(tx.fee.into())),
        // fee_tip: always present in preimage as 0 when absent from envelope
        (
            Value::Integer(7u64.into()),
            Value::Integer(tx.fee_tip.into()),
        ),
        (
            Value::Integer(8u64.into()),
            Value::Integer(tx.gas_limit.into()),
        ),
        (
            Value::Integer(9u64.into()),
            Value::Bytes(tx.payload.clone()),
        ),
        (
            Value::Integer(10u64.into()),
            Value::Integer(u64::from(tx.sig_alg_id.as_u16()).into()),
        ),
        (
            Value::Integer(11u64.into()),
            Value::Integer(u64::from(tx.sig_key_version).into()),
        ),
    ]);

    let mut cbor_bytes = Vec::new();
    ciborium::into_writer(&map, &mut cbor_bytes)
        .map_err(|e| PreimageError::CborEncodingFailed(e.to_string()))?;

    // Body: fork_digest (cross-chain replay scope) prepended to the
    // canonical CBOR envelope; the domain tag is supplied separately
    // via `tagged_hash`. The 32-byte digest is the signer's message.
    let mut body = Vec::with_capacity(4 + cbor_bytes.len());
    body.extend_from_slice(fork_digest.as_bytes());
    body.extend_from_slice(&cbor_bytes);

    Ok(tagged_hash(DOMAIN_SEPARATOR, &body).to_vec())
}

#[derive(Debug, thiserror::Error)]
pub enum PreimageError {
    #[error("CBOR encoding failed: {0}")]
    CborEncodingFailed(String),
}

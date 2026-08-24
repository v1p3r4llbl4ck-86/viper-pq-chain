// SPDX-License-Identifier: BUSL-1.1
//! `proof_anchor` state transition — SPEC-OPS-001 §6.3.
//!
//! Writes a lightweight on-chain proof anchor record indexed by the
//! transaction hash. No secondary indexes are maintained. Optimized for
//! high-volume machine-to-machine anchoring workflows.

use ciborium::value::Value;
use pqc_tx::{codec::encode_tx, compute_tx_hash};
use pqc_types::{
    proof_anchor::{is_supported_claim_type, AnchorId, ProofAnchor},
    transaction::Transaction,
};

use crate::{error::ApplyError, store::StateStore};

/// Apply a `proof_anchor` operation — SPEC-OPS-001 §6.3.
///
/// Business rules:
/// - `claim_type` MUST be a recognized Phase 1 value (0x0001–0x0003).
/// - `asset_id_hash` and `proof_hash` MUST each be exactly 32 bytes
///   (enforced by CBOR decode).
/// - The `anchor_id` (= tx_hash) is derived deterministically; duplicate
///   submissions are rejected implicitly because the mempool deduplicates
///   by tx_hash before reaching the apply layer.
///
/// On success, a `ProofAnchor` record is written to state, indexed by
/// `anchor_id`, and its leaf hash is added to the incremental state root.
pub fn apply_proof_anchor(store: &mut StateStore, tx: &Transaction) -> Result<(), ApplyError> {
    let payload = decode_proof_anchor_payload(&tx.payload)?;

    if !is_supported_claim_type(payload.claim_type) {
        return Err(ApplyError::InvalidClaimType);
    }

    let raw = encode_tx(tx).map_err(|e| ApplyError::PayloadDecode(e.to_string()))?;
    let anchor_id = AnchorId(compute_tx_hash(&raw));
    let anchor_height = store.block_height().saturating_add(1);

    let record = ProofAnchor {
        anchor_id,
        claimer: tx.sender.clone(),
        claim_type: payload.claim_type,
        asset_id_hash: payload.asset_id_hash,
        proof_hash: payload.proof_hash,
        schema_id: payload.schema_id,
        anchor_height,
    };

    tracing::info!(
        anchor_id = %record.anchor_id.to_hex(),
        claimer = %tx.sender,
        claim_type = record.claim_type,
        anchor_height = record.anchor_height,
        "proof_anchor applied"
    );

    store.insert_proof_anchor(record);
    Ok(())
}

struct ProofAnchorPayload {
    claim_type: u16,
    asset_id_hash: [u8; 32],
    proof_hash: [u8; 32],
    schema_id: Option<[u8; 32]>,
}

fn decode_proof_anchor_payload(payload: &[u8]) -> Result<ProofAnchorPayload, ApplyError> {
    if payload.is_empty() {
        return Err(ApplyError::PayloadDecode("empty payload".into()));
    }

    let value: Value =
        ciborium::from_reader(payload).map_err(|e: ciborium::de::Error<std::io::Error>| {
            ApplyError::PayloadDecode(e.to_string())
        })?;

    let map = match value {
        Value::Map(map) => map,
        _ => {
            return Err(ApplyError::PayloadDecode(
                "payload must be a CBOR map".into(),
            ))
        }
    };

    let mut claim_type = None;
    let mut asset_id_hash = None;
    let mut proof_hash = None;
    let mut schema_id = None;

    for (key, value) in map {
        let key = match key {
            Value::Integer(integer) => i128::from(integer),
            _ => return Err(ApplyError::PayloadDecode("non-integer map key".into())),
        };

        match key {
            1 => {
                claim_type = Some(
                    u16::try_from(i128::from(expect_integer(value)?)).map_err(|_| {
                        ApplyError::PayloadDecode("claim_type out of u16 range".into())
                    })?,
                )
            }
            2 => asset_id_hash = Some(expect_hash32(value)?),
            3 => proof_hash = Some(expect_hash32(value)?),
            4 => schema_id = Some(expect_hash32(value)?),
            _ => {
                return Err(ApplyError::PayloadDecode(format!(
                    "unknown payload key: {key}"
                )))
            }
        }
    }

    Ok(ProofAnchorPayload {
        claim_type: claim_type
            .ok_or_else(|| ApplyError::PayloadDecode("missing field 1 (claim_type)".into()))?,
        asset_id_hash: asset_id_hash
            .ok_or_else(|| ApplyError::PayloadDecode("missing field 2 (asset_id_hash)".into()))?,
        proof_hash: proof_hash
            .ok_or_else(|| ApplyError::PayloadDecode("missing field 3 (proof_hash)".into()))?,
        schema_id,
    })
}

fn expect_integer(value: Value) -> Result<ciborium::value::Integer, ApplyError> {
    match value {
        Value::Integer(integer) => Ok(integer),
        _ => Err(ApplyError::PayloadDecode("expected integer".into())),
    }
}

fn expect_hash32(value: Value) -> Result<[u8; 32], ApplyError> {
    let bytes = match value {
        Value::Bytes(bytes) => bytes,
        _ => return Err(ApplyError::PayloadDecode("expected bytes".into())),
    };

    if bytes.len() != 32 {
        return Err(ApplyError::InvalidHash);
    }

    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

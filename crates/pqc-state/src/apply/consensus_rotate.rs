// SPDX-License-Identifier: BUSL-1.1
//! `consensus_key_rotate` state transition — SPEC-OPS-001 §7.4.
//!
//! # Phase 3 constraint (ADR-020)
//!
//! Phase 3 nodes read their consensus signing key from static node configuration
//! at startup. There is no on-chain validator registry in Phase 3 (that is Phase 4
//! scope per ADR-007). This apply function:
//!
//! - Validates the payload structure (alg_id, pk_bytes, rotation_start_height).
//! - Validates that `rotation_start_height ≥ current_height + ROTATION_WINDOW`.
//! - Rejects SLH-DSA and ML-KEM algorithms for consensus keys.
//! - Writes a `ConsensusKeyRotation` record to state for auditability.
//!
//! Gap: the "sender MUST be the operator of a registered validator" check
//! (SPEC-OPS-001 §7.4) is not enforced in Phase 3 because there is no on-chain
//! validator registry. This is documented in ADR-020 and will be enforced once
//! the Phase 4 validator lifecycle is implemented.
//!
//! Gap: the node's actual consensus signing key is NOT changed by this operation
//! in Phase 3. The record is stored for future Phase 4 activation.

use crate::{error::ApplyError, store::StateStore};
use ciborium::value::Value;
use pqc_crypto::AlgId;
use pqc_types::{consensus_rotation::ConsensusKeyRotation, transaction::Transaction};

/// Minimum number of blocks between the current height and rotation_start_height.
///
/// Ensures a transition window during which the old key remains valid.
/// SPEC-OPS-001 §7.4 leaves the concrete value to the implementation; 100 blocks
/// is the Phase 3 baseline (approximately 10 minutes at 6-second block time).
pub const ROTATION_WINDOW: u64 = 100;

/// Apply a `consensus_key_rotate` operation.
///
/// Preconditions (SPEC-OPS-001 §7.4):
/// - `new_consensus_alg_id` MUST NOT be SLH-DSA or ML-KEM (consensus-key restriction)
/// - `new_consensus_pk_bytes` length MUST match `expected_pk_size(new_consensus_alg_id)`
/// - `rotation_start_height` MUST be ≥ `current_height + ROTATION_WINDOW`
/// - (Phase 3 gap) sender MUST be a registered validator operator — NOT enforced;
///   see ADR-020 for rationale and Phase 4 resolution path
///
/// State transition:
/// - insert or overwrite the `ConsensusKeyRotation` record for `tx.sender`
/// - record is included in the incremental state root under domain
///   `"PQC-CONSENSUS-ROTATE-LEAF-V1"`
pub fn apply_consensus_key_rotate(
    store: &mut StateStore,
    tx: &Transaction,
) -> Result<(), ApplyError> {
    let payload = decode_consensus_key_rotate_payload(&tx.payload)?;

    let alg_id =
        AlgId::from_u16(payload.new_consensus_alg_id).ok_or(ApplyError::UnsupportedAlgorithm)?;

    // Only ML-DSA and SLH-DSA-SHAKE-192s are allowed for consensus keys (ADR-043).
    if !alg_id.allowed_for_consensus() {
        return Err(ApplyError::AlgorithmNotAllowedForConsensus);
    }

    // pk_bytes size must match registry spec.
    let entry = store
        .alg_entry(alg_id)
        .ok_or(ApplyError::UnsupportedAlgorithm)?;
    if payload.new_consensus_pk_bytes.len() != entry.pk_size {
        return Err(ApplyError::InvalidKeySize);
    }

    // rotation_start_height must respect the transition window.
    let min_start = store.block_height().saturating_add(ROTATION_WINDOW);
    if payload.rotation_start_height < min_start {
        return Err(ApplyError::InvalidRotationHeight);
    }

    // Phase 3 gap: no validator-set membership check.
    // See ADR-020 for the Phase 4 resolution plan.

    let rotation = ConsensusKeyRotation {
        operator: tx.sender.clone(),
        new_alg_id: alg_id,
        new_pk_bytes: payload.new_consensus_pk_bytes,
        rotation_start_height: payload.rotation_start_height,
        recorded_at_height: store.block_height(),
    };

    tracing::info!(
        operator = %tx.sender,
        rotation_start_height = payload.rotation_start_height,
        "consensus_key_rotate applied (Phase 3: record only — node still uses config key)"
    );

    store.insert_consensus_key_rotation(rotation);

    Ok(())
}

struct ConsensusKeyRotatePayload {
    new_consensus_alg_id: u16,
    new_consensus_pk_bytes: Vec<u8>,
    rotation_start_height: u64,
}

fn decode_consensus_key_rotate_payload(
    payload: &[u8],
) -> Result<ConsensusKeyRotatePayload, ApplyError> {
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

    let mut new_consensus_alg_id: Option<u16> = None;
    let mut new_consensus_pk_bytes: Option<Vec<u8>> = None;
    let mut rotation_start_height: Option<u64> = None;

    for (k, v) in map {
        let key = match k {
            Value::Integer(i) => i128::from(i),
            _ => return Err(ApplyError::PayloadDecode("non-integer map key".into())),
        };
        match key {
            1 => {
                new_consensus_alg_id =
                    Some(u16::try_from(i128::from(expect_integer(v)?)).map_err(|_| {
                        ApplyError::PayloadDecode("new_consensus_alg_id out of u16 range".into())
                    })?);
            }
            2 => {
                new_consensus_pk_bytes = Some(expect_bytes(v)?);
            }
            3 => {
                rotation_start_height =
                    Some(u64::try_from(i128::from(expect_integer(v)?)).map_err(|_| {
                        ApplyError::PayloadDecode("rotation_start_height out of u64 range".into())
                    })?);
            }
            _ => {
                return Err(ApplyError::PayloadDecode(format!(
                    "unknown payload key: {key}"
                )))
            }
        }
    }

    Ok(ConsensusKeyRotatePayload {
        new_consensus_alg_id: new_consensus_alg_id.ok_or_else(|| {
            ApplyError::PayloadDecode("missing field 1 (new_consensus_alg_id)".into())
        })?,
        new_consensus_pk_bytes: new_consensus_pk_bytes.ok_or_else(|| {
            ApplyError::PayloadDecode("missing field 2 (new_consensus_pk_bytes)".into())
        })?,
        rotation_start_height: rotation_start_height.ok_or_else(|| {
            ApplyError::PayloadDecode("missing field 3 (rotation_start_height)".into())
        })?,
    })
}

fn expect_integer(v: Value) -> Result<ciborium::value::Integer, ApplyError> {
    match v {
        Value::Integer(i) => Ok(i),
        _ => Err(ApplyError::PayloadDecode("expected integer".into())),
    }
}

fn expect_bytes(v: Value) -> Result<Vec<u8>, ApplyError> {
    match v {
        Value::Bytes(b) => Ok(b),
        _ => Err(ApplyError::PayloadDecode("expected bytes".into())),
    }
}

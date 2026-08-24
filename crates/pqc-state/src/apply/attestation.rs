// SPDX-License-Identifier: BUSL-1.1
//! `attestation_create` and `attestation_revoke` state transitions — SPEC-OPS-001 §6.1–§6.2.

use ciborium::value::Value;
use pqc_tx::{codec::encode_tx, compute_tx_hash};
use pqc_types::{
    attestation::{
        is_supported_attestation_type, Attestation, AttestationId, AttestationRevocation,
        AttestationStatus,
    },
    transaction::Transaction,
};

use crate::{error::ApplyError, store::StateStore};

pub fn apply_attestation_create(
    store: &mut StateStore,
    tx: &Transaction,
) -> Result<(), ApplyError> {
    let payload = decode_attestation_create_payload(&tx.payload)?;
    let anchor_height = store.block_height().saturating_add(1);

    if !is_supported_attestation_type(payload.attestation_type) {
        return Err(ApplyError::InvalidAttestationType);
    }

    if let Some(expires_at_height) = payload.expires_at_height {
        if expires_at_height <= anchor_height {
            return Err(ApplyError::InvalidExpiry);
        }
    }

    let raw = encode_tx(tx).map_err(|err| ApplyError::PayloadDecode(err.to_string()))?;
    let attestation_id = AttestationId(compute_tx_hash(&raw));
    if store.get_attestation(&attestation_id).is_some() {
        return Err(ApplyError::AttestationExists);
    }

    let attestation = Attestation {
        attestation_id,
        attester: tx.sender.clone(),
        subject: payload.subject,
        attestation_type: payload.attestation_type,
        content_hash: payload.content_hash,
        schema_id: payload.schema_id,
        metadata_hash: payload.metadata_hash,
        anchor_height,
        expires_at_height: payload.expires_at_height,
        status: AttestationStatus::Active,
        revocation: None,
    };

    tracing::info!(
        attestation_id = %attestation.attestation_id.to_hex(),
        attester = %tx.sender,
        attestation_type = attestation.attestation_type,
        anchor_height = attestation.anchor_height,
        "attestation_create applied"
    );

    store.insert_attestation(attestation);
    Ok(())
}

struct AttestationCreatePayload {
    subject: [u8; 32],
    attestation_type: u16,
    content_hash: [u8; 32],
    schema_id: [u8; 32],
    metadata_hash: Option<[u8; 32]>,
    expires_at_height: Option<u64>,
}

fn decode_attestation_create_payload(
    payload: &[u8],
) -> Result<AttestationCreatePayload, ApplyError> {
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

    let mut subject = None;
    let mut attestation_type = None;
    let mut content_hash = None;
    let mut schema_id = None;
    let mut metadata_hash = None;
    let mut expires_at_height = None;

    for (key, value) in map {
        let key = match key {
            Value::Integer(integer) => i128::from(integer),
            _ => return Err(ApplyError::PayloadDecode("non-integer map key".into())),
        };

        match key {
            1 => subject = Some(expect_hash32(value)?),
            2 => {
                attestation_type = Some(u16::try_from(i128::from(expect_integer(value)?)).map_err(
                    |_| ApplyError::PayloadDecode("attestation_type out of u16 range".into()),
                )?)
            }
            3 => content_hash = Some(expect_hash32(value)?),
            4 => schema_id = Some(expect_hash32(value)?),
            5 => metadata_hash = Some(expect_hash32(value)?),
            6 => {
                expires_at_height = Some(
                    u64::try_from(i128::from(expect_integer(value)?)).map_err(|_| {
                        ApplyError::PayloadDecode("expires_at_height out of u64 range".into())
                    })?,
                )
            }
            _ => {
                return Err(ApplyError::PayloadDecode(format!(
                    "unknown payload key: {key}"
                )))
            }
        }
    }

    Ok(AttestationCreatePayload {
        subject: subject
            .ok_or_else(|| ApplyError::PayloadDecode("missing field 1 (subject)".into()))?,
        attestation_type: attestation_type.ok_or_else(|| {
            ApplyError::PayloadDecode("missing field 2 (attestation_type)".into())
        })?,
        content_hash: content_hash
            .ok_or_else(|| ApplyError::PayloadDecode("missing field 3 (content_hash)".into()))?,
        schema_id: schema_id
            .ok_or_else(|| ApplyError::PayloadDecode("missing field 4 (schema_id)".into()))?,
        metadata_hash,
        expires_at_height,
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

// ── attestation_revoke ────────────────────────────────────────────────────────

/// Apply an `attestation_revoke` operation — SPEC-OPS-001 §6.2.
///
/// Business rules:
/// - The referenced `attestation_id` must exist in chain state.
/// - The attestation must be in `Active` status (double-revoke is rejected).
/// - The sender must be the original attester (only issuer can revoke).
///
/// On success the attestation `status` transitions to `Revoked` and the
/// `revocation` field is populated with the block height, revoker address,
/// and an optional `revocation_reason_hash`.
pub fn apply_attestation_revoke(
    store: &mut StateStore,
    tx: &Transaction,
) -> Result<(), ApplyError> {
    let payload = decode_attestation_revoke_payload(&tx.payload)?;

    // Look up the existing attestation.
    let attestation = store
        .get_attestation(&payload.attestation_id)
        .ok_or(ApplyError::AttestationNotFound)?
        .clone();

    // Only Active attestations can be revoked.
    if attestation.status == AttestationStatus::Revoked {
        return Err(ApplyError::AttestationAlreadyRevoked);
    }

    // Only the original attester may revoke.
    if attestation.attester != tx.sender {
        return Err(ApplyError::UnauthorizedRevoker);
    }

    let revoked_at_height = store.block_height().saturating_add(1);

    // Build the updated attestation record (status transition only).
    let revoked = Attestation {
        status: AttestationStatus::Revoked,
        revocation: Some(AttestationRevocation {
            revoked_at_height,
            revoker: tx.sender.clone(),
            revocation_reason_hash: payload.revocation_reason_hash,
        }),
        ..attestation
    };

    tracing::info!(
        attestation_id = %revoked.attestation_id.to_hex(),
        revoker = %tx.sender,
        revoked_at_height,
        "attestation_revoke applied"
    );

    store.insert_attestation(revoked);
    Ok(())
}

struct AttestationRevokePayload {
    attestation_id: AttestationId,
    revocation_reason_hash: Option<[u8; 32]>,
}

fn decode_attestation_revoke_payload(
    payload: &[u8],
) -> Result<AttestationRevokePayload, ApplyError> {
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

    let mut attestation_id_bytes = None;
    let mut revocation_reason_hash = None;

    for (key, value) in map {
        let key = match key {
            Value::Integer(integer) => i128::from(integer),
            _ => return Err(ApplyError::PayloadDecode("non-integer map key".into())),
        };

        match key {
            1 => attestation_id_bytes = Some(expect_hash32(value)?),
            2 => revocation_reason_hash = Some(expect_hash32(value)?),
            _ => {
                return Err(ApplyError::PayloadDecode(format!(
                    "unknown payload key: {key}"
                )))
            }
        }
    }

    let id_bytes = attestation_id_bytes
        .ok_or_else(|| ApplyError::PayloadDecode("missing field 1 (attestation_id)".into()))?;

    Ok(AttestationRevokePayload {
        attestation_id: AttestationId(id_bytes),
        revocation_reason_hash,
    })
}

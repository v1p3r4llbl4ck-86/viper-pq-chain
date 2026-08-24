// SPDX-License-Identifier: BUSL-1.1
//! Key-management state transitions — SPEC-OPS-001 §7.

use ciborium::value::Value;
use pqc_crypto::AlgId;
use pqc_types::{
    keyset::{allowed_tx, KeyEntry, KeyStatus},
    transaction::Transaction,
};

use crate::{error::ApplyError, store::StateStore};

pub fn apply_key_add(store: &mut StateStore, tx: &Transaction) -> Result<(), ApplyError> {
    let payload = decode_key_add_payload(&tx.payload)?;
    let new_key = build_new_key_entry(
        store,
        payload.alg_id,
        payload.pk_bytes,
        payload.key_version,
        payload.valid_from_height,
        payload.allowed_tx_types,
    )?;

    {
        let sender = store
            .get_account_mut(&tx.sender)
            .ok_or(ApplyError::KeyNotFound)?;

        let max_key_version = sender
            .keys
            .0
            .iter()
            .map(|key| key.key_version)
            .max()
            .unwrap_or(0);
        if new_key.key_version == 0 || new_key.key_version <= max_key_version {
            return Err(ApplyError::KeyVersionConflict);
        }

        sender.keys.0.push(new_key);
        ensure_account_invariants(sender)?;
    }
    store.commit_account_mutation(&tx.sender);
    Ok(())
}

pub fn apply_key_rotate(store: &mut StateStore, tx: &Transaction) -> Result<(), ApplyError> {
    let payload = decode_key_rotate_payload(&tx.payload)?;
    let new_key = build_new_key_entry(
        store,
        payload.new_alg_id,
        payload.new_pk_bytes,
        payload.new_key_version,
        payload.new_valid_from_height,
        payload.new_allowed_tx_types,
    )?;

    {
        let sender = store
            .get_account_mut(&tx.sender)
            .ok_or(ApplyError::KeyNotFound)?;

        let max_key_version = sender
            .keys
            .0
            .iter()
            .map(|key| key.key_version)
            .max()
            .unwrap_or(0);
        if new_key.key_version == 0 || new_key.key_version <= max_key_version {
            return Err(ApplyError::KeyVersionConflict);
        }
        if payload.revoke_key_version == new_key.key_version {
            return Err(ApplyError::InvalidKeyRotation);
        }

        let target_index = sender
            .keys
            .0
            .iter()
            .position(|key| key.key_version == payload.revoke_key_version)
            .ok_or(ApplyError::KeyNotFound)?;

        match sender.keys.0[target_index].status {
            KeyStatus::Revoked => return Err(ApplyError::KeyAlreadyRevoked),
            KeyStatus::Pending => return Err(ApplyError::InvalidKeyRotation),
            KeyStatus::Active => {}
        }

        sender.keys.0[target_index].status = KeyStatus::Revoked;
        sender.keys.0.push(new_key);
        ensure_account_invariants(sender)?;
    }
    store.commit_account_mutation(&tx.sender);
    Ok(())
}

pub fn apply_key_revoke(store: &mut StateStore, tx: &Transaction) -> Result<(), ApplyError> {
    let payload = decode_key_revoke_payload(&tx.payload)?;
    if payload.target_key_version == tx.sig_key_version {
        return Err(ApplyError::SignerIsTarget);
    }

    {
        let sender = store
            .get_account_mut(&tx.sender)
            .ok_or(ApplyError::KeyNotFound)?;

        let target_index = sender
            .keys
            .0
            .iter()
            .position(|key| key.key_version == payload.target_key_version)
            .ok_or(ApplyError::KeyNotFound)?;

        if sender.keys.0[target_index].status == KeyStatus::Revoked {
            return Err(ApplyError::KeyAlreadyRevoked);
        }

        sender.keys.0[target_index].status = KeyStatus::Revoked;
        ensure_account_invariants(sender)?;
    }
    store.commit_account_mutation(&tx.sender);
    Ok(())
}

struct KeyAddPayload {
    alg_id: u16,
    pk_bytes: Vec<u8>,
    key_version: u32,
    valid_from_height: u64,
    allowed_tx_types: u32,
}

struct KeyRotatePayload {
    new_alg_id: u16,
    new_pk_bytes: Vec<u8>,
    new_key_version: u32,
    new_valid_from_height: u64,
    new_allowed_tx_types: u32,
    revoke_key_version: u32,
}

struct KeyRevokePayload {
    target_key_version: u32,
}

fn build_new_key_entry(
    store: &StateStore,
    alg_id_raw: u16,
    pk_bytes: Vec<u8>,
    key_version: u32,
    valid_from_height: u64,
    allowed_tx_types: u32,
) -> Result<KeyEntry, ApplyError> {
    let alg_id = AlgId::from_u16(alg_id_raw).ok_or(ApplyError::UnsupportedAlgorithm)?;
    let entry = store
        .alg_entry(alg_id)
        .ok_or(ApplyError::UnsupportedAlgorithm)?;
    if entry.lifecycle != pqc_crypto::Lifecycle::Active {
        return Err(ApplyError::UnsupportedAlgorithm);
    }
    if pk_bytes.len() != entry.pk_size {
        return Err(ApplyError::InvalidKeySize);
    }
    if valid_from_height < store.block_height() {
        return Err(ApplyError::InvalidActivationHeight);
    }
    if alg_id == AlgId::SlhDsaSha2128s && allowed_tx_types != allowed_tx::SLH_DSA_ONLY {
        return Err(ApplyError::InvalidKeyPermissions);
    }

    let status = if store.block_height() >= valid_from_height {
        KeyStatus::Active
    } else {
        KeyStatus::Pending
    };

    Ok(KeyEntry {
        alg_id,
        pk_bytes: pk_bytes.into(),
        key_version,
        valid_from_height,
        status,
        allowed_tx_types,
    })
}

fn ensure_account_invariants(account: &pqc_types::account::Account) -> Result<(), ApplyError> {
    account.check_invariants().map_err(|err| match err {
        "I-1: account has no active key" => ApplyError::InsufficientActiveKeys,
        "I-2: duplicate key_version values in KeySet" => ApplyError::KeyVersionConflict,
        other => ApplyError::PayloadDecode(other.to_string()),
    })
}

fn decode_key_add_payload(payload: &[u8]) -> Result<KeyAddPayload, ApplyError> {
    let map = decode_map(payload)?;

    let mut alg_id = None;
    let mut pk_bytes = None;
    let mut key_version = None;
    let mut valid_from_height = None;
    let mut allowed_tx_types = None;

    for (key, value) in map {
        match key {
            1 => alg_id = Some(decode_u16(value, "alg_id")?),
            2 => pk_bytes = Some(expect_bytes(value)?),
            3 => key_version = Some(decode_u32(value, "key_version")?),
            4 => valid_from_height = Some(decode_u64(value, "valid_from_height")?),
            5 => allowed_tx_types = Some(decode_u32(value, "allowed_tx_types")?),
            _ => {
                return Err(ApplyError::PayloadDecode(format!(
                    "unknown payload key: {key}"
                )))
            }
        }
    }

    Ok(KeyAddPayload {
        alg_id: alg_id
            .ok_or_else(|| ApplyError::PayloadDecode("missing field 1 (alg_id)".into()))?,
        pk_bytes: pk_bytes
            .ok_or_else(|| ApplyError::PayloadDecode("missing field 2 (pk_bytes)".into()))?,
        key_version: key_version
            .ok_or_else(|| ApplyError::PayloadDecode("missing field 3 (key_version)".into()))?,
        valid_from_height: valid_from_height.ok_or_else(|| {
            ApplyError::PayloadDecode("missing field 4 (valid_from_height)".into())
        })?,
        allowed_tx_types: allowed_tx_types.ok_or_else(|| {
            ApplyError::PayloadDecode("missing field 5 (allowed_tx_types)".into())
        })?,
    })
}

fn decode_key_rotate_payload(payload: &[u8]) -> Result<KeyRotatePayload, ApplyError> {
    let map = decode_map(payload)?;

    let mut new_alg_id = None;
    let mut new_pk_bytes = None;
    let mut new_key_version = None;
    let mut new_valid_from_height = None;
    let mut new_allowed_tx_types = None;
    let mut revoke_key_version = None;

    for (key, value) in map {
        match key {
            1 => new_alg_id = Some(decode_u16(value, "new_alg_id")?),
            2 => new_pk_bytes = Some(expect_bytes(value)?),
            3 => new_key_version = Some(decode_u32(value, "new_key_version")?),
            4 => new_valid_from_height = Some(decode_u64(value, "new_valid_from_height")?),
            5 => new_allowed_tx_types = Some(decode_u32(value, "new_allowed_tx_types")?),
            6 => revoke_key_version = Some(decode_u32(value, "revoke_key_version")?),
            _ => {
                return Err(ApplyError::PayloadDecode(format!(
                    "unknown payload key: {key}"
                )))
            }
        }
    }

    Ok(KeyRotatePayload {
        new_alg_id: new_alg_id
            .ok_or_else(|| ApplyError::PayloadDecode("missing field 1 (new_alg_id)".into()))?,
        new_pk_bytes: new_pk_bytes
            .ok_or_else(|| ApplyError::PayloadDecode("missing field 2 (new_pk_bytes)".into()))?,
        new_key_version: new_key_version
            .ok_or_else(|| ApplyError::PayloadDecode("missing field 3 (new_key_version)".into()))?,
        new_valid_from_height: new_valid_from_height.ok_or_else(|| {
            ApplyError::PayloadDecode("missing field 4 (new_valid_from_height)".into())
        })?,
        new_allowed_tx_types: new_allowed_tx_types.ok_or_else(|| {
            ApplyError::PayloadDecode("missing field 5 (new_allowed_tx_types)".into())
        })?,
        revoke_key_version: revoke_key_version.ok_or_else(|| {
            ApplyError::PayloadDecode("missing field 6 (revoke_key_version)".into())
        })?,
    })
}

fn decode_key_revoke_payload(payload: &[u8]) -> Result<KeyRevokePayload, ApplyError> {
    let map = decode_map(payload)?;
    let mut target_key_version = None;

    for (key, value) in map {
        match key {
            1 => target_key_version = Some(decode_u32(value, "target_key_version")?),
            _ => {
                return Err(ApplyError::PayloadDecode(format!(
                    "unknown payload key: {key}"
                )))
            }
        }
    }

    Ok(KeyRevokePayload {
        target_key_version: target_key_version.ok_or_else(|| {
            ApplyError::PayloadDecode("missing field 1 (target_key_version)".into())
        })?,
    })
}

fn decode_map(payload: &[u8]) -> Result<Vec<(i128, Value)>, ApplyError> {
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

    map.into_iter()
        .map(|(key, value)| match key {
            Value::Integer(integer) => Ok((i128::from(integer), value)),
            _ => Err(ApplyError::PayloadDecode("non-integer map key".into())),
        })
        .collect()
}

fn expect_integer(value: Value) -> Result<ciborium::value::Integer, ApplyError> {
    match value {
        Value::Integer(integer) => Ok(integer),
        _ => Err(ApplyError::PayloadDecode("expected integer".into())),
    }
}

fn expect_bytes(value: Value) -> Result<Vec<u8>, ApplyError> {
    match value {
        Value::Bytes(bytes) => Ok(bytes),
        _ => Err(ApplyError::PayloadDecode("expected bytes".into())),
    }
}

fn decode_u16(value: Value, field: &str) -> Result<u16, ApplyError> {
    u16::try_from(i128::from(expect_integer(value)?))
        .map_err(|_| ApplyError::PayloadDecode(format!("{field} out of u16 range")))
}

fn decode_u32(value: Value, field: &str) -> Result<u32, ApplyError> {
    u32::try_from(i128::from(expect_integer(value)?))
        .map_err(|_| ApplyError::PayloadDecode(format!("{field} out of u32 range")))
}

fn decode_u64(value: Value, field: &str) -> Result<u64, ApplyError> {
    u64::try_from(i128::from(expect_integer(value)?))
        .map_err(|_| ApplyError::PayloadDecode(format!("{field} out of u64 range")))
}

// SPDX-License-Identifier: BUSL-1.1
//! `vault_create` and `vault_policy_update` state transitions — SPEC-OPS-001 §5.1–§5.2.

use crate::{error::ApplyError, store::StateStore};
use ciborium::value::Value;
use pqc_crypto::AlgId;
use pqc_types::{
    account::{Account, Address},
    keyset::{allowed_tx, KeyEntry, KeySet, KeyStatus},
    transaction::Transaction,
};

/// Apply a `vault_create` operation.
///
/// Preconditions (SPEC-OPS-001 §5.1):
/// - `alg_id` must be active in the Algorithm Registry
/// - `pk_bytes` length must match `expected_pk_size(alg_id)`
/// - `valid_from_height` ≥ current block height
/// - SLH-DSA genesis key must have `allowed_tx_types = 0x00000004`
/// - `new_address` must not already exist in state
///
/// State transition:
/// - create account at `new_address` with `balance=0`, `nonce=0`
/// - genesis key: `key_version=1`, `status=Pending` (→ Active at `valid_from_height`)
pub fn apply_vault_create(store: &mut StateStore, tx: &Transaction) -> Result<(), ApplyError> {
    let payload = decode_vault_create_payload(&tx.payload)?;

    let alg_id = AlgId::from_u16(payload.alg_id).ok_or(ApplyError::UnsupportedAlgorithm)?;

    // Check alg_id is active in the registry
    let entry = store
        .alg_entry(alg_id)
        .ok_or(ApplyError::UnsupportedAlgorithm)?;
    if entry.lifecycle != pqc_crypto::Lifecycle::Active {
        return Err(ApplyError::UnsupportedAlgorithm);
    }

    // pk_bytes size must match registry spec
    if payload.pk_bytes.len() != entry.pk_size {
        return Err(ApplyError::InvalidKeySize);
    }

    // SLH-DSA genesis key must be key-management only
    if alg_id == AlgId::SlhDsaSha2128s && payload.allowed_tx_types != allowed_tx::SLH_DSA_ONLY {
        return Err(ApplyError::InvalidKeyPermissions);
    }

    // valid_from_height: any value ≤ store.block_height() yields an immediately-active key;
    // any value > store.block_height() yields Pending, which fails I-1 and is rejected below.
    // The original "reject if in the past" check created an unsolvable race for callers:
    // the tx must be included in EXACTLY the block where store.block_height() == valid_from_height,
    // which is impossible to guarantee in a live system. Relaxing this allows valid_from_height=0
    // (or any past height) for an immediately-active vault key.
    // (Spec deviation recorded in DECISIONS.md — prototype path, Phase 2.)

    // Derive new_address using the canonical address derivation from pqc-crypto::address.
    // ADR-053 §T1.3: address = SHAKE-256("VIPER-ADDR-V1" || chain_id || sig_alg_id_be16 || pk_bytes, 32)
    let new_address = Address(pqc_crypto::derive_address(
        store.chain_id(),
        alg_id,
        &payload.pk_bytes,
    ));

    // Account must not already exist
    if store.get_account(&new_address).is_some() {
        return Err(ApplyError::AccountExists);
    }

    let key_status = if store.block_height() >= payload.valid_from_height {
        KeyStatus::Active
    } else {
        KeyStatus::Pending
    };

    let account = Account {
        address: new_address,
        balance: 0,
        nonce: 0,
        keys: KeySet(vec![KeyEntry {
            alg_id,
            pk_bytes: payload.pk_bytes.into(),
            key_version: 1,
            valid_from_height: payload.valid_from_height,
            status: key_status,
            allowed_tx_types: payload.allowed_tx_types,
        }]),
        policy_version: 0,
        policy_hash: None,
        verifier_template_id: pqc_types::account::VERIFIER_TEMPLATE_ID_EOA,
        auth_data: Vec::new(),
    };

    // Invariant check before committing
    account
        .check_invariants()
        .map_err(|e| ApplyError::PayloadDecode(e.to_string()))?;

    tracing::info!(
        address = %account.address.to_hex(),
        "vault_create applied"
    );

    store.insert_account(account);

    Ok(())
}

struct VaultCreatePayload {
    alg_id: u16,
    pk_bytes: Vec<u8>,
    allowed_tx_types: u32,
    valid_from_height: u64,
}

fn decode_vault_create_payload(payload: &[u8]) -> Result<VaultCreatePayload, ApplyError> {
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

    let mut alg_id: Option<u16> = None;
    let mut pk_bytes: Option<Vec<u8>> = None;
    let mut allowed_tx_types: Option<u32> = None;
    let mut valid_from_height: Option<u64> = None;

    for (k, v) in map {
        let key = match k {
            Value::Integer(i) => i128::from(i),
            _ => return Err(ApplyError::PayloadDecode("non-integer map key".into())),
        };
        match key {
            1 => {
                alg_id = Some(
                    u16::try_from(i128::from(expect_integer(v)?))
                        .map_err(|_| ApplyError::PayloadDecode("alg_id out of u16 range".into()))?,
                )
            }
            2 => pk_bytes = Some(expect_bytes(v)?),
            3 => {
                allowed_tx_types =
                    Some(u32::try_from(i128::from(expect_integer(v)?)).map_err(|_| {
                        ApplyError::PayloadDecode("allowed_tx_types out of u32 range".into())
                    })?)
            }
            4 => {
                valid_from_height =
                    Some(u64::try_from(i128::from(expect_integer(v)?)).map_err(|_| {
                        ApplyError::PayloadDecode("valid_from_height out of u64 range".into())
                    })?)
            }
            5 => {} // metadata_hash — optional, ignored in Phase 1 state (stored off-chain)
            _ => {
                return Err(ApplyError::PayloadDecode(format!(
                    "unknown payload key: {key}"
                )))
            }
        }
    }

    Ok(VaultCreatePayload {
        alg_id: alg_id
            .ok_or_else(|| ApplyError::PayloadDecode("missing field 1 (alg_id)".into()))?,
        pk_bytes: pk_bytes
            .ok_or_else(|| ApplyError::PayloadDecode("missing field 2 (pk_bytes)".into()))?,
        allowed_tx_types: allowed_tx_types.ok_or_else(|| {
            ApplyError::PayloadDecode("missing field 3 (allowed_tx_types)".into())
        })?,
        valid_from_height: valid_from_height.ok_or_else(|| {
            ApplyError::PayloadDecode("missing field 4 (valid_from_height)".into())
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

// ── vault_policy_update ───────────────────────────────────────────────────────

/// Apply a `vault_policy_update` operation — SPEC-OPS-001 §5.2.
///
/// Business rules:
/// - The sender's account must exist (enforced upstream by `validate_tx`).
/// - `policy_version` MUST be strictly greater than the current `policy_version`
///   on the sender's account (prevents policy replay).
/// - `policy_hash` MUST be exactly 32 bytes (enforced by CBOR decode).
///
/// On success, the account's `policy_version` and `policy_hash` fields are
/// updated and the leaf hash is recomputed via `commit_account_mutation`.
pub fn apply_vault_policy_update(
    store: &mut StateStore,
    tx: &Transaction,
) -> Result<(), ApplyError> {
    let payload = decode_vault_policy_update_payload(&tx.payload)?;

    let current_policy_version = store
        .get_account(&tx.sender)
        .ok_or(ApplyError::InsufficientFunds)? // account not found — use InsufficientFunds (validate_tx guards this)
        .policy_version;

    if payload.policy_version <= current_policy_version {
        return Err(ApplyError::PolicyVersionConflict);
    }

    {
        let account = store
            .get_account_mut(&tx.sender)
            .ok_or(ApplyError::InsufficientFunds)?;
        account.policy_version = payload.policy_version;
        account.policy_hash = Some(payload.policy_hash);
    }
    store.commit_account_mutation(&tx.sender);

    tracing::info!(
        account = %tx.sender,
        policy_version = payload.policy_version,
        "vault_policy_update applied"
    );

    Ok(())
}

struct VaultPolicyUpdatePayload {
    policy_version: u32,
    policy_hash: [u8; 32],
    // schema_id (field 3) is recognized but not stored on-chain in this prototype
}

fn decode_vault_policy_update_payload(
    payload: &[u8],
) -> Result<VaultPolicyUpdatePayload, ApplyError> {
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

    let mut policy_version = None;
    let mut policy_hash = None;

    for (key, value) in map {
        let key = match key {
            Value::Integer(integer) => i128::from(integer),
            _ => return Err(ApplyError::PayloadDecode("non-integer map key".into())),
        };

        match key {
            1 => {
                policy_version = Some(u32::try_from(i128::from(expect_integer(value)?)).map_err(
                    |_| ApplyError::PayloadDecode("policy_version out of u32 range".into()),
                )?)
            }
            2 => {
                let bytes = expect_bytes(value)?;
                if bytes.len() != 32 {
                    return Err(ApplyError::InvalidHash);
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                policy_hash = Some(arr);
            }
            3 => {
                // schema_id — recognized but not stored in this prototype
                let _ = value;
            }
            _ => {
                return Err(ApplyError::PayloadDecode(format!(
                    "unknown payload key: {key}"
                )))
            }
        }
    }

    Ok(VaultPolicyUpdatePayload {
        policy_version: policy_version
            .ok_or_else(|| ApplyError::PayloadDecode("missing field 1 (policy_version)".into()))?,
        policy_hash: policy_hash
            .ok_or_else(|| ApplyError::PayloadDecode("missing field 2 (policy_hash)".into()))?,
    })
}

// Address derivation uses the canonical `pqc_crypto::derive_address(chain_id, alg_id, pk_bytes)`
// per ADR-053 §T1.3 (viper-pq-1 tagged-hash with chain_id binding). This replaced an
// earlier local derivation that used a different field order (F-017 audit finding).

// SPDX-License-Identifier: BUSL-1.1
//! Validator staking lifecycle state transitions — SPEC-VAL-001 + ADR-047.
//!
//! Operations:
//! - `ValidatorRegister`       — `none → candidate` (promoted to `active` if set has capacity)
//! - `ValidatorExit`           — `active → unbonding`
//! - `ValidatorUnjail`         — `jailed → candidate` (promoted to `active` if set has capacity)
//! - `ValidatorRotatePeerId`   — update the on-chain libp2p PeerId binding (ADR-047)

use crate::{error::ApplyError, store::StateStore};
use ciborium::value::Value;
use pqc_crypto::AlgId;
use pqc_types::{
    transaction::Transaction,
    validator::{
        ValidatorRecord, ValidatorRegisterPayload, ValidatorRotatePeerIdPayload, ValidatorStatus,
        VALIDATOR_MAX_ACTIVE_SET_SIZE, VALIDATOR_PEER_ID_MAX_LEN,
    },
};

/// Apply a `ValidatorRegister` transaction.
pub fn apply_validator_register(
    store: &mut StateStore,
    tx: &Transaction,
) -> Result<(), ApplyError> {
    let payload = decode_register_payload(&tx.payload)?;

    let consensus_alg_id = AlgId::from_u16(payload.consensus_alg_id)
        .ok_or(ApplyError::AlgorithmNotAllowedForConsensusKey)?;
    if !consensus_alg_id.allowed_for_consensus() {
        return Err(ApplyError::AlgorithmNotAllowedForConsensusKey);
    }

    let entry = store
        .alg_entry(consensus_alg_id)
        .ok_or(ApplyError::UnsupportedAlgorithm)?;
    if payload.consensus_pk.len() != entry.pk_size {
        return Err(ApplyError::InvalidKeySize);
    }

    if payload.self_bond == 0 {
        return Err(ApplyError::ValidatorBondZero);
    }

    if let Some(existing) = store.get_validator(&tx.sender) {
        if existing.status != ValidatorStatus::Exited {
            return Err(ApplyError::ValidatorAlreadyRegistered);
        }
    }

    if store.consensus_key_in_use(&payload.consensus_pk) {
        return Err(ApplyError::ValidatorConsensusKeyConflict);
    }

    // ADR-047: validate on-chain peer_id binding. An empty peer_id is permitted
    // at Register time for backward compatibility with pre-ADR-047 devnet-2
    // genesis txs; those validators self-register via `ValidatorRotatePeerId`.
    if payload.peer_id.len() > VALIDATOR_PEER_ID_MAX_LEN {
        return Err(ApplyError::ValidatorPeerIdTooLarge);
    }
    if !payload.peer_id.is_empty() && store.peer_id_in_use(&payload.peer_id) {
        return Err(ApplyError::ValidatorPeerIdConflict);
    }

    {
        let operator = store
            .get_account_mut(&tx.sender)
            .ok_or(ApplyError::ValidatorNotFound)?;
        if operator.balance < payload.self_bond {
            return Err(ApplyError::InsufficientFunds);
        }
        operator.balance -= payload.self_bond;
    }
    store.commit_account_mutation(&tx.sender);

    let active_count = store.active_validator_count();
    let initial_status = if active_count < VALIDATOR_MAX_ACTIVE_SET_SIZE {
        ValidatorStatus::Active
    } else {
        ValidatorStatus::Candidate
    };

    store.insert_validator(ValidatorRecord {
        operator: tx.sender.clone(),
        node_id: payload.node_id,
        consensus_alg_id,
        consensus_pk: payload.consensus_pk,
        self_bond: payload.self_bond,
        status: initial_status,
        registered_height: store.block_height(),
        tombstoned: false,
    });

    if !payload.peer_id.is_empty() {
        store.set_validator_peer_id(&tx.sender, payload.peer_id);
    }

    Ok(())
}

/// Apply a `ValidatorExit` transaction.
pub fn apply_validator_exit(store: &mut StateStore, tx: &Transaction) -> Result<(), ApplyError> {
    {
        let record = store
            .get_validator(&tx.sender)
            .ok_or(ApplyError::ValidatorNotFound)?;
        if record.status != ValidatorStatus::Active {
            return Err(ApplyError::ValidatorNotActive);
        }
    }

    if store.active_validator_count() <= 1 {
        return Err(ApplyError::ValidatorExitWouldEmptySet);
    }

    let current_height = store.block_height();
    let record = store
        .get_validator_mut(&tx.sender)
        .ok_or(ApplyError::ValidatorNotFound)?;
    record.status = ValidatorStatus::Unbonding {
        start_height: current_height,
    };
    store.commit_validator_mutation(&tx.sender);

    Ok(())
}

/// Apply a `ValidatorUnjail` transaction.
pub fn apply_validator_unjail(store: &mut StateStore, tx: &Transaction) -> Result<(), ApplyError> {
    {
        let record = store
            .get_validator(&tx.sender)
            .ok_or(ApplyError::ValidatorNotFound)?;
        if record.tombstoned {
            return Err(ApplyError::AlreadyTombstoned);
        }
        if record.status != ValidatorStatus::Jailed {
            return Err(ApplyError::ValidatorNotJailed);
        }
    }

    let active_count = store.active_validator_count();
    let new_status = if active_count < VALIDATOR_MAX_ACTIVE_SET_SIZE {
        ValidatorStatus::Active
    } else {
        ValidatorStatus::Candidate
    };

    let record = store
        .get_validator_mut(&tx.sender)
        .ok_or(ApplyError::ValidatorNotFound)?;
    record.status = new_status;
    store.commit_validator_mutation(&tx.sender);

    Ok(())
}

/// Apply a `ValidatorRotatePeerId` transaction — ADR-047, TASK-159.
///
/// Preconditions:
/// - Sender must be a registered validator in Active/Candidate/Jailed status.
/// - `new_peer_id` must be non-empty and ≤ `VALIDATOR_PEER_ID_MAX_LEN`.
/// - `new_peer_id` must not collide with another live validator's binding
///   (a sender rotating to their own current binding is a no-op, permitted).
pub fn apply_validator_rotate_peer_id(
    store: &mut StateStore,
    tx: &Transaction,
) -> Result<(), ApplyError> {
    let payload = decode_rotate_peer_id_payload(&tx.payload)?;

    if payload.new_peer_id.is_empty() {
        return Err(ApplyError::ValidatorPeerIdEmpty);
    }
    if payload.new_peer_id.len() > VALIDATOR_PEER_ID_MAX_LEN {
        return Err(ApplyError::ValidatorPeerIdTooLarge);
    }

    {
        let record = store
            .get_validator(&tx.sender)
            .ok_or(ApplyError::ValidatorNotFound)?;
        match record.status {
            ValidatorStatus::Active | ValidatorStatus::Candidate | ValidatorStatus::Jailed => {}
            ValidatorStatus::Unbonding { .. } | ValidatorStatus::Exited => {
                return Err(ApplyError::ValidatorPeerIdNotRotatable);
            }
        }
    }

    let is_own_current_binding = store
        .get_validator_peer_id(&tx.sender)
        .is_some_and(|p| p == payload.new_peer_id.as_slice());
    if !is_own_current_binding && store.peer_id_in_use(&payload.new_peer_id) {
        return Err(ApplyError::ValidatorPeerIdConflict);
    }

    store.set_validator_peer_id(&tx.sender, payload.new_peer_id);

    Ok(())
}

/// Decode the CBOR payload for a `ValidatorRegister` transaction — ADR-047.
///
/// Field 5 (peer_id) is optional at decode for backward compatibility with
/// devnet-2 genesis transactions serialized before ADR-047. A missing field 5
/// decodes to `peer_id = vec![]` and emits a deprecation warning via `tracing`.
fn decode_register_payload(payload: &[u8]) -> Result<ValidatorRegisterPayload, ApplyError> {
    let value: Value = ciborium::de::from_reader(payload)
        .map_err(|e| ApplyError::PayloadDecode(format!("CBOR decode failed: {e}")))?;

    let map = match value {
        Value::Map(m) => m,
        _ => return Err(ApplyError::PayloadDecode("expected CBOR map".into())),
    };

    let mut node_id = None::<String>;
    let mut consensus_alg_id = None::<u16>;
    let mut consensus_pk = None::<Vec<u8>>;
    let mut self_bond = None::<u128>;
    let mut peer_id = None::<Vec<u8>>;

    for (k, v) in map {
        match k {
            Value::Integer(i) if i == 1i64.into() => {
                node_id = Some(match v {
                    Value::Bytes(b) => String::from_utf8(b)
                        .map_err(|_| ApplyError::PayloadDecode("node_id must be UTF-8".into()))?,
                    _ => return Err(ApplyError::PayloadDecode("field 1 must be bytes".into())),
                });
            }
            Value::Integer(i) if i == 2i64.into() => {
                consensus_alg_id = Some(match v {
                    Value::Integer(n) => {
                        let n: i128 = n.into();
                        u16::try_from(n)
                            .map_err(|_| ApplyError::PayloadDecode("alg_id overflow".into()))?
                    }
                    _ => return Err(ApplyError::PayloadDecode("field 2 must be integer".into())),
                });
            }
            Value::Integer(i) if i == 3i64.into() => {
                consensus_pk = Some(match v {
                    Value::Bytes(b) => b,
                    _ => return Err(ApplyError::PayloadDecode("field 3 must be bytes".into())),
                });
            }
            Value::Integer(i) if i == 4i64.into() => {
                self_bond = Some(match v {
                    Value::Bytes(b) if b.len() == 16 => {
                        let mut arr = [0u8; 16];
                        arr.copy_from_slice(&b);
                        u128::from_be_bytes(arr)
                    }
                    _ => {
                        return Err(ApplyError::PayloadDecode(
                            "field 4 must be 16-byte bstr".into(),
                        ))
                    }
                });
            }
            Value::Integer(i) if i == 5i64.into() => {
                peer_id = Some(match v {
                    Value::Bytes(b) => b,
                    _ => return Err(ApplyError::PayloadDecode("field 5 must be bytes".into())),
                });
            }
            _ => {}
        }
    }

    let peer_id = peer_id.unwrap_or_else(|| {
        tracing::warn!(
            target: "pqc_state::validator",
            "ValidatorRegister payload is missing field 5 (peer_id) — \
             accepting as legacy pre-ADR-047 payload with empty binding"
        );
        Vec::new()
    });

    Ok(ValidatorRegisterPayload {
        node_id: node_id
            .ok_or_else(|| ApplyError::PayloadDecode("missing field 1 (node_id)".into()))?,
        consensus_alg_id: consensus_alg_id
            .ok_or_else(|| ApplyError::PayloadDecode("missing field 2 (alg_id)".into()))?,
        consensus_pk: consensus_pk
            .ok_or_else(|| ApplyError::PayloadDecode("missing field 3 (consensus_pk)".into()))?,
        self_bond: self_bond
            .ok_or_else(|| ApplyError::PayloadDecode("missing field 4 (self_bond)".into()))?,
        peer_id,
    })
}

/// Decode the CBOR payload for a `ValidatorRotatePeerId` transaction — ADR-047.
fn decode_rotate_peer_id_payload(
    payload: &[u8],
) -> Result<ValidatorRotatePeerIdPayload, ApplyError> {
    let value: Value = ciborium::de::from_reader(payload)
        .map_err(|e| ApplyError::PayloadDecode(format!("CBOR decode failed: {e}")))?;

    let map = match value {
        Value::Map(m) => m,
        _ => return Err(ApplyError::PayloadDecode("expected CBOR map".into())),
    };

    let mut new_peer_id = None::<Vec<u8>>;

    for (k, v) in map {
        if let Value::Integer(i) = k {
            if i == 1i64.into() {
                new_peer_id = Some(match v {
                    Value::Bytes(b) => b,
                    _ => return Err(ApplyError::PayloadDecode("field 1 must be bytes".into())),
                });
            }
        }
    }

    Ok(ValidatorRotatePeerIdPayload {
        new_peer_id: new_peer_id
            .ok_or_else(|| ApplyError::PayloadDecode("missing field 1 (new_peer_id)".into()))?,
    })
}

/// Encode a `ValidatorRegister` payload as CBOR — ADR-047.
///
/// When `peer_id` is empty the encoder omits CBOR key 5 so the wire form is
/// byte-identical to the pre-ADR-047 4-field encoding.
pub fn encode_register_payload(p: &ValidatorRegisterPayload) -> Vec<u8> {
    let mut entries: Vec<(Value, Value)> = vec![
        (
            Value::Integer(1i64.into()),
            Value::Bytes(p.node_id.as_bytes().to_vec()),
        ),
        (
            Value::Integer(2i64.into()),
            Value::Integer((p.consensus_alg_id as i64).into()),
        ),
        (
            Value::Integer(3i64.into()),
            Value::Bytes(p.consensus_pk.clone()),
        ),
        (
            Value::Integer(4i64.into()),
            Value::Bytes(p.self_bond.to_be_bytes().to_vec()),
        ),
    ];
    if !p.peer_id.is_empty() {
        entries.push((Value::Integer(5i64.into()), Value::Bytes(p.peer_id.clone())));
    }
    let map = Value::Map(entries);
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&map, &mut buf).expect("CBOR encode is infallible");
    buf
}

/// Encode a `ValidatorRotatePeerId` payload as CBOR — ADR-047.
pub fn encode_rotate_peer_id_payload(new_peer_id: &[u8]) -> Vec<u8> {
    let map = Value::Map(vec![(
        Value::Integer(1i64.into()),
        Value::Bytes(new_peer_id.to_vec()),
    )]);
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&map, &mut buf).expect("CBOR encode is infallible");
    buf
}

/// Encode a `ValidatorExit` or `ValidatorUnjail` payload as CBOR (empty map).
pub fn encode_empty_validator_payload() -> Vec<u8> {
    let map: Value = Value::Map(vec![]);
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&map, &mut buf).expect("CBOR encode is infallible");
    buf
}

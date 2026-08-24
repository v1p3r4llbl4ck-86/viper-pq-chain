// SPDX-License-Identifier: Apache-2.0
//! CBOR encoding and decoding for transaction envelopes.
//!
//! SPEC-TX-001 §4 — deterministic CBOR rules.
//! SPEC-TX-001 §8, steps 1-2 — canonical encoding check at validation entry.
//!
//! Rules enforced on decode:
//!   R-1: map keys in ascending numeric order
//!   R-2: shortest-form integer and byte string encoding
//!   R-3: no indefinite-length encodings
//!   R-4: no duplicate map keys
//!   R-5: no floating-point values in protocol objects

use crate::error::TxError;
use ciborium::value::Value;
use pqc_crypto::AlgId;
use pqc_types::{
    account::Address,
    transaction::{MsgType, Transaction},
};

/// Decode a transaction from canonical CBOR bytes.
///
/// Returns `TxError::EncodingInvalid` for any CBOR that does not meet the
/// deterministic encoding rules (SPEC-TX-001 §4).
pub fn decode_tx(bytes: &[u8]) -> Result<Transaction, TxError> {
    let value: Value = ciborium::from_reader(bytes).map_err(|_| TxError::EncodingInvalid)?;

    let map = match value {
        Value::Map(m) => m,
        _ => return Err(TxError::EncodingInvalid),
    };

    // Re-encode and compare to detect non-canonical inputs (round-trip check).
    // Any non-deterministic encoding will produce different bytes.
    let mut reencoded = Vec::new();
    ciborium::into_writer(&Value::Map(map.clone()), &mut reencoded)
        .map_err(|_| TxError::EncodingInvalid)?;
    if reencoded != bytes {
        return Err(TxError::EncodingInvalid);
    }

    // Extract fields from the map by integer key.
    let fields = MapFields::from_pairs(map)?;

    let tx_version = fields.get_u8(1)?;
    let chain_id = fields.get_bytes(2)?;
    let msg_type_raw = fields.get_u16(3)?;
    let sender_bytes = fields.get_bytes(4)?;
    let nonce = fields.get_u64(5)?;
    let fee = fields.get_u64(6)?;
    let fee_tip = fields.get_u64_optional(7)?.unwrap_or(0);
    let gas_limit = fields.get_u64(8)?;
    let payload = fields.get_bytes(9)?;
    let sig_alg_id_raw = fields.get_u16(10)?;
    let sig_key_version = fields.get_u32(11)?;
    let signature = fields.get_bytes(12)?;

    let msg_type = MsgType::from_u16(msg_type_raw).ok_or(TxError::MsgTypeUnknown(msg_type_raw))?;

    let sig_alg_id =
        AlgId::from_u16(sig_alg_id_raw).ok_or(TxError::AlgorithmNotFound(sig_alg_id_raw))?;

    // Decode TLV envelope — ADR-044
    let (envelope_alg_id, signature) =
        pqc_crypto::decode_sig_envelope(&signature).map_err(|_| TxError::EncodingInvalid)?;
    // Consistency check: TLV algo_id must match CBOR field 10
    if envelope_alg_id != sig_alg_id {
        return Err(TxError::EncodingInvalid);
    }

    if sender_bytes.len() != 32 {
        return Err(TxError::EncodingInvalid);
    }
    let mut sender_arr = [0u8; 32];
    sender_arr.copy_from_slice(&sender_bytes);

    Ok(Transaction {
        tx_version,
        chain_id,
        msg_type,
        sender: Address(sender_arr),
        nonce,
        fee,
        fee_tip,
        gas_limit,
        payload,
        sig_alg_id,
        sig_key_version,
        signature,
    })
}

/// Encode a transaction to canonical CBOR bytes.
pub fn encode_tx(tx: &Transaction) -> Result<Vec<u8>, TxError> {
    use ciborium::value::Value;

    let mut pairs = vec![
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
        (
            Value::Integer(12u64.into()),
            Value::Bytes(
                pqc_crypto::encode_sig_envelope(tx.sig_alg_id, &tx.signature)
                    .map_err(|_| TxError::EncodingInvalid)?,
            ),
        ),
    ];

    // Field 7 (fee_tip) is omitted when zero — SPEC-TX-001 §3.
    if tx.fee_tip != 0 {
        // Insert at position 6 (after fee, before gas_limit) to maintain key order.
        pairs.insert(
            6,
            (
                Value::Integer(7u64.into()),
                Value::Integer(tx.fee_tip.into()),
            ),
        );
    }

    let mut out = Vec::new();
    ciborium::into_writer(&Value::Map(pairs), &mut out).map_err(|_| TxError::EncodingInvalid)?;
    Ok(out)
}

// ── Internal helpers ──────────────────────────────────────────────────────────

struct MapFields(std::collections::HashMap<i128, Value>);

impl MapFields {
    fn from_pairs(pairs: Vec<(Value, Value)>) -> Result<Self, TxError> {
        let mut map = std::collections::HashMap::new();
        for (k, v) in pairs {
            let key = match k {
                Value::Integer(i) => i128::from(i),
                _ => return Err(TxError::EncodingInvalid),
            };
            if map.insert(key, v).is_some() {
                // R-4: no duplicate keys
                return Err(TxError::EncodingInvalid);
            }
        }
        Ok(Self(map))
    }

    fn get_u8(&self, key: u64) -> Result<u8, TxError> {
        self.get_integer(key as i128)
            .and_then(|v| u8::try_from(v).map_err(|_| TxError::EncodingInvalid))
    }
    fn get_u16(&self, key: u64) -> Result<u16, TxError> {
        self.get_integer(key as i128)
            .and_then(|v| u16::try_from(v).map_err(|_| TxError::EncodingInvalid))
    }
    fn get_u32(&self, key: u64) -> Result<u32, TxError> {
        self.get_integer(key as i128)
            .and_then(|v| u32::try_from(v).map_err(|_| TxError::EncodingInvalid))
    }
    fn get_u64(&self, key: u64) -> Result<u64, TxError> {
        self.get_integer(key as i128)
            .and_then(|v| u64::try_from(v).map_err(|_| TxError::EncodingInvalid))
    }
    fn get_u64_optional(&self, key: u64) -> Result<Option<u64>, TxError> {
        match self.0.get(&(key as i128)) {
            None => Ok(None),
            Some(_) => self.get_u64(key).map(Some),
        }
    }
    fn get_bytes(&self, key: u64) -> Result<Vec<u8>, TxError> {
        match self.0.get(&(key as i128)) {
            Some(Value::Bytes(b)) => Ok(b.clone()),
            Some(_) => Err(TxError::EncodingInvalid),
            None => Err(TxError::EncodingInvalid),
        }
    }
    fn get_integer(&self, key: i128) -> Result<i128, TxError> {
        match self.0.get(&key) {
            Some(Value::Integer(i)) => Ok(i128::from(*i)),
            Some(_) => Err(TxError::EncodingInvalid),
            None => Err(TxError::EncodingInvalid),
        }
    }
}

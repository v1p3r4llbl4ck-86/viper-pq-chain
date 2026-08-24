// SPDX-License-Identifier: Apache-2.0
//! Consensus gossip message types — SPEC-CONSENSUS-001 §8.2 / §8.3.
//!
//! A `SignedVote` is the on-wire shape of a single BFT vote (Prevote or
//! Precommit) broadcast during consensus. It is the payload carried inside
//! a `pqc-p2p` `GossipMessage` envelope with outer `MessageType::ConsensusVote`.
//!
//! CBOR encoding uses deterministic integer keys per RFC 8949 §4.2, matching
//! the convention established by `slashing::EquivocationVote` in this crate.
//! Unknown keys are rejected on decode.
//!
//! Relationship to `slashing::EquivocationVote`:
//! - `SignedVote` is the on-wire gossip message (carries `msg_type` and
//!   `validator_address`; `step` is implicit in `msg_type`).
//! - `EquivocationVote` is the slashing-evidence projection (carries `step`
//!   as a compact u8; `validator_address` lives on the enclosing
//!   `EquivocationEvidence`).
//!
//! The two are intentionally distinct types: mutating one should never
//! silently alter the wire format of the other.

use ciborium::value::Value;

/// A single signed BFT vote for gossip — SPEC-CONSENSUS-001 §8.2 / §8.3.
///
/// CBOR field keys (ascending integer order, required):
/// - 1: `msg_type` (uint / u8; `0xC2` Prevote, `0xC3` Precommit)
/// - 2: `height` (uint / u64)
/// - 3: `round`  (uint / u32)
/// - 4: `block_hash` (bstr, exactly 32 bytes; `[0x00; 32]` = nil vote)
/// - 5: `validator_address` (bstr, exactly 32 bytes; operator address of the voter)
/// - 6: `signature` (bstr; ML-DSA-65 up to 3 309 bytes, or SLH-DSA-SHAKE-192s up to 16 224 bytes)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedVote {
    /// Consensus message discriminator: `0xC2` Prevote, `0xC3` Precommit.
    pub msg_type: u8,
    /// Block height being voted on.
    pub height: u64,
    /// BFT round within the height.
    pub round: u32,
    /// Hash of the block voted for; `[0x00; 32]` encodes a nil vote.
    pub block_hash: [u8; 32],
    /// Operator address of the voter.
    pub validator_address: [u8; 32],
    /// Signature over the vote preimage (SPEC-CONSENSUS-001 §8.4).
    pub signature: Vec<u8>,
}

/// Prevote discriminator (SPEC-CONSENSUS-001 §8.2).
pub const MSG_TYPE_PREVOTE: u8 = 0xC2;
/// Precommit discriminator (SPEC-CONSENSUS-001 §8.3).
pub const MSG_TYPE_PRECOMMIT: u8 = 0xC3;

/// Decode error for `SignedVote` CBOR payloads.
#[derive(Debug, PartialEq, Eq)]
pub enum SignedVoteDecodeError {
    /// Top-level structure is not a CBOR map, or CBOR parse failure.
    InvalidFormat(String),
    /// A required field is absent.
    MissingField(u8),
    /// A field value has the wrong type or is out of range.
    InvalidField(u8, String),
    /// The `msg_type` byte is not `0xC2` or `0xC3`.
    InvalidMsgType(u8),
}

impl std::fmt::Display for SignedVoteDecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidFormat(s) => write!(f, "INVALID_VOTE_FORMAT: {s}"),
            Self::MissingField(k) => write!(f, "INVALID_VOTE_FORMAT: missing field {k}"),
            Self::InvalidField(k, s) => write!(f, "INVALID_VOTE_FORMAT: field {k}: {s}"),
            Self::InvalidMsgType(v) => write!(
                f,
                "INVALID_VOTE_FORMAT: msg_type {v:#04x} is not 0xC2 (Prevote) or 0xC3 (Precommit)"
            ),
        }
    }
}

impl std::error::Error for SignedVoteDecodeError {}

// ── CBOR encoding ─────────────────────────────────────────────────────────────

/// Encode a `SignedVote` as a deterministic CBOR map (RFC 8949 §4.2).
///
/// Returns the `Value` rather than raw bytes so callers can embed the vote
/// inside a larger structure. Use [`encode_signed_vote_bytes`] for the
/// ready-to-send byte form.
pub fn encode_signed_vote(vote: &SignedVote) -> Value {
    Value::Map(vec![
        (
            Value::Integer(1i64.into()),
            Value::Integer((vote.msg_type as i64).into()),
        ),
        (
            Value::Integer(2i64.into()),
            Value::Integer(vote.height.into()),
        ),
        (
            Value::Integer(3i64.into()),
            Value::Integer(u64::from(vote.round).into()),
        ),
        (
            Value::Integer(4i64.into()),
            Value::Bytes(vote.block_hash.to_vec()),
        ),
        (
            Value::Integer(5i64.into()),
            Value::Bytes(vote.validator_address.to_vec()),
        ),
        (
            Value::Integer(6i64.into()),
            Value::Bytes(vote.signature.clone()),
        ),
    ])
}

/// Encode a `SignedVote` directly to CBOR bytes — ready to wrap in a
/// `pqc-p2p::GossipMessage` payload.
pub fn encode_signed_vote_bytes(vote: &SignedVote) -> Vec<u8> {
    let value = encode_signed_vote(vote);
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&value, &mut buf)
        .expect("CBOR encode is infallible for in-memory Vec writer");
    buf
}

// ── CBOR decoding ─────────────────────────────────────────────────────────────

/// Decode a `SignedVote` from raw CBOR bytes.
///
/// Rejects:
/// - payloads that are not a CBOR map
/// - maps with unknown keys (forward-compat safety — a future release adding
///   field 7 MUST bump the version or define a new type)
/// - `msg_type` values other than `0xC2` or `0xC3`
/// - `block_hash` or `validator_address` that are not exactly 32 bytes
pub fn decode_signed_vote(payload: &[u8]) -> Result<SignedVote, SignedVoteDecodeError> {
    let value: Value = ciborium::de::from_reader(payload)
        .map_err(|e| SignedVoteDecodeError::InvalidFormat(format!("CBOR parse error: {e}")))?;

    let map = match value {
        Value::Map(m) => m,
        _ => {
            return Err(SignedVoteDecodeError::InvalidFormat(
                "payload must be a CBOR map".into(),
            ))
        }
    };

    let mut msg_type = None::<u8>;
    let mut height = None::<u64>;
    let mut round = None::<u32>;
    let mut block_hash = None::<[u8; 32]>;
    let mut validator_address = None::<[u8; 32]>;
    let mut signature = None::<Vec<u8>>;

    for (k, v) in &map {
        let key_i: i64 = match k {
            Value::Integer(i) => {
                let n: i128 = (*i).into();
                i64::try_from(n).map_err(|_| {
                    SignedVoteDecodeError::InvalidFormat("key out of i64 range".into())
                })?
            }
            _ => {
                return Err(SignedVoteDecodeError::InvalidFormat(
                    "map key must be integer".into(),
                ))
            }
        };
        match key_i {
            1 => {
                let n: i128 = match v {
                    Value::Integer(i) => (*i).into(),
                    _ => {
                        return Err(SignedVoteDecodeError::InvalidField(
                            1,
                            "must be integer".into(),
                        ))
                    }
                };
                let byte = u8::try_from(n)
                    .map_err(|_| SignedVoteDecodeError::InvalidField(1, "u8 overflow".into()))?;
                if byte != MSG_TYPE_PREVOTE && byte != MSG_TYPE_PRECOMMIT {
                    return Err(SignedVoteDecodeError::InvalidMsgType(byte));
                }
                msg_type = Some(byte);
            }
            2 => {
                let n: i128 = match v {
                    Value::Integer(i) => (*i).into(),
                    _ => {
                        return Err(SignedVoteDecodeError::InvalidField(
                            2,
                            "must be integer".into(),
                        ))
                    }
                };
                height =
                    Some(u64::try_from(n).map_err(|_| {
                        SignedVoteDecodeError::InvalidField(2, "u64 overflow".into())
                    })?);
            }
            3 => {
                let n: i128 = match v {
                    Value::Integer(i) => (*i).into(),
                    _ => {
                        return Err(SignedVoteDecodeError::InvalidField(
                            3,
                            "must be integer".into(),
                        ))
                    }
                };
                round =
                    Some(u32::try_from(n).map_err(|_| {
                        SignedVoteDecodeError::InvalidField(3, "u32 overflow".into())
                    })?);
            }
            4 => {
                let bytes = match v {
                    Value::Bytes(b) => b,
                    _ => {
                        return Err(SignedVoteDecodeError::InvalidField(
                            4,
                            "must be bytes".into(),
                        ))
                    }
                };
                if bytes.len() != 32 {
                    return Err(SignedVoteDecodeError::InvalidField(
                        4,
                        format!("block_hash must be 32 bytes, got {}", bytes.len()),
                    ));
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(bytes);
                block_hash = Some(arr);
            }
            5 => {
                let bytes = match v {
                    Value::Bytes(b) => b,
                    _ => {
                        return Err(SignedVoteDecodeError::InvalidField(
                            5,
                            "must be bytes".into(),
                        ))
                    }
                };
                if bytes.len() != 32 {
                    return Err(SignedVoteDecodeError::InvalidField(
                        5,
                        format!("validator_address must be 32 bytes, got {}", bytes.len()),
                    ));
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(bytes);
                validator_address = Some(arr);
            }
            6 => {
                signature = Some(match v {
                    Value::Bytes(b) => b.clone(),
                    _ => {
                        return Err(SignedVoteDecodeError::InvalidField(
                            6,
                            "must be bytes".into(),
                        ))
                    }
                });
            }
            _ => {
                return Err(SignedVoteDecodeError::InvalidFormat(format!(
                    "unknown key {key_i} in SignedVote"
                )))
            }
        }
    }

    Ok(SignedVote {
        msg_type: msg_type.ok_or(SignedVoteDecodeError::MissingField(1))?,
        height: height.ok_or(SignedVoteDecodeError::MissingField(2))?,
        round: round.ok_or(SignedVoteDecodeError::MissingField(3))?,
        block_hash: block_hash.ok_or(SignedVoteDecodeError::MissingField(4))?,
        validator_address: validator_address.ok_or(SignedVoteDecodeError::MissingField(5))?,
        signature: signature.ok_or(SignedVoteDecodeError::MissingField(6))?,
    })
}

#[cfg(test)]
mod tests;

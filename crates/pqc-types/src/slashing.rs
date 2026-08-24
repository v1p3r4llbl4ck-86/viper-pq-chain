// SPDX-License-Identifier: Apache-2.0
//! Equivocation evidence types — SPEC-SLASH-001 §6–§7.
//!
//! An `EquivocationVote` represents one side of an equivocation: a single signed
//! vote broadcast during BFT consensus. An `EquivocationEvidence` bundles two
//! conflicting votes for the same `(height, round, step)` by the same validator.
//!
//! CBOR encoding uses deterministic integer keys per RFC 8949 §4.2 and
//! SPEC-SLASH-001 §6–§7.

use ciborium::value::Value;

/// One signed BFT vote — SPEC-SLASH-001 §6.
///
/// CBOR field keys (ascending integer order, required):
/// - 1: `height` (uint / u64)
/// - 2: `round`  (uint / u32)
/// - 3: `block_hash` (bstr, exactly 32 bytes; `[0x00;32]` = nil vote)
/// - 4: `step` (uint / u8; 0x01 = Prevote, 0x02 = Precommit)
/// - 5: `signature` (bstr; ML-DSA-65 signature, max 3 309 bytes)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EquivocationVote {
    /// Block height at which the vote was cast.
    pub height: u64,
    /// BFT round within the height.
    pub round: u32,
    /// Hash of the block voted for; `[0x00; 32]` encodes a nil vote.
    pub block_hash: [u8; 32],
    /// Vote phase: 0x01 = Prevote, 0x02 = Precommit.
    pub step: u8,
    /// ML-DSA-65 signature over the canonical vote preimage (SPEC-SLASH-001 §6.1).
    pub signature: Vec<u8>,
}

/// A single entry in the sliding-window correlation ledger — SPEC-SLASH-001 §17.4, ADR-048.
///
/// Each slashing execution records `(height, slashed_stake)` so that subsequent
/// slashings can look up the recent history within a 36-day window and scale
/// the penalty accordingly (Ethereum ETH2-style correlation penalty).
///
/// The ledger is kept in the `StateStore` and committed to the state root so
/// every validator agrees on the multiplier at apply-time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecentSlashEntry {
    /// Block height at which this slash was applied.
    pub height: u64,
    /// Stake slashed in this single event, in venom units. This is the
    /// `slash_amount` (bond × effective_fraction) computed at apply-time.
    pub slashed_stake: u128,
}

/// Two conflicting votes by the same validator — SPEC-SLASH-001 §7.
///
/// CBOR field keys (ascending integer order, required):
/// - 1: `validator_address` (bstr, exactly 32 bytes)
/// - 2: `height` (uint / u64; must equal vote_a.height and vote_b.height)
/// - 3: `vote_a` (map — EquivocationVote)
/// - 4: `vote_b` (map — EquivocationVote)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EquivocationEvidence {
    /// Operator address of the accused validator.
    pub validator_address: [u8; 32],
    /// Block height at which equivocation occurred.
    pub height: u64,
    /// First signed vote.
    pub vote_a: EquivocationVote,
    /// Conflicting signed vote.
    pub vote_b: EquivocationVote,
}

// ── CBOR encoding ─────────────────────────────────────────────────────────────

/// Encode an `EquivocationVote` as a deterministic CBOR map (SPEC-SLASH-001 §6).
pub fn encode_equivocation_vote(vote: &EquivocationVote) -> Value {
    Value::Map(vec![
        (
            Value::Integer(1i64.into()),
            Value::Integer(vote.height.into()),
        ),
        (
            Value::Integer(2i64.into()),
            Value::Integer(u64::from(vote.round).into()),
        ),
        (
            Value::Integer(3i64.into()),
            Value::Bytes(vote.block_hash.to_vec()),
        ),
        (
            Value::Integer(4i64.into()),
            Value::Integer((vote.step as i64).into()),
        ),
        (
            Value::Integer(5i64.into()),
            Value::Bytes(vote.signature.clone()),
        ),
    ])
}

/// Encode an `EquivocationEvidence` as deterministic CBOR (SPEC-SLASH-001 §7).
pub fn encode_equivocation_evidence(ev: &EquivocationEvidence) -> Vec<u8> {
    let map = Value::Map(vec![
        (
            Value::Integer(1i64.into()),
            Value::Bytes(ev.validator_address.to_vec()),
        ),
        (
            Value::Integer(2i64.into()),
            Value::Integer(ev.height.into()),
        ),
        (
            Value::Integer(3i64.into()),
            encode_equivocation_vote(&ev.vote_a),
        ),
        (
            Value::Integer(4i64.into()),
            encode_equivocation_vote(&ev.vote_b),
        ),
    ]);
    let mut buf = Vec::new();
    // SAFETY: ciborium only fails on I/O errors; Vec<u8> is infallible as the writer.
    ciborium::ser::into_writer(&map, &mut buf).expect("CBOR encode is infallible for valid data");
    buf
}

// ── CBOR decoding ─────────────────────────────────────────────────────────────

/// Decode error for equivocation CBOR payloads.
#[derive(Debug, PartialEq, Eq)]
pub enum EvidenceDecodeError {
    /// Top-level structure is not a CBOR map or has an unknown key.
    InvalidFormat(String),
    /// A required field is absent.
    MissingField(u8),
    /// A field value has the wrong type or is out of range.
    InvalidField(u8, String),
    /// The `step` byte is not 0x01 or 0x02.
    InvalidStep(u8),
}

impl std::fmt::Display for EvidenceDecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidFormat(s) => write!(f, "INVALID_EVIDENCE_FORMAT: {s}"),
            Self::MissingField(k) => write!(f, "INVALID_EVIDENCE_FORMAT: missing field {k}"),
            Self::InvalidField(k, s) => write!(f, "INVALID_EVIDENCE_FORMAT: field {k}: {s}"),
            Self::InvalidStep(v) => write!(
                f,
                "INVALID_EVIDENCE_FORMAT: step {v:#04x} is not 0x01 or 0x02"
            ),
        }
    }
}

/// Decode an `EquivocationVote` from an already-parsed CBOR `Value::Map`.
///
/// Rejects maps with unknown keys (SPEC-SLASH-001 §6: "A decoder MUST reject any
/// EquivocationVote with unknown keys").
pub fn decode_equivocation_vote(value: &Value) -> Result<EquivocationVote, EvidenceDecodeError> {
    let map = match value {
        Value::Map(m) => m,
        _ => {
            return Err(EvidenceDecodeError::InvalidFormat(
                "vote must be a CBOR map".into(),
            ))
        }
    };

    let mut height = None::<u64>;
    let mut round = None::<u32>;
    let mut block_hash = None::<[u8; 32]>;
    let mut step = None::<u8>;
    let mut signature = None::<Vec<u8>>;

    for (k, v) in map {
        let key_i: i64 = match k {
            Value::Integer(i) => {
                let n: i128 = (*i).into();
                i64::try_from(n).map_err(|_| {
                    EvidenceDecodeError::InvalidFormat("key out of i64 range".into())
                })?
            }
            _ => {
                return Err(EvidenceDecodeError::InvalidFormat(
                    "map key must be integer".into(),
                ))
            }
        };
        match key_i {
            1 => {
                let n: i128 = match v {
                    Value::Integer(i) => (*i).into(),
                    _ => {
                        return Err(EvidenceDecodeError::InvalidField(
                            1,
                            "must be integer".into(),
                        ))
                    }
                };
                height =
                    Some(u64::try_from(n).map_err(|_| {
                        EvidenceDecodeError::InvalidField(1, "u64 overflow".into())
                    })?);
            }
            2 => {
                let n: i128 = match v {
                    Value::Integer(i) => (*i).into(),
                    _ => {
                        return Err(EvidenceDecodeError::InvalidField(
                            2,
                            "must be integer".into(),
                        ))
                    }
                };
                round =
                    Some(u32::try_from(n).map_err(|_| {
                        EvidenceDecodeError::InvalidField(2, "u32 overflow".into())
                    })?);
            }
            3 => {
                let bytes = match v {
                    Value::Bytes(b) => b,
                    _ => return Err(EvidenceDecodeError::InvalidField(3, "must be bytes".into())),
                };
                if bytes.len() != 32 {
                    return Err(EvidenceDecodeError::InvalidField(
                        3,
                        format!("block_hash must be 32 bytes, got {}", bytes.len()),
                    ));
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(bytes);
                block_hash = Some(arr);
            }
            4 => {
                let n: i128 = match v {
                    Value::Integer(i) => (*i).into(),
                    _ => {
                        return Err(EvidenceDecodeError::InvalidField(
                            4,
                            "must be integer".into(),
                        ))
                    }
                };
                let byte = u8::try_from(n)
                    .map_err(|_| EvidenceDecodeError::InvalidField(4, "u8 overflow".into()))?;
                // step must be 0x01 (Prevote) or 0x02 (Precommit) — SPEC-SLASH-001 §6.2
                if byte != 0x01 && byte != 0x02 {
                    return Err(EvidenceDecodeError::InvalidStep(byte));
                }
                step = Some(byte);
            }
            5 => {
                signature = Some(match v {
                    Value::Bytes(b) => b.clone(),
                    _ => return Err(EvidenceDecodeError::InvalidField(5, "must be bytes".into())),
                });
            }
            _ => {
                return Err(EvidenceDecodeError::InvalidFormat(format!(
                    "unknown key {key_i} in EquivocationVote"
                )))
            }
        }
    }

    Ok(EquivocationVote {
        height: height.ok_or(EvidenceDecodeError::MissingField(1))?,
        round: round.ok_or(EvidenceDecodeError::MissingField(2))?,
        block_hash: block_hash.ok_or(EvidenceDecodeError::MissingField(3))?,
        step: step.ok_or(EvidenceDecodeError::MissingField(4))?,
        signature: signature.ok_or(EvidenceDecodeError::MissingField(5))?,
    })
}

/// Decode an `EquivocationEvidence` from raw CBOR bytes (SPEC-SLASH-001 §7).
pub fn decode_equivocation_evidence(
    payload: &[u8],
) -> Result<EquivocationEvidence, EvidenceDecodeError> {
    let value: Value = ciborium::de::from_reader(payload)
        .map_err(|e| EvidenceDecodeError::InvalidFormat(format!("CBOR parse error: {e}")))?;

    let map = match value {
        Value::Map(m) => m,
        _ => {
            return Err(EvidenceDecodeError::InvalidFormat(
                "payload must be a CBOR map".into(),
            ))
        }
    };

    let mut validator_address = None::<[u8; 32]>;
    let mut height = None::<u64>;
    let mut vote_a = None::<EquivocationVote>;
    let mut vote_b = None::<EquivocationVote>;

    for (k, v) in &map {
        let key_i: i64 = match k {
            Value::Integer(i) => {
                let n: i128 = (*i).into();
                i64::try_from(n).map_err(|_| {
                    EvidenceDecodeError::InvalidFormat("key out of i64 range".into())
                })?
            }
            _ => {
                return Err(EvidenceDecodeError::InvalidFormat(
                    "map key must be integer".into(),
                ))
            }
        };
        match key_i {
            1 => {
                let bytes = match v {
                    Value::Bytes(b) => b,
                    _ => return Err(EvidenceDecodeError::InvalidField(1, "must be bytes".into())),
                };
                if bytes.len() != 32 {
                    return Err(EvidenceDecodeError::InvalidField(
                        1,
                        format!("validator_address must be 32 bytes, got {}", bytes.len()),
                    ));
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(bytes);
                validator_address = Some(arr);
            }
            2 => {
                let n: i128 = match v {
                    Value::Integer(i) => (*i).into(),
                    _ => {
                        return Err(EvidenceDecodeError::InvalidField(
                            2,
                            "must be integer".into(),
                        ))
                    }
                };
                height =
                    Some(u64::try_from(n).map_err(|_| {
                        EvidenceDecodeError::InvalidField(2, "u64 overflow".into())
                    })?);
            }
            3 => {
                vote_a = Some(decode_equivocation_vote(v)?);
            }
            4 => {
                vote_b = Some(decode_equivocation_vote(v)?);
            }
            _ => {
                return Err(EvidenceDecodeError::InvalidFormat(format!(
                    "unknown key {key_i} in EquivocationEvidence"
                )))
            }
        }
    }

    Ok(EquivocationEvidence {
        validator_address: validator_address.ok_or(EvidenceDecodeError::MissingField(1))?,
        height: height.ok_or(EvidenceDecodeError::MissingField(2))?,
        vote_a: vote_a.ok_or(EvidenceDecodeError::MissingField(3))?,
        vote_b: vote_b.ok_or(EvidenceDecodeError::MissingField(4))?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_vote(height: u64, round: u32, step: u8, block_hash: [u8; 32]) -> EquivocationVote {
        EquivocationVote {
            height,
            round,
            step,
            block_hash,
            signature: vec![0xAA; 16],
        }
    }

    #[test]
    fn equivocation_evidence_cbor_roundtrip() {
        let vote_a = make_vote(42, 1, 0x01, [0xAB; 32]);
        let vote_b = make_vote(42, 1, 0x01, [0xCD; 32]);
        let evidence = EquivocationEvidence {
            validator_address: [0x01; 32],
            height: 42,
            vote_a,
            vote_b,
        };

        let encoded = encode_equivocation_evidence(&evidence);
        let decoded = decode_equivocation_evidence(&encoded).expect("round-trip must succeed");

        assert_eq!(decoded, evidence);
    }

    #[test]
    fn decode_rejects_invalid_step() {
        let mut vote = make_vote(1, 0, 0x01, [0u8; 32]);
        vote.step = 0x03; // invalid step value
                          // Encode with the invalid step manually
        let bad_map = Value::Map(vec![
            (
                Value::Integer(1i64.into()),
                Value::Integer((vote.height as i64).into()),
            ),
            (
                Value::Integer(2i64.into()),
                Value::Integer((vote.round as i64).into()),
            ),
            (
                Value::Integer(3i64.into()),
                Value::Bytes(vote.block_hash.to_vec()),
            ),
            (Value::Integer(4i64.into()), Value::Integer(3i64.into())),
            (
                Value::Integer(5i64.into()),
                Value::Bytes(vote.signature.clone()),
            ),
        ]);
        let err = decode_equivocation_vote(&bad_map).unwrap_err();
        assert!(matches!(err, EvidenceDecodeError::InvalidStep(0x03)));
    }

    #[test]
    fn decode_rejects_unknown_vote_key() {
        let bad_map = Value::Map(vec![
            (Value::Integer(1i64.into()), Value::Integer(1i64.into())),
            (Value::Integer(2i64.into()), Value::Integer(0i64.into())),
            (Value::Integer(3i64.into()), Value::Bytes(vec![0u8; 32])),
            (Value::Integer(4i64.into()), Value::Integer(1i64.into())),
            (Value::Integer(5i64.into()), Value::Bytes(vec![0xBB; 16])),
            (Value::Integer(99i64.into()), Value::Integer(0i64.into())), // unknown key
        ]);
        let err = decode_equivocation_vote(&bad_map).unwrap_err();
        assert!(matches!(err, EvidenceDecodeError::InvalidFormat(_)));
    }
}

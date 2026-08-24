// SPDX-License-Identifier: Apache-2.0
//! Multisig account types — SPEC-MULTISIG-001 §7.
//!
//! `MultisigPolicy` stores the on-chain authorization policy for a multisig account.
//! `MultisigMember` represents one authorized co-signer.
//! `MultisigWitness` is carried in the `signature` field (key 12) when `sig_alg_id = 0xFFFF`.
//!
//! CBOR encodings follow SPEC-MULTISIG-001 §7.1.1, §7.2.1, §7.3.1 with deterministic
//! integer keys in ascending order.

use ciborium::value::Value;
use pqc_crypto::AlgId;

// ── MultisigMember ────────────────────────────────────────────────────────────

/// One authorized co-signer within a `MultisigPolicy` — SPEC-MULTISIG-001 §7.2.
///
/// `alg_id` MUST NOT be `AlgId::Multisig` (nested multisig is forbidden).
/// `public_key` length MUST equal `Registry[alg_id].pk_size`.
/// `weight` MUST be ≥ 1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultisigMember {
    /// Co-signer's on-chain account address (32 bytes).
    pub address: [u8; 32],
    /// Signing algorithm for this member. MUST NOT be `AlgId::Multisig`.
    pub alg_id: AlgId,
    /// Raw public key bytes; length must match `Registry[alg_id].pk_size`.
    pub public_key: Vec<u8>,
    /// Signing weight; 1–255; default 1.
    pub weight: u8,
}

impl MultisigMember {
    /// Encode `MultisigMember` as a deterministic CBOR map value (integer keys 1–4).
    ///
    /// Key ordering: 1 (address), 2 (alg_id), 3 (public_key), 4 (weight).
    pub fn to_cbor_value(&self) -> Value {
        Value::Map(vec![
            (
                Value::Integer(1.into()),
                Value::Bytes(self.address.to_vec()),
            ),
            (
                Value::Integer(2.into()),
                Value::Integer((self.alg_id.as_u16() as u64).into()),
            ),
            (
                Value::Integer(3.into()),
                Value::Bytes(self.public_key.clone()),
            ),
            (
                Value::Integer(4.into()),
                Value::Integer((self.weight as u64).into()),
            ),
        ])
    }

    /// Decode a `MultisigMember` from a CBOR map value.
    pub fn from_cbor_value(value: Value) -> Result<Self, MultisigDecodeError> {
        let map = match value {
            Value::Map(m) => m,
            _ => return Err(MultisigDecodeError::ExpectedMap),
        };

        let mut address = None;
        let mut alg_id = None;
        let mut public_key = None;
        let mut weight = None;

        for (k, v) in map {
            let key = cbor_key_i128(k)?;
            match key {
                1 => address = Some(cbor_bytes32(v)?),
                2 => {
                    let raw = cbor_u16(v)?;
                    alg_id =
                        Some(AlgId::from_u16(raw).ok_or(MultisigDecodeError::UnknownAlgId(raw))?);
                }
                3 => {
                    let bytes = match v {
                        Value::Bytes(b) => b,
                        _ => return Err(MultisigDecodeError::ExpectedBytes),
                    };
                    public_key = Some(bytes);
                }
                4 => weight = Some(cbor_u8(v)?),
                _ => return Err(MultisigDecodeError::UnknownKey(key)),
            }
        }

        Ok(MultisigMember {
            address: address.ok_or(MultisigDecodeError::MissingField(1))?,
            alg_id: alg_id.ok_or(MultisigDecodeError::MissingField(2))?,
            public_key: public_key.ok_or(MultisigDecodeError::MissingField(3))?,
            weight: weight.ok_or(MultisigDecodeError::MissingField(4))?,
        })
    }
}

// ── MultisigPolicy ────────────────────────────────────────────────────────────

/// On-chain authorization policy for a multisig account — SPEC-MULTISIG-001 §7.1.
///
/// Constraints:
/// - `threshold` ≥ 1 and ≤ sum of all member weights.
/// - `members` contains 2–24 entries with distinct addresses.
/// - `policy_version` starts at 1 and increments by exactly 1 on each update.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultisigPolicy {
    /// Minimum weight sum required to authorize a transaction.
    pub threshold: u8,
    /// Ordered list of authorized co-signers.
    pub members: Vec<MultisigMember>,
    /// Monotonically increasing version counter; starts at 1.
    pub policy_version: u32,
}

impl MultisigPolicy {
    /// Encode `MultisigPolicy` as deterministic CBOR bytes (integer keys 1–3).
    ///
    /// Key ordering: 1 (threshold), 2 (members), 3 (policy_version).
    pub fn to_cbor_bytes(&self) -> Vec<u8> {
        let members_array = Value::Array(self.members.iter().map(|m| m.to_cbor_value()).collect());
        let map = Value::Map(vec![
            (
                Value::Integer(1.into()),
                Value::Integer((self.threshold as u64).into()),
            ),
            (Value::Integer(2.into()), members_array),
            (
                Value::Integer(3.into()),
                Value::Integer((self.policy_version as u64).into()),
            ),
        ]);
        let mut buf = Vec::new();
        // SAFETY: ciborium only fails on I/O errors; Vec<u8> is infallible as the writer.
        ciborium::into_writer(&map, &mut buf)
            .expect("CBOR encoding of MultisigPolicy is infallible");
        buf
    }

    /// Decode `MultisigPolicy` from CBOR bytes.
    pub fn from_cbor_bytes(bytes: &[u8]) -> Result<Self, MultisigDecodeError> {
        let value: Value =
            ciborium::from_reader(bytes).map_err(|_| MultisigDecodeError::CborMalformed)?;
        Self::from_cbor_value(value)
    }

    /// Decode from a CBOR `Value`.
    pub fn from_cbor_value(value: Value) -> Result<Self, MultisigDecodeError> {
        let map = match value {
            Value::Map(m) => m,
            _ => return Err(MultisigDecodeError::ExpectedMap),
        };

        let mut threshold = None;
        let mut members = None;
        let mut policy_version = None;

        for (k, v) in map {
            let key = cbor_key_i128(k)?;
            match key {
                1 => threshold = Some(cbor_u8(v)?),
                2 => {
                    let arr = match v {
                        Value::Array(a) => a,
                        _ => return Err(MultisigDecodeError::ExpectedArray),
                    };
                    let parsed: Result<Vec<MultisigMember>, _> = arr
                        .into_iter()
                        .map(MultisigMember::from_cbor_value)
                        .collect();
                    members = Some(parsed?);
                }
                3 => policy_version = Some(cbor_u32(v)?),
                _ => return Err(MultisigDecodeError::UnknownKey(key)),
            }
        }

        Ok(MultisigPolicy {
            threshold: threshold.ok_or(MultisigDecodeError::MissingField(1))?,
            members: members.ok_or(MultisigDecodeError::MissingField(2))?,
            policy_version: policy_version.ok_or(MultisigDecodeError::MissingField(3))?,
        })
    }
}

// ── MultisigWitness ───────────────────────────────────────────────────────────

/// Witness carried in the `signature` field (key 12) when `sig_alg_id = 0xFFFF` —
/// SPEC-MULTISIG-001 §7.3.
///
/// The `signature` field of the SPEC-TX-001 envelope MUST contain the CBOR encoding
/// of this struct as a byte string (key 12 type contract: `bstr`).
///
/// `signatures` MUST be sorted in ascending order of `member_index`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultisigWitness {
    /// Address of the multisig account authorizing this transaction.
    pub multisig_account: [u8; 32],
    /// Signature pairs `(member_index, sig_bytes)`, sorted ascending by `member_index`.
    pub signatures: Vec<(u8, Vec<u8>)>,
}

impl MultisigWitness {
    /// Encode `MultisigWitness` as deterministic CBOR bytes.
    ///
    /// Key ordering: 1 (multisig_account), 2 (signatures).
    /// `signatures` is encoded as an array of 2-element arrays `[member_index, sig_bytes]`.
    pub fn to_cbor_bytes(&self) -> Vec<u8> {
        let sigs_array = Value::Array(
            self.signatures
                .iter()
                .map(|(idx, sig)| {
                    Value::Array(vec![
                        Value::Integer((*idx as u64).into()),
                        Value::Bytes(sig.clone()),
                    ])
                })
                .collect(),
        );
        let map = Value::Map(vec![
            (
                Value::Integer(1.into()),
                Value::Bytes(self.multisig_account.to_vec()),
            ),
            (Value::Integer(2.into()), sigs_array),
        ]);
        let mut buf = Vec::new();
        // SAFETY: ciborium only fails on I/O errors; Vec<u8> is infallible as the writer.
        ciborium::into_writer(&map, &mut buf)
            .expect("CBOR encoding of MultisigWitness is infallible");
        buf
    }

    /// Decode `MultisigWitness` from CBOR bytes.
    pub fn from_cbor_bytes(bytes: &[u8]) -> Result<Self, MultisigDecodeError> {
        let value: Value =
            ciborium::from_reader(bytes).map_err(|_| MultisigDecodeError::CborMalformed)?;
        Self::from_cbor_value(value)
    }

    /// Decode from a CBOR `Value`.
    pub fn from_cbor_value(value: Value) -> Result<Self, MultisigDecodeError> {
        let map = match value {
            Value::Map(m) => m,
            _ => return Err(MultisigDecodeError::ExpectedMap),
        };

        let mut multisig_account = None;
        let mut signatures = None;

        for (k, v) in map {
            let key = cbor_key_i128(k)?;
            match key {
                1 => multisig_account = Some(cbor_bytes32(v)?),
                2 => {
                    let arr = match v {
                        Value::Array(a) => a,
                        _ => return Err(MultisigDecodeError::ExpectedArray),
                    };
                    let mut pairs = Vec::with_capacity(arr.len());
                    for item in arr {
                        let pair = match item {
                            Value::Array(a) if a.len() == 2 => a,
                            _ => return Err(MultisigDecodeError::ExpectedArray),
                        };
                        let mut it = pair.into_iter();
                        let (Some(idx_val), Some(sig_val)) = (it.next(), it.next()) else {
                            return Err(MultisigDecodeError::ExpectedArray);
                        };
                        let idx = cbor_u8(idx_val)?;
                        let sig_bytes = match sig_val {
                            Value::Bytes(b) => b,
                            _ => return Err(MultisigDecodeError::ExpectedBytes),
                        };
                        pairs.push((idx, sig_bytes));
                    }
                    signatures = Some(pairs);
                }
                _ => return Err(MultisigDecodeError::UnknownKey(key)),
            }
        }

        Ok(MultisigWitness {
            multisig_account: multisig_account.ok_or(MultisigDecodeError::MissingField(1))?,
            signatures: signatures.ok_or(MultisigDecodeError::MissingField(2))?,
        })
    }
}

// ── MultisigAccountState ──────────────────────────────────────────────────────

/// Full state entry for a multisig account in the MultisigAccountMap — SPEC-MULTISIG-001 §14.1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultisigAccountState {
    pub address: [u8; 32],
    pub balance: u128,
    pub nonce: u64,
    pub policy: MultisigPolicy,
}

impl MultisigAccountState {
    /// Encode as deterministic CBOR bytes (integer keys 1–4).
    pub fn to_cbor_bytes(&self) -> Vec<u8> {
        let map = Value::Map(vec![
            (
                Value::Integer(1.into()),
                Value::Bytes(self.address.to_vec()),
            ),
            // u128 does not fit in CBOR integer directly; encode as big-endian 16-byte bstr.
            (
                Value::Integer(2.into()),
                Value::Bytes(self.balance.to_be_bytes().to_vec()),
            ),
            (Value::Integer(3.into()), Value::Integer(self.nonce.into())),
            (Value::Integer(4.into()), {
                // Inline the policy map value rather than going through bytes.
                let members_array = Value::Array(
                    self.policy
                        .members
                        .iter()
                        .map(|m| m.to_cbor_value())
                        .collect(),
                );
                Value::Map(vec![
                    (
                        Value::Integer(1.into()),
                        Value::Integer((self.policy.threshold as u64).into()),
                    ),
                    (Value::Integer(2.into()), members_array),
                    (
                        Value::Integer(3.into()),
                        Value::Integer((self.policy.policy_version as u64).into()),
                    ),
                ])
            }),
        ]);
        let mut buf = Vec::new();
        // SAFETY: ciborium only fails on I/O errors; Vec<u8> is infallible as the writer.
        ciborium::into_writer(&map, &mut buf)
            .expect("CBOR encoding of MultisigAccountState is infallible");
        buf
    }
}

// ── Decode error ──────────────────────────────────────────────────────────────

#[derive(Debug, PartialEq, Eq)]
pub enum MultisigDecodeError {
    CborMalformed,
    ExpectedMap,
    ExpectedArray,
    ExpectedBytes,
    ExpectedInteger,
    IntegerOutOfRange,
    MissingField(i128),
    UnknownKey(i128),
    UnknownAlgId(u16),
}

impl std::fmt::Display for MultisigDecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CborMalformed => write!(f, "CBOR is malformed"),
            Self::ExpectedMap => write!(f, "expected CBOR map"),
            Self::ExpectedArray => write!(f, "expected CBOR array"),
            Self::ExpectedBytes => write!(f, "expected CBOR byte string"),
            Self::ExpectedInteger => write!(f, "expected CBOR integer"),
            Self::IntegerOutOfRange => write!(f, "integer value out of range"),
            Self::MissingField(k) => write!(f, "missing required field {k}"),
            Self::UnknownKey(k) => write!(f, "unknown map key {k}"),
            Self::UnknownAlgId(v) => write!(f, "unknown AlgId 0x{v:04X}"),
        }
    }
}

impl std::error::Error for MultisigDecodeError {}

// ── CBOR helper functions ─────────────────────────────────────────────────────

fn cbor_key_i128(v: Value) -> Result<i128, MultisigDecodeError> {
    match v {
        Value::Integer(i) => Ok(i128::from(i)),
        _ => Err(MultisigDecodeError::ExpectedInteger),
    }
}

fn cbor_u8(v: Value) -> Result<u8, MultisigDecodeError> {
    let i = match v {
        Value::Integer(i) => i128::from(i),
        _ => return Err(MultisigDecodeError::ExpectedInteger),
    };
    u8::try_from(i).map_err(|_| MultisigDecodeError::IntegerOutOfRange)
}

fn cbor_u16(v: Value) -> Result<u16, MultisigDecodeError> {
    let i = match v {
        Value::Integer(i) => i128::from(i),
        _ => return Err(MultisigDecodeError::ExpectedInteger),
    };
    u16::try_from(i).map_err(|_| MultisigDecodeError::IntegerOutOfRange)
}

fn cbor_u32(v: Value) -> Result<u32, MultisigDecodeError> {
    let i = match v {
        Value::Integer(i) => i128::from(i),
        _ => return Err(MultisigDecodeError::ExpectedInteger),
    };
    u32::try_from(i).map_err(|_| MultisigDecodeError::IntegerOutOfRange)
}

fn cbor_bytes32(v: Value) -> Result<[u8; 32], MultisigDecodeError> {
    let bytes = match v {
        Value::Bytes(b) => b,
        _ => return Err(MultisigDecodeError::ExpectedBytes),
    };
    if bytes.len() != 32 {
        return Err(MultisigDecodeError::ExpectedBytes);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

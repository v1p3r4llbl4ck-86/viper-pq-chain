// SPDX-License-Identifier: Apache-2.0
//! Archival overlay wire-format types — SPEC-ARCHIVAL-001 §4.4 / §4.5.
//!
//! This module holds the pure data types and deterministic CBOR codec for the
//! archival overlay. It is intentionally side-effect-free:
//!
//! - NO signing or verification (that lives in `pqc-crypto`, TASK-162).
//! - NO state-store integration (that lives in `pqc-state`, TASK-161).
//! - NO network wiring (that lives in `pqc-consensus` / the sidecar, TASK-163 / TASK-164).
//!
//! The codec follows the same deterministic-CBOR rules as SPEC-TX-001 §4 and
//! the ADR-030 field-tagged-map convention already used by `pqc-types::multisig`
//! and `pqc-tx::codec`:
//!
//! - Field-tagged map (not positional) for forward compatibility.
//! - Integer keys `1..=N` per field, ascending.
//! - No indefinite-length encodings.
//! - No duplicate map keys.
//! - No floating-point values.
//!
//! All CBOR helpers here are internal — public callers go through
//! `encode_archival_record` / `decode_archival_record` and their siblings.

use ciborium::value::Value;

// ── Constants ─────────────────────────────────────────────────────────────────

/// Length in bytes of an SLH-DSA-SHAKE-256s signature (FIPS 205, Cat 5).
///
/// Referenced by SPEC-ARCHIVAL-001 §4.5 and ADR-043. Kept as a soft check at
/// decode time so the codec stays forward-compatible if governance later adds
/// a different SLH parameter set via `ProposalEffect::AddArchivalAnchorKind`
/// (or an equivalent algorithm-addition flow).
pub const SLH_DSA_SHAKE_256S_SIG_LEN: usize = 29_792;

/// Length in bytes of an SLH-DSA-SHAKE-256s public key (FIPS 205, Cat 5).
pub const SLH_DSA_SHAKE_256S_PK_LEN: usize = 64;

/// Length in bytes of an SLH-DSA-SHAKE-256s secret key (FIPS 205, Cat 5 §10.3).
///
/// Consumed by the M4.4 archival-overlay signer — each designated validator
/// holds one in its local keystore to sign `epoch_root` at every epoch
/// boundary.
pub const SLH_DSA_SHAKE_256S_SK_LEN: usize = 128;

/// ADR-044 algorithm identifier for SLH-DSA-SHAKE-256s.
///
/// Registered alongside the existing ML-DSA / Falcon entries. The archival
/// overlay is the primary consumer (SPEC-ARCHIVAL-001 §4.5 and TASK-162).
pub const ARCHIVAL_ALG_ID_SLH_DSA_SHAKE_256S: u16 = 0x0023;

/// Sanity bound on `TimestampAnchor::external_hash` size — prevents a
/// pathologically-large TST / tx-id from slipping through the codec.
/// RFC 3161 TimeStampTokens in practice are a few KB; 16 KiB leaves generous
/// headroom for envelope-style anchors.
pub const TIMESTAMP_ANCHOR_EXTERNAL_HASH_MAX_LEN: usize = 16_384;

// ── EpochNumber ───────────────────────────────────────────────────────────────

/// Strongly-typed wrapper around the archival epoch counter.
///
/// The wrapping keeps `u64` epoch numbers from being accidentally confused with
/// block heights or other `u64` fields on a struct literal. The inner `u64` is
/// public so callers can pattern-match directly when they need the raw value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EpochNumber(pub u64);

// ── AnchorKind ────────────────────────────────────────────────────────────────

/// Variant of external timestamp anchor carried in a `TimestampAnchor`.
///
/// SPEC-ARCHIVAL-001 §4.4 + §6. The discriminant values are the wire codes; new
/// kinds are added by governance via `ProposalEffect::AddArchivalAnchorKind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AnchorKind {
    /// RFC 3161 Time-Stamp Authority token (default path, EU-qualified TSAs).
    Rfc3161Tsa = 0x01,
    /// Bitcoin `OP_RETURN` anchor (§6.4 — opt-in via governance).
    BitcoinOpReturn = 0x02,
    /// Ethereum L1 anchor (§6.4 — opt-in via governance).
    EthereumL1 = 0x03,
    /// Opaque fallback for future/TSA-family anchors not yet enumerated.
    OtherTsa = 0xFF,
}

impl AnchorKind {
    /// Wire-code for this variant.
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    /// Build a variant from a wire code. Returns `None` for unknown codes so
    /// the decoder can surface a structured error.
    pub fn from_u8(raw: u8) -> Option<Self> {
        match raw {
            0x01 => Some(Self::Rfc3161Tsa),
            0x02 => Some(Self::BitcoinOpReturn),
            0x03 => Some(Self::EthereumL1),
            0xFF => Some(Self::OtherTsa),
            _ => None,
        }
    }
}

// ── TsaRef ────────────────────────────────────────────────────────────────────

/// Stable reference to a particular RFC 3161 TSA.
///
/// Present on `TimestampAnchor` only when `kind == AnchorKind::Rfc3161Tsa`.
/// The `cert_fingerprint_sha256` pins the TSA's X.509 certificate identity at
/// the moment of anchor submission (SPEC-ARCHIVAL-001 §6.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TsaRef {
    /// Service URL of the TSA — e.g. `"https://tsa.aruba.it"`.
    pub url: String,
    /// SHA-256 fingerprint of the TSA's X.509 certificate (DER).
    pub cert_fingerprint_sha256: [u8; 32],
    /// OPTIONAL TSA policy OID — e.g. `"1.2.3.4"`. `None` encodes as absent.
    pub policy_oid: Option<String>,
}

// ── TimestampAnchor ───────────────────────────────────────────────────────────

/// External-world anchor attached to an `ArchivalRecord` (SPEC-ARCHIVAL-001 §4.4 / §6).
///
/// `tsa_ref` MUST be `Some` for `AnchorKind::Rfc3161Tsa` and MUST be `None`
/// for the other kinds. The decoder enforces this invariant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimestampAnchor {
    /// Which external-timestamping mechanism produced this anchor.
    pub kind: AnchorKind,
    /// TSA reference (URL + cert pin + optional policy OID) when `kind` is an RFC 3161 TSA.
    pub tsa_ref: Option<TsaRef>,
    /// Opaque wire evidence: DER of the RFC 3161 TimeStampToken, or a tx-id, etc.
    pub external_hash: Vec<u8>,
    /// Local block height at which the anchor transaction was applied.
    pub posted_at_height: u64,
}

// ── ValidatorArchivalKey ──────────────────────────────────────────────────────

/// Registration record for a validator's archival-overlay signing key
/// (SPEC-ARCHIVAL-001 §4.5).
///
/// The archival key is separate from the consensus key by design (ADR-043 /
/// ADR-045 — family diversification). `archival_alg_id` identifies the
/// algorithm so the registry-driven dispatcher in `pqc-crypto` can verify
/// signatures produced with this key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatorArchivalKey {
    /// Operator (validator) address that owns this archival key.
    pub operator: [u8; 32],
    /// ADR-044 algorithm identifier — e.g. `0x0023` for SLH-DSA-SHAKE-256s.
    pub archival_alg_id: u16,
    /// Raw archival public key. Length should match `Registry[alg_id].pk_size`.
    pub archival_pk: Vec<u8>,
    /// Block height at which this archival key was registered.
    pub registered_at_height: u64,
}

// ── ArchivalRecord ────────────────────────────────────────────────────────────

/// On-chain archival record produced at an epoch boundary
/// (SPEC-ARCHIVAL-001 §4.4).
///
/// `signer_addresses` MUST be sorted lexicographically ascending, and
/// `slh_signatures[i]` MUST correspond to `signer_addresses[i]` (zipped).
/// Both invariants are enforced at decode time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchivalRecord {
    /// Epoch number this record covers.
    pub epoch_number: u64,
    /// `SHAKE-256(concat(block_hashes_in_epoch))` — SPEC-ARCHIVAL-001 §4.1.
    pub epoch_root: [u8; 32],
    /// Sorted list of validator addresses that signed this epoch's archival
    /// preimage (SPEC-ARCHIVAL-001 §4.5). Lexicographic ascending order.
    pub signer_addresses: Vec<[u8; 32]>,
    /// SLH-DSA-SHAKE-256s signatures, one per entry in `signer_addresses`.
    /// Expected length per signature: `SLH_DSA_SHAKE_256S_SIG_LEN` = 29 792 B.
    pub slh_signatures: Vec<Vec<u8>>,
    /// External-world timestamp anchors attached to this record.
    pub timestamp_anchors: Vec<TimestampAnchor>,
    /// ERS renewal chain counter (SPEC-ARCHIVAL-001 §8). Starts at 0.
    pub evidence_record_version: u16,
}

// ── Decode error ──────────────────────────────────────────────────────────────

/// Structured error returned by the archival CBOR decoders.
#[derive(Debug, PartialEq, Eq)]
pub enum ArchivalDecodeError {
    /// CBOR bytes are malformed or not canonical.
    CborMalformed,
    /// Top-level value was not a map.
    ExpectedMap,
    /// Expected a byte string but got something else.
    ExpectedBytes,
    /// Expected a text string but got something else.
    ExpectedText,
    /// Expected an array but got something else.
    ExpectedArray,
    /// Expected an integer but got something else.
    ExpectedInteger,
    /// Integer value did not fit in the target width.
    IntegerOutOfRange,
    /// A byte string had an unexpected length (e.g. `epoch_root` not 32 bytes).
    InvalidByteLength {
        field: i128,
        expected: usize,
        actual: usize,
    },
    /// Required field was absent from the map.
    MissingField(i128),
    /// Map contained a key that is not defined for this type.
    UnknownKey(i128),
    /// Map contained a duplicate integer key.
    DuplicateKey(i128),
    /// `AnchorKind` discriminant was not a known variant.
    UnknownAnchorKind(u8),
    /// `signer_addresses` was not sorted lexicographically ascending.
    SignersUnsorted,
    /// `signer_addresses.len() != slh_signatures.len()`.
    SignerSignatureCountMismatch { signers: usize, sigs: usize },
    /// `TsaRef` was present for a non-RFC-3161 anchor kind, or absent for one.
    AnchorTsaRefInconsistent,
    /// `external_hash` exceeded `TIMESTAMP_ANCHOR_EXTERNAL_HASH_MAX_LEN`.
    ExternalHashTooLarge(usize),
}

impl std::fmt::Display for ArchivalDecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CborMalformed => write!(f, "CBOR is malformed or non-canonical"),
            Self::ExpectedMap => write!(f, "expected CBOR map"),
            Self::ExpectedBytes => write!(f, "expected CBOR byte string"),
            Self::ExpectedText => write!(f, "expected CBOR text string"),
            Self::ExpectedArray => write!(f, "expected CBOR array"),
            Self::ExpectedInteger => write!(f, "expected CBOR integer"),
            Self::IntegerOutOfRange => write!(f, "integer value out of range"),
            Self::InvalidByteLength {
                field,
                expected,
                actual,
            } => write!(
                f,
                "field {field}: invalid byte length (expected {expected}, got {actual})"
            ),
            Self::MissingField(k) => write!(f, "missing required field {k}"),
            Self::UnknownKey(k) => write!(f, "unknown map key {k}"),
            Self::DuplicateKey(k) => write!(f, "duplicate map key {k}"),
            Self::UnknownAnchorKind(v) => write!(f, "unknown AnchorKind 0x{v:02X}"),
            Self::SignersUnsorted => {
                write!(
                    f,
                    "signer_addresses must be sorted lexicographically ascending"
                )
            }
            Self::SignerSignatureCountMismatch { signers, sigs } => write!(
                f,
                "signer_addresses.len() ({signers}) != slh_signatures.len() ({sigs})"
            ),
            Self::AnchorTsaRefInconsistent => write!(
                f,
                "tsa_ref presence must match AnchorKind (Some iff Rfc3161Tsa)"
            ),
            Self::ExternalHashTooLarge(n) => write!(
                f,
                "external_hash too large: {n} > {TIMESTAMP_ANCHOR_EXTERNAL_HASH_MAX_LEN}"
            ),
        }
    }
}

impl std::error::Error for ArchivalDecodeError {}

// ── Encode / decode: TsaRef ───────────────────────────────────────────────────

/// Field keys for `TsaRef` CBOR map.
const KEY_TSA_URL: u64 = 1;
const KEY_TSA_CERT_FP: u64 = 2;
const KEY_TSA_POLICY_OID: u64 = 3;

fn tsa_ref_to_cbor_value(t: &TsaRef) -> Value {
    let mut pairs = vec![
        (
            Value::Integer(KEY_TSA_URL.into()),
            Value::Text(t.url.clone()),
        ),
        (
            Value::Integer(KEY_TSA_CERT_FP.into()),
            Value::Bytes(t.cert_fingerprint_sha256.to_vec()),
        ),
    ];
    if let Some(oid) = &t.policy_oid {
        pairs.push((
            Value::Integer(KEY_TSA_POLICY_OID.into()),
            Value::Text(oid.clone()),
        ));
    }
    Value::Map(pairs)
}

fn tsa_ref_from_cbor_value(value: Value) -> Result<TsaRef, ArchivalDecodeError> {
    let map = match value {
        Value::Map(m) => m,
        _ => return Err(ArchivalDecodeError::ExpectedMap),
    };

    let mut url: Option<String> = None;
    let mut cert_fp: Option<[u8; 32]> = None;
    let mut policy_oid: Option<String> = None;
    let mut seen_keys = std::collections::BTreeSet::<i128>::new();

    for (k, v) in map {
        let key = cbor_key_i128(k)?;
        if !seen_keys.insert(key) {
            return Err(ArchivalDecodeError::DuplicateKey(key));
        }
        match key {
            k if k == KEY_TSA_URL as i128 => url = Some(cbor_text(v)?),
            k if k == KEY_TSA_CERT_FP as i128 => cert_fp = Some(cbor_bytes_fixed(v, 32, k)?),
            k if k == KEY_TSA_POLICY_OID as i128 => policy_oid = Some(cbor_text(v)?),
            other => return Err(ArchivalDecodeError::UnknownKey(other)),
        }
    }

    Ok(TsaRef {
        url: url.ok_or(ArchivalDecodeError::MissingField(KEY_TSA_URL as i128))?,
        cert_fingerprint_sha256: cert_fp
            .ok_or(ArchivalDecodeError::MissingField(KEY_TSA_CERT_FP as i128))?,
        policy_oid,
    })
}

/// Encode a `TsaRef` to canonical CBOR bytes.
pub fn encode_tsa_ref(t: &TsaRef) -> Vec<u8> {
    let mut buf = Vec::new();
    ciborium::into_writer(&tsa_ref_to_cbor_value(t), &mut buf)
        .expect("CBOR encoding of TsaRef is infallible into Vec<u8>");
    buf
}

/// Decode a `TsaRef` from canonical CBOR bytes.
pub fn decode_tsa_ref(bytes: &[u8]) -> Result<TsaRef, ArchivalDecodeError> {
    let value: Value =
        ciborium::from_reader(bytes).map_err(|_| ArchivalDecodeError::CborMalformed)?;
    tsa_ref_from_cbor_value(value)
}

// ── Encode / decode: TimestampAnchor ──────────────────────────────────────────

/// Field keys for `TimestampAnchor` CBOR map.
const KEY_ANCHOR_KIND: u64 = 1;
const KEY_ANCHOR_TSA_REF: u64 = 2;
const KEY_ANCHOR_EXTERNAL_HASH: u64 = 3;
const KEY_ANCHOR_POSTED_AT_HEIGHT: u64 = 4;

fn timestamp_anchor_to_cbor_value(a: &TimestampAnchor) -> Value {
    let mut pairs = vec![(
        Value::Integer(KEY_ANCHOR_KIND.into()),
        Value::Integer((a.kind.as_u8() as u64).into()),
    )];
    if let Some(tsa) = &a.tsa_ref {
        pairs.push((
            Value::Integer(KEY_ANCHOR_TSA_REF.into()),
            tsa_ref_to_cbor_value(tsa),
        ));
    }
    pairs.push((
        Value::Integer(KEY_ANCHOR_EXTERNAL_HASH.into()),
        Value::Bytes(a.external_hash.clone()),
    ));
    pairs.push((
        Value::Integer(KEY_ANCHOR_POSTED_AT_HEIGHT.into()),
        Value::Integer(a.posted_at_height.into()),
    ));
    Value::Map(pairs)
}

fn timestamp_anchor_from_cbor_value(value: Value) -> Result<TimestampAnchor, ArchivalDecodeError> {
    let map = match value {
        Value::Map(m) => m,
        _ => return Err(ArchivalDecodeError::ExpectedMap),
    };

    let mut kind: Option<AnchorKind> = None;
    let mut tsa_ref: Option<TsaRef> = None;
    let mut external_hash: Option<Vec<u8>> = None;
    let mut posted_at_height: Option<u64> = None;
    let mut seen_keys = std::collections::BTreeSet::<i128>::new();

    for (k, v) in map {
        let key = cbor_key_i128(k)?;
        if !seen_keys.insert(key) {
            return Err(ArchivalDecodeError::DuplicateKey(key));
        }
        match key {
            k if k == KEY_ANCHOR_KIND as i128 => {
                let raw = cbor_u8(v)?;
                kind = Some(
                    AnchorKind::from_u8(raw).ok_or(ArchivalDecodeError::UnknownAnchorKind(raw))?,
                );
            }
            k if k == KEY_ANCHOR_TSA_REF as i128 => {
                tsa_ref = Some(tsa_ref_from_cbor_value(v)?);
            }
            k if k == KEY_ANCHOR_EXTERNAL_HASH as i128 => {
                let bytes = cbor_bytes(v)?;
                if bytes.len() > TIMESTAMP_ANCHOR_EXTERNAL_HASH_MAX_LEN {
                    return Err(ArchivalDecodeError::ExternalHashTooLarge(bytes.len()));
                }
                external_hash = Some(bytes);
            }
            k if k == KEY_ANCHOR_POSTED_AT_HEIGHT as i128 => posted_at_height = Some(cbor_u64(v)?),
            other => return Err(ArchivalDecodeError::UnknownKey(other)),
        }
    }

    let kind = kind.ok_or(ArchivalDecodeError::MissingField(KEY_ANCHOR_KIND as i128))?;
    let external_hash = external_hash.ok_or(ArchivalDecodeError::MissingField(
        KEY_ANCHOR_EXTERNAL_HASH as i128,
    ))?;
    let posted_at_height = posted_at_height.ok_or(ArchivalDecodeError::MissingField(
        KEY_ANCHOR_POSTED_AT_HEIGHT as i128,
    ))?;

    // Presence invariant: tsa_ref is Some iff kind == Rfc3161Tsa.
    match (&kind, &tsa_ref) {
        (AnchorKind::Rfc3161Tsa, Some(_)) => {}
        (AnchorKind::Rfc3161Tsa, None) => {
            return Err(ArchivalDecodeError::AnchorTsaRefInconsistent)
        }
        (_, Some(_)) => return Err(ArchivalDecodeError::AnchorTsaRefInconsistent),
        (_, None) => {}
    }

    Ok(TimestampAnchor {
        kind,
        tsa_ref,
        external_hash,
        posted_at_height,
    })
}

/// Encode a `TimestampAnchor` to canonical CBOR bytes.
pub fn encode_timestamp_anchor(a: &TimestampAnchor) -> Vec<u8> {
    let mut buf = Vec::new();
    ciborium::into_writer(&timestamp_anchor_to_cbor_value(a), &mut buf)
        .expect("CBOR encoding of TimestampAnchor is infallible into Vec<u8>");
    buf
}

/// Decode a `TimestampAnchor` from canonical CBOR bytes.
pub fn decode_timestamp_anchor(bytes: &[u8]) -> Result<TimestampAnchor, ArchivalDecodeError> {
    let value: Value =
        ciborium::from_reader(bytes).map_err(|_| ArchivalDecodeError::CborMalformed)?;
    timestamp_anchor_from_cbor_value(value)
}

// ── Encode / decode: ValidatorArchivalKey ─────────────────────────────────────

/// Field keys for `ValidatorArchivalKey` CBOR map.
const KEY_VAK_OPERATOR: u64 = 1;
const KEY_VAK_ALG_ID: u64 = 2;
const KEY_VAK_PK: u64 = 3;
const KEY_VAK_REGISTERED_AT: u64 = 4;

fn validator_archival_key_to_cbor_value(k: &ValidatorArchivalKey) -> Value {
    Value::Map(vec![
        (
            Value::Integer(KEY_VAK_OPERATOR.into()),
            Value::Bytes(k.operator.to_vec()),
        ),
        (
            Value::Integer(KEY_VAK_ALG_ID.into()),
            Value::Integer((k.archival_alg_id as u64).into()),
        ),
        (
            Value::Integer(KEY_VAK_PK.into()),
            Value::Bytes(k.archival_pk.clone()),
        ),
        (
            Value::Integer(KEY_VAK_REGISTERED_AT.into()),
            Value::Integer(k.registered_at_height.into()),
        ),
    ])
}

fn validator_archival_key_from_cbor_value(
    value: Value,
) -> Result<ValidatorArchivalKey, ArchivalDecodeError> {
    let map = match value {
        Value::Map(m) => m,
        _ => return Err(ArchivalDecodeError::ExpectedMap),
    };

    let mut operator: Option<[u8; 32]> = None;
    let mut alg_id: Option<u16> = None;
    let mut pk: Option<Vec<u8>> = None;
    let mut registered_at: Option<u64> = None;
    let mut seen_keys = std::collections::BTreeSet::<i128>::new();

    for (k, v) in map {
        let key = cbor_key_i128(k)?;
        if !seen_keys.insert(key) {
            return Err(ArchivalDecodeError::DuplicateKey(key));
        }
        match key {
            k if k == KEY_VAK_OPERATOR as i128 => {
                operator = Some(cbor_bytes_fixed(v, 32, k)?);
            }
            k if k == KEY_VAK_ALG_ID as i128 => alg_id = Some(cbor_u16(v)?),
            k if k == KEY_VAK_PK as i128 => pk = Some(cbor_bytes(v)?),
            k if k == KEY_VAK_REGISTERED_AT as i128 => registered_at = Some(cbor_u64(v)?),
            other => return Err(ArchivalDecodeError::UnknownKey(other)),
        }
    }

    Ok(ValidatorArchivalKey {
        operator: operator.ok_or(ArchivalDecodeError::MissingField(KEY_VAK_OPERATOR as i128))?,
        archival_alg_id: alg_id.ok_or(ArchivalDecodeError::MissingField(KEY_VAK_ALG_ID as i128))?,
        archival_pk: pk.ok_or(ArchivalDecodeError::MissingField(KEY_VAK_PK as i128))?,
        registered_at_height: registered_at.ok_or(ArchivalDecodeError::MissingField(
            KEY_VAK_REGISTERED_AT as i128,
        ))?,
    })
}

/// Encode a `ValidatorArchivalKey` to canonical CBOR bytes.
pub fn encode_validator_archival_key(k: &ValidatorArchivalKey) -> Vec<u8> {
    let mut buf = Vec::new();
    ciborium::into_writer(&validator_archival_key_to_cbor_value(k), &mut buf)
        .expect("CBOR encoding of ValidatorArchivalKey is infallible into Vec<u8>");
    buf
}

/// Decode a `ValidatorArchivalKey` from canonical CBOR bytes.
pub fn decode_validator_archival_key(
    bytes: &[u8],
) -> Result<ValidatorArchivalKey, ArchivalDecodeError> {
    let value: Value =
        ciborium::from_reader(bytes).map_err(|_| ArchivalDecodeError::CborMalformed)?;
    validator_archival_key_from_cbor_value(value)
}

// ── Encode / decode: ArchivalRecord ───────────────────────────────────────────

/// Field keys for `ArchivalRecord` CBOR map.
const KEY_AR_EPOCH_NUMBER: u64 = 1;
const KEY_AR_EPOCH_ROOT: u64 = 2;
const KEY_AR_SIGNER_ADDRESSES: u64 = 3;
const KEY_AR_SLH_SIGNATURES: u64 = 4;
const KEY_AR_TIMESTAMP_ANCHORS: u64 = 5;
const KEY_AR_EVIDENCE_RECORD_VERSION: u64 = 6;

/// Encode an `ArchivalRecord` to canonical CBOR bytes.
///
/// Determinism is guaranteed by:
/// - Fixed integer key order (ascending 1..=6).
/// - `ciborium`'s canonical output for integers / byte strings / arrays.
/// - Invariant that `signer_addresses` is already sorted lexicographically.
///
/// This function does NOT reject an unsorted `signer_addresses` — it simply
/// encodes what it was given. Sorting is a decode-side invariant per the
/// spec's "reject unsorted" rule; byte-identical output is still guaranteed
/// for any fixed input.
pub fn encode_archival_record(r: &ArchivalRecord) -> Vec<u8> {
    let signers = Value::Array(
        r.signer_addresses
            .iter()
            .map(|a| Value::Bytes(a.to_vec()))
            .collect(),
    );
    let sigs = Value::Array(
        r.slh_signatures
            .iter()
            .map(|s| Value::Bytes(s.clone()))
            .collect(),
    );
    let anchors = Value::Array(
        r.timestamp_anchors
            .iter()
            .map(timestamp_anchor_to_cbor_value)
            .collect(),
    );

    let map = Value::Map(vec![
        (
            Value::Integer(KEY_AR_EPOCH_NUMBER.into()),
            Value::Integer(r.epoch_number.into()),
        ),
        (
            Value::Integer(KEY_AR_EPOCH_ROOT.into()),
            Value::Bytes(r.epoch_root.to_vec()),
        ),
        (Value::Integer(KEY_AR_SIGNER_ADDRESSES.into()), signers),
        (Value::Integer(KEY_AR_SLH_SIGNATURES.into()), sigs),
        (Value::Integer(KEY_AR_TIMESTAMP_ANCHORS.into()), anchors),
        (
            Value::Integer(KEY_AR_EVIDENCE_RECORD_VERSION.into()),
            Value::Integer((r.evidence_record_version as u64).into()),
        ),
    ]);

    let mut buf = Vec::new();
    ciborium::into_writer(&map, &mut buf)
        .expect("CBOR encoding of ArchivalRecord is infallible into Vec<u8>");
    buf
}

/// Decode an `ArchivalRecord` from canonical CBOR bytes.
///
/// Enforces (SPEC-ARCHIVAL-001 §4.4):
/// - `epoch_root` is exactly 32 bytes;
/// - `signer_addresses.len() == slh_signatures.len()`;
/// - `signer_addresses` is sorted lexicographically ascending;
/// - each `TimestampAnchor.external_hash` is ≤ `TIMESTAMP_ANCHOR_EXTERNAL_HASH_MAX_LEN` bytes.
///
/// A `slh_signatures[i].len() != SLH_DSA_SHAKE_256S_SIG_LEN` is NOT a hard
/// error — the codec stays forward-compatible if governance later adds a
/// different SLH parameter set. Callers that need strict sizing should check
/// it themselves after decode.
pub fn decode_archival_record(bytes: &[u8]) -> Result<ArchivalRecord, ArchivalDecodeError> {
    let value: Value =
        ciborium::from_reader(bytes).map_err(|_| ArchivalDecodeError::CborMalformed)?;
    let map = match value {
        Value::Map(m) => m,
        _ => return Err(ArchivalDecodeError::ExpectedMap),
    };

    let mut epoch_number: Option<u64> = None;
    let mut epoch_root: Option<[u8; 32]> = None;
    let mut signer_addresses: Option<Vec<[u8; 32]>> = None;
    let mut slh_signatures: Option<Vec<Vec<u8>>> = None;
    let mut timestamp_anchors: Option<Vec<TimestampAnchor>> = None;
    let mut evidence_record_version: Option<u16> = None;
    let mut seen_keys = std::collections::BTreeSet::<i128>::new();

    for (k, v) in map {
        let key = cbor_key_i128(k)?;
        if !seen_keys.insert(key) {
            return Err(ArchivalDecodeError::DuplicateKey(key));
        }
        match key {
            k if k == KEY_AR_EPOCH_NUMBER as i128 => epoch_number = Some(cbor_u64(v)?),
            k if k == KEY_AR_EPOCH_ROOT as i128 => {
                epoch_root = Some(cbor_bytes_fixed(v, 32, k)?);
            }
            k if k == KEY_AR_SIGNER_ADDRESSES as i128 => {
                let arr = cbor_array(v)?;
                let mut addrs = Vec::with_capacity(arr.len());
                for item in arr {
                    addrs.push(cbor_bytes_fixed(item, 32, k)?);
                }
                signer_addresses = Some(addrs);
            }
            k if k == KEY_AR_SLH_SIGNATURES as i128 => {
                let arr = cbor_array(v)?;
                let mut sigs = Vec::with_capacity(arr.len());
                for item in arr {
                    sigs.push(cbor_bytes(item)?);
                }
                slh_signatures = Some(sigs);
            }
            k if k == KEY_AR_TIMESTAMP_ANCHORS as i128 => {
                let arr = cbor_array(v)?;
                let mut anchors = Vec::with_capacity(arr.len());
                for item in arr {
                    anchors.push(timestamp_anchor_from_cbor_value(item)?);
                }
                timestamp_anchors = Some(anchors);
            }
            k if k == KEY_AR_EVIDENCE_RECORD_VERSION as i128 => {
                evidence_record_version = Some(cbor_u16(v)?);
            }
            other => return Err(ArchivalDecodeError::UnknownKey(other)),
        }
    }

    let epoch_number = epoch_number.ok_or(ArchivalDecodeError::MissingField(
        KEY_AR_EPOCH_NUMBER as i128,
    ))?;
    let epoch_root =
        epoch_root.ok_or(ArchivalDecodeError::MissingField(KEY_AR_EPOCH_ROOT as i128))?;
    let signer_addresses = signer_addresses.ok_or(ArchivalDecodeError::MissingField(
        KEY_AR_SIGNER_ADDRESSES as i128,
    ))?;
    let slh_signatures = slh_signatures.ok_or(ArchivalDecodeError::MissingField(
        KEY_AR_SLH_SIGNATURES as i128,
    ))?;
    let timestamp_anchors = timestamp_anchors.ok_or(ArchivalDecodeError::MissingField(
        KEY_AR_TIMESTAMP_ANCHORS as i128,
    ))?;
    let evidence_record_version = evidence_record_version.ok_or(
        ArchivalDecodeError::MissingField(KEY_AR_EVIDENCE_RECORD_VERSION as i128),
    )?;

    // Invariant 1: signer / signature count must match.
    if signer_addresses.len() != slh_signatures.len() {
        return Err(ArchivalDecodeError::SignerSignatureCountMismatch {
            signers: signer_addresses.len(),
            sigs: slh_signatures.len(),
        });
    }

    // Invariant 2: signer_addresses sorted lexicographically ascending.
    // Strict-ascending check also rejects duplicates.
    for pair in signer_addresses.windows(2) {
        if pair[0] >= pair[1] {
            return Err(ArchivalDecodeError::SignersUnsorted);
        }
    }

    Ok(ArchivalRecord {
        epoch_number,
        epoch_root,
        signer_addresses,
        slh_signatures,
        timestamp_anchors,
        evidence_record_version,
    })
}

// ── CBOR helpers ──────────────────────────────────────────────────────────────

fn cbor_key_i128(v: Value) -> Result<i128, ArchivalDecodeError> {
    match v {
        Value::Integer(i) => Ok(i128::from(i)),
        _ => Err(ArchivalDecodeError::ExpectedInteger),
    }
}

fn cbor_u8(v: Value) -> Result<u8, ArchivalDecodeError> {
    let i = match v {
        Value::Integer(i) => i128::from(i),
        _ => return Err(ArchivalDecodeError::ExpectedInteger),
    };
    u8::try_from(i).map_err(|_| ArchivalDecodeError::IntegerOutOfRange)
}

fn cbor_u16(v: Value) -> Result<u16, ArchivalDecodeError> {
    let i = match v {
        Value::Integer(i) => i128::from(i),
        _ => return Err(ArchivalDecodeError::ExpectedInteger),
    };
    u16::try_from(i).map_err(|_| ArchivalDecodeError::IntegerOutOfRange)
}

fn cbor_u64(v: Value) -> Result<u64, ArchivalDecodeError> {
    let i = match v {
        Value::Integer(i) => i128::from(i),
        _ => return Err(ArchivalDecodeError::ExpectedInteger),
    };
    u64::try_from(i).map_err(|_| ArchivalDecodeError::IntegerOutOfRange)
}

fn cbor_bytes(v: Value) -> Result<Vec<u8>, ArchivalDecodeError> {
    match v {
        Value::Bytes(b) => Ok(b),
        _ => Err(ArchivalDecodeError::ExpectedBytes),
    }
}

fn cbor_bytes_fixed(
    v: Value,
    expected: usize,
    field_key: i128,
) -> Result<[u8; 32], ArchivalDecodeError> {
    // Currently all fixed-size byte fields in this module are 32 bytes, so we
    // hardcode the output shape. Kept generic-ish via the `expected` arg for
    // error-message clarity.
    debug_assert_eq!(
        expected, 32,
        "cbor_bytes_fixed only supports 32-byte outputs"
    );
    let bytes = cbor_bytes(v)?;
    if bytes.len() != expected {
        return Err(ArchivalDecodeError::InvalidByteLength {
            field: field_key,
            expected,
            actual: bytes.len(),
        });
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn cbor_text(v: Value) -> Result<String, ArchivalDecodeError> {
    match v {
        Value::Text(s) => Ok(s),
        _ => Err(ArchivalDecodeError::ExpectedText),
    }
}

fn cbor_array(v: Value) -> Result<Vec<Value>, ArchivalDecodeError> {
    match v {
        Value::Array(a) => Ok(a),
        _ => Err(ArchivalDecodeError::ExpectedArray),
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;

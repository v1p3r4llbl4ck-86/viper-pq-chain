// SPDX-License-Identifier: BUSL-1.1
//! Archival-overlay state transitions — SPEC-ARCHIVAL-001 §4.6–§4.7, ADR-045.
//!
//! Operations:
//! - `ValidatorRegisterArchivalKey`  — operator registers a per-validator
//!   SLH-DSA-SHAKE-256s archival public key. Rotation is by resubmission.
//! - `ArchivalRecordSubmit`          — post the SLH signature set for one
//!   closed epoch's `epoch_root`. First-writer-wins per `epoch_number`.
//! - `ArchivalRecordAddAnchor`       — any account attaches an RFC 3161 TST
//!   (or governance-added anchor kind) to an already-recorded epoch.
//! - `ArchivalRecordRenew`           — bumps `evidence_record_version` and
//!   records a fresh RFC 4998 ERS bundle for one or more epochs.
//!
//! Types (`ArchivalRecord`, `ValidatorArchivalKey`, `TimestampAnchor`,
//! `AnchorKind`) come from the `pqc-types::archival` module (TASK-160 / D1).

use crate::{error::ApplyError, store::StateStore};
use ciborium::value::Value;
use pqc_crypto::{
    sign::{PublicKey, Signature, SignatureVerifier},
    AlgId, TaggedHasher,
};
use pqc_types::{
    account::Address,
    archival::{
        AnchorKind, ArchivalRecord, TimestampAnchor, TsaRef, ValidatorArchivalKey,
        SLH_DSA_SHAKE_256S_PK_LEN, TIMESTAMP_ANCHOR_EXTERNAL_HASH_MAX_LEN,
    },
    transaction::Transaction,
    validator::ValidatorStatus,
};

// ── Spec constants (SPEC-ARCHIVAL-001 §4.5 / §4.6) ───────────────────────────

/// SLH-DSA-SHAKE-256s public key size in bytes (FIPS 205 Cat 5).
///
/// Re-exported from `pqc_types::archival` so the rest of pqc-state can
/// refer to a single name (and so this file keeps its naming symmetry with
/// the pre-D1 stub module). Value is 64 bytes.
pub const ARCHIVAL_PK_SIZE: usize = SLH_DSA_SHAKE_256S_PK_LEN;

/// Per-anchor sanity cap for `external_hash` / `tst_bytes` — mirrors
/// D1's `TIMESTAMP_ANCHOR_EXTERNAL_HASH_MAX_LEN`.
pub const ARCHIVAL_ANCHOR_MAX_LEN: usize = TIMESTAMP_ANCHOR_EXTERNAL_HASH_MAX_LEN;

/// Domain separator for the SLH-DSA-SHAKE-256s signature preimage —
/// SPEC-ARCHIVAL-001 §4.5.
pub const ARCHIVAL_SIG_DOMAIN: &[u8] = b"VIPER-ARCHIVAL-SIG-V1";

// ── CBOR payload helpers ─────────────────────────────────────────────────────

fn decode_cbor_map(payload: &[u8]) -> Result<Vec<(Value, Value)>, ApplyError> {
    let value: Value = ciborium::de::from_reader(payload)
        .map_err(|e| ApplyError::PayloadDecode(format!("CBOR decode failed: {e}")))?;
    match value {
        Value::Map(m) => Ok(m),
        _ => Err(ApplyError::PayloadDecode("expected CBOR map".into())),
    }
}

fn cbor_integer_key_eq(k: &Value, n: i64) -> bool {
    matches!(k, Value::Integer(i) if *i == n.into())
}

fn cbor_u64(v: &Value, field: &str) -> Result<u64, ApplyError> {
    match v {
        Value::Integer(n) => {
            let n: i128 = (*n).into();
            u64::try_from(n)
                .map_err(|_| ApplyError::PayloadDecode(format!("{field} must be unsigned u64")))
        }
        _ => Err(ApplyError::PayloadDecode(format!(
            "{field} must be integer"
        ))),
    }
}

fn cbor_bytes<'a>(v: &'a Value, field: &str) -> Result<&'a [u8], ApplyError> {
    match v {
        Value::Bytes(b) => Ok(b.as_slice()),
        _ => Err(ApplyError::PayloadDecode(format!("{field} must be bytes"))),
    }
}

/// `ValidatorRegisterArchivalKey` payload — two CBOR fields:
/// - 1: archival_alg_id (u16)
/// - 2: archival_pk (bstr)
pub(crate) struct RegisterArchivalKeyPayload {
    pub archival_alg_id: u16,
    pub archival_pk: Vec<u8>,
}

fn decode_register_archival_key_payload(
    payload: &[u8],
) -> Result<RegisterArchivalKeyPayload, ApplyError> {
    let map = decode_cbor_map(payload)?;
    let mut alg_id: Option<u16> = None;
    let mut pk: Option<Vec<u8>> = None;
    for (k, v) in map {
        if cbor_integer_key_eq(&k, 1) {
            let n = cbor_u64(&v, "archival_alg_id")?;
            alg_id = Some(
                u16::try_from(n)
                    .map_err(|_| ApplyError::PayloadDecode("archival_alg_id overflow".into()))?,
            );
        } else if cbor_integer_key_eq(&k, 2) {
            pk = Some(cbor_bytes(&v, "archival_pk")?.to_vec());
        }
    }
    Ok(RegisterArchivalKeyPayload {
        archival_alg_id: alg_id
            .ok_or_else(|| ApplyError::PayloadDecode("missing field 1 (archival_alg_id)".into()))?,
        archival_pk: pk
            .ok_or_else(|| ApplyError::PayloadDecode("missing field 2 (archival_pk)".into()))?,
    })
}

/// `ArchivalRecordSubmit` payload — SPEC-ARCHIVAL-001 §4.4.
/// - 1: epoch_number (u64)
/// - 2: first_height (u64)
/// - 3: last_height (u64)
/// - 4: epoch_root (bstr, 32 B)
/// - 5: slh_sig_set (array of [addr (bstr 32), sig (bstr)])
pub(crate) struct ArchivalRecordSubmitPayload {
    pub epoch_number: u64,
    #[allow(dead_code)]
    pub first_height: u64,
    #[allow(dead_code)]
    pub last_height: u64,
    pub epoch_root: [u8; 32],
    pub slh_sig_set: Vec<(Address, Vec<u8>)>,
}

fn decode_archival_record_submit_payload(
    payload: &[u8],
) -> Result<ArchivalRecordSubmitPayload, ApplyError> {
    let map = decode_cbor_map(payload)?;
    let mut epoch_number: Option<u64> = None;
    let mut first_height: Option<u64> = None;
    let mut last_height: Option<u64> = None;
    let mut epoch_root: Option<[u8; 32]> = None;
    let mut slh_sig_set: Option<Vec<(Address, Vec<u8>)>> = None;
    for (k, v) in map {
        if cbor_integer_key_eq(&k, 1) {
            epoch_number = Some(cbor_u64(&v, "epoch_number")?);
        } else if cbor_integer_key_eq(&k, 2) {
            first_height = Some(cbor_u64(&v, "first_height")?);
        } else if cbor_integer_key_eq(&k, 3) {
            last_height = Some(cbor_u64(&v, "last_height")?);
        } else if cbor_integer_key_eq(&k, 4) {
            let b = cbor_bytes(&v, "epoch_root")?;
            if b.len() != 32 {
                return Err(ApplyError::PayloadDecode(
                    "epoch_root must be 32 bytes".into(),
                ));
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(b);
            epoch_root = Some(arr);
        } else if cbor_integer_key_eq(&k, 5) {
            let arr = match v {
                Value::Array(a) => a,
                _ => {
                    return Err(ApplyError::PayloadDecode(
                        "slh_sig_set must be array".into(),
                    ))
                }
            };
            let mut out: Vec<(Address, Vec<u8>)> = Vec::with_capacity(arr.len());
            for item in arr {
                let pair = match item {
                    Value::Array(p) => p,
                    _ => {
                        return Err(ApplyError::PayloadDecode(
                            "slh_sig_set entries must be arrays".into(),
                        ))
                    }
                };
                if pair.len() != 2 {
                    return Err(ApplyError::PayloadDecode(
                        "slh_sig_set entry must have 2 elements".into(),
                    ));
                }
                let addr_bytes = cbor_bytes(&pair[0], "slh_sig_set[].addr")?;
                if addr_bytes.len() != 32 {
                    return Err(ApplyError::PayloadDecode(
                        "slh_sig_set addr must be 32 bytes".into(),
                    ));
                }
                let mut arr32 = [0u8; 32];
                arr32.copy_from_slice(addr_bytes);
                let sig_bytes = cbor_bytes(&pair[1], "slh_sig_set[].sig")?.to_vec();
                out.push((Address(arr32), sig_bytes));
            }
            slh_sig_set = Some(out);
        }
    }
    Ok(ArchivalRecordSubmitPayload {
        epoch_number: epoch_number
            .ok_or_else(|| ApplyError::PayloadDecode("missing field 1 (epoch_number)".into()))?,
        first_height: first_height
            .ok_or_else(|| ApplyError::PayloadDecode("missing field 2 (first_height)".into()))?,
        last_height: last_height
            .ok_or_else(|| ApplyError::PayloadDecode("missing field 3 (last_height)".into()))?,
        epoch_root: epoch_root
            .ok_or_else(|| ApplyError::PayloadDecode("missing field 4 (epoch_root)".into()))?,
        slh_sig_set: slh_sig_set
            .ok_or_else(|| ApplyError::PayloadDecode("missing field 5 (slh_sig_set)".into()))?,
    })
}

/// `ArchivalRecordAddAnchor` payload — SPEC-ARCHIVAL-001 §4.4 / §6.
/// - 1: epoch_number (u64)
/// - 2: anchor_kind (u8)
/// - 3: tst_bytes (bstr, ≤ 16 KiB)
/// - 4: external_hash (bstr, ≤ 16 KiB)
/// - 5: created_at (u64, unix seconds; 0 if unknown)
pub(crate) struct ArchivalRecordAddAnchorPayload {
    pub epoch_number: u64,
    pub anchor_kind: u8,
    #[allow(dead_code)]
    pub tst_bytes: Vec<u8>,
    pub external_hash: Vec<u8>,
    #[allow(dead_code)]
    pub created_at: u64,
}

fn decode_archival_record_add_anchor_payload(
    payload: &[u8],
) -> Result<ArchivalRecordAddAnchorPayload, ApplyError> {
    let map = decode_cbor_map(payload)?;
    let mut epoch_number: Option<u64> = None;
    let mut anchor_kind: Option<u8> = None;
    let mut tst_bytes: Option<Vec<u8>> = None;
    let mut external_hash: Option<Vec<u8>> = None;
    let mut created_at: Option<u64> = None;
    for (k, v) in map {
        if cbor_integer_key_eq(&k, 1) {
            epoch_number = Some(cbor_u64(&v, "epoch_number")?);
        } else if cbor_integer_key_eq(&k, 2) {
            let n = cbor_u64(&v, "anchor_kind")?;
            anchor_kind = Some(
                u8::try_from(n)
                    .map_err(|_| ApplyError::PayloadDecode("anchor_kind overflow".into()))?,
            );
        } else if cbor_integer_key_eq(&k, 3) {
            tst_bytes = Some(cbor_bytes(&v, "tst_bytes")?.to_vec());
        } else if cbor_integer_key_eq(&k, 4) {
            external_hash = Some(cbor_bytes(&v, "external_hash")?.to_vec());
        } else if cbor_integer_key_eq(&k, 5) {
            created_at = Some(cbor_u64(&v, "created_at")?);
        }
    }
    Ok(ArchivalRecordAddAnchorPayload {
        epoch_number: epoch_number
            .ok_or_else(|| ApplyError::PayloadDecode("missing field 1 (epoch_number)".into()))?,
        anchor_kind: anchor_kind
            .ok_or_else(|| ApplyError::PayloadDecode("missing field 2 (anchor_kind)".into()))?,
        tst_bytes: tst_bytes
            .ok_or_else(|| ApplyError::PayloadDecode("missing field 3 (tst_bytes)".into()))?,
        external_hash: external_hash
            .ok_or_else(|| ApplyError::PayloadDecode("missing field 4 (external_hash)".into()))?,
        created_at: created_at.unwrap_or(0),
    })
}

/// `ArchivalRecordRenew` payload — SPEC-ARCHIVAL-001 §8.3.
/// - 1: epoch_number (u64)
/// - 2: ers_bundle_hash (bstr, 32 B) — the submitter's SHAKE-256 over the new
///   RFC 4998 ArchiveTimeStampChain (recorded on-chain; verification is
///   offline at proof-assembly time, per SPEC §7.5).
pub(crate) struct ArchivalRecordRenewPayload {
    pub epoch_number: u64,
    pub ers_bundle_hash: [u8; 32],
}

fn decode_archival_record_renew_payload(
    payload: &[u8],
) -> Result<ArchivalRecordRenewPayload, ApplyError> {
    let map = decode_cbor_map(payload)?;
    let mut epoch_number: Option<u64> = None;
    let mut ers_bundle_hash: Option<[u8; 32]> = None;
    for (k, v) in map {
        if cbor_integer_key_eq(&k, 1) {
            epoch_number = Some(cbor_u64(&v, "epoch_number")?);
        } else if cbor_integer_key_eq(&k, 2) {
            let b = cbor_bytes(&v, "ers_bundle_hash")?;
            if b.len() != 32 {
                return Err(ApplyError::PayloadDecode(
                    "ers_bundle_hash must be 32 bytes".into(),
                ));
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(b);
            ers_bundle_hash = Some(arr);
        }
    }
    Ok(ArchivalRecordRenewPayload {
        epoch_number: epoch_number
            .ok_or_else(|| ApplyError::PayloadDecode("missing field 1 (epoch_number)".into()))?,
        ers_bundle_hash: ers_bundle_hash
            .ok_or_else(|| ApplyError::PayloadDecode("missing field 2 (ers_bundle_hash)".into()))?,
    })
}

// ── CBOR payload encoders (helpers for tests & sidecars) ─────────────────────

/// Encode a `ValidatorRegisterArchivalKey` payload as deterministic CBOR.
pub fn encode_register_archival_key_payload(archival_alg_id: u16, archival_pk: &[u8]) -> Vec<u8> {
    let map = Value::Map(vec![
        (
            Value::Integer(1i64.into()),
            Value::Integer((archival_alg_id as i64).into()),
        ),
        (
            Value::Integer(2i64.into()),
            Value::Bytes(archival_pk.to_vec()),
        ),
    ]);
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&map, &mut buf).expect("CBOR encode is infallible");
    buf
}

/// Encode an `ArchivalRecordSubmit` payload as deterministic CBOR.
pub fn encode_archival_record_submit_payload(
    epoch_number: u64,
    first_height: u64,
    last_height: u64,
    epoch_root: &[u8; 32],
    slh_sig_set: &[(Address, Vec<u8>)],
) -> Vec<u8> {
    let entries: Vec<Value> = slh_sig_set
        .iter()
        .map(|(addr, sig)| {
            Value::Array(vec![
                Value::Bytes(addr.0.to_vec()),
                Value::Bytes(sig.clone()),
            ])
        })
        .collect();
    let map = Value::Map(vec![
        (
            Value::Integer(1i64.into()),
            Value::Integer(epoch_number.into()),
        ),
        (
            Value::Integer(2i64.into()),
            Value::Integer(first_height.into()),
        ),
        (
            Value::Integer(3i64.into()),
            Value::Integer(last_height.into()),
        ),
        (
            Value::Integer(4i64.into()),
            Value::Bytes(epoch_root.to_vec()),
        ),
        (Value::Integer(5i64.into()), Value::Array(entries)),
    ]);
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&map, &mut buf).expect("CBOR encode is infallible");
    buf
}

/// Encode an `ArchivalRecordAddAnchor` payload as deterministic CBOR.
pub fn encode_archival_record_add_anchor_payload(
    epoch_number: u64,
    anchor_kind: u8,
    tst_bytes: &[u8],
    external_hash: &[u8],
    created_at: u64,
) -> Vec<u8> {
    let map = Value::Map(vec![
        (
            Value::Integer(1i64.into()),
            Value::Integer(epoch_number.into()),
        ),
        (
            Value::Integer(2i64.into()),
            Value::Integer((anchor_kind as i64).into()),
        ),
        (
            Value::Integer(3i64.into()),
            Value::Bytes(tst_bytes.to_vec()),
        ),
        (
            Value::Integer(4i64.into()),
            Value::Bytes(external_hash.to_vec()),
        ),
        (
            Value::Integer(5i64.into()),
            Value::Integer(created_at.into()),
        ),
    ]);
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&map, &mut buf).expect("CBOR encode is infallible");
    buf
}

/// Encode an `ArchivalRecordRenew` payload as deterministic CBOR.
pub fn encode_archival_record_renew_payload(
    epoch_number: u64,
    ers_bundle_hash: &[u8; 32],
) -> Vec<u8> {
    let map = Value::Map(vec![
        (
            Value::Integer(1i64.into()),
            Value::Integer(epoch_number.into()),
        ),
        (
            Value::Integer(2i64.into()),
            Value::Bytes(ers_bundle_hash.to_vec()),
        ),
    ]);
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&map, &mut buf).expect("CBOR encode is infallible");
    buf
}

// ── SLH-DSA signature preimage (SPEC-ARCHIVAL-001 §4.5) ──────────────────────

/// Build the §4.5 signature preimage consumed by every archival signer.
///
/// Public so the M4.4 submission path in `pqcd` can sign the same bytes the
/// apply path verifies, without re-encoding the formula.
///
/// Per ADR-053 §T1.2 the 4-byte `fork_digest` prefix scopes every archival
/// signature to a specific `(fork_version, genesis_validators_root)` pair so
/// a signed epoch-commitment on one chain cannot be replayed on any
/// parallel/future chain that shares the `VIPER-ARCHIVAL-SIG-V1` tag. The
/// BIP340 double-tagged outer hash (ADR-053 §T2.4) additionally defends
/// against domain-tag collisions.
///
/// The returned `Vec<u8>` is the 32-byte tagged-hash digest the signer
/// operates over.
pub fn archival_sig_preimage(
    fork_digest: &pqc_types::ForkDigest,
    epoch_number: u64,
    epoch_root: &[u8; 32],
) -> Vec<u8> {
    let mut body = Vec::with_capacity(4 + 8 + 32);
    body.extend_from_slice(fork_digest.as_bytes());
    body.extend_from_slice(&epoch_number.to_be_bytes());
    body.extend_from_slice(epoch_root);
    pqc_crypto::tagged_hash(ARCHIVAL_SIG_DOMAIN, &body).to_vec()
}

// ── Epoch helper (loose coupling — engine owns the real schedule) ────────────
//
// pqc-state cannot take a dep on pqc-consensus (that's where `EpochInfo`
// lives). Instead we compute epoch numbers locally using the devnet-default
// `VALIDATOR_EPOCH_DURATION_DEVNET` from `pqc-types::validator`. The spec
// allows governance to mutate the epoch length; once M4.4 wires the engine's
// real schedule through, this helper moves to a `StateStore` accessor that
// reads `state.epoch_duration_blocks`.

fn current_epoch_number(current_block_height: u64) -> u64 {
    use pqc_types::validator::VALIDATOR_EPOCH_DURATION_DEVNET;
    if VALIDATOR_EPOCH_DURATION_DEVNET == 0 {
        return 0;
    }
    current_block_height / VALIDATOR_EPOCH_DURATION_DEVNET
}

// ── Apply: ValidatorRegisterArchivalKey ───────────────────────────────────────

/// Apply a `ValidatorRegisterArchivalKey` transaction — SPEC-ARCHIVAL-001 §4.5.
///
/// Preconditions:
/// - Sender must be an Active or Candidate validator.
/// - Algorithm must be SLH-DSA-SHAKE-256s (the current-generation archival alg).
/// - `archival_pk` length must equal `ARCHIVAL_PK_SIZE` (64 B).
///
/// Rotation: resubmission by the same operator replaces the existing key
/// (the spec permits key rotation without a dedicated rotation tx).
///
/// # AlgId note
///
/// The spec §4.5 and D1's `ARCHIVAL_ALG_ID_SLH_DSA_SHAKE_256S` constant both
/// name `0x0023`, but the on-chain `AlgId` enum has
/// `SlhDsaShake256s = 0x0022` (earlier renumbering; see TASK-162 note). This
/// admission keys on the `AlgId::SlhDsaShake256s` variant so it is correct
/// regardless of the documented hex — the spec erratum is tracked separately.
pub fn apply_validator_register_archival_key(
    store: &mut StateStore,
    tx: &Transaction,
) -> Result<(), ApplyError> {
    let payload = decode_register_archival_key_payload(&tx.payload)?;

    // Algorithm admissibility — only SLH-DSA-SHAKE-256s is allowed.
    let alg =
        AlgId::from_u16(payload.archival_alg_id).ok_or(ApplyError::ArchivalAlgorithmNotAllowed)?;
    if !matches!(alg, AlgId::SlhDsaShake256s) {
        return Err(ApplyError::ArchivalAlgorithmNotAllowed);
    }

    if payload.archival_pk.len() != ARCHIVAL_PK_SIZE {
        return Err(ApplyError::ArchivalInvalidPkSize);
    }

    // Sender must be Active or Candidate validator (SPEC §4.2 invariant is
    // "Active"; we also admit Candidates so validators can pre-register before
    // their first epoch-boundary activation).
    let status = store
        .get_validator(&tx.sender)
        .map(|r| r.status.clone())
        .ok_or(ApplyError::ArchivalValidatorNotEligible)?;
    match status {
        ValidatorStatus::Active | ValidatorStatus::Candidate => {}
        _ => return Err(ApplyError::ArchivalValidatorNotEligible),
    }

    let key = ValidatorArchivalKey {
        operator: tx.sender.0,
        archival_alg_id: payload.archival_alg_id,
        archival_pk: payload.archival_pk,
        registered_at_height: store.block_height(),
    };
    store.insert_archival_key(key);

    Ok(())
}

// ── Apply: ArchivalRecordSubmit ───────────────────────────────────────────────

/// Apply an `ArchivalRecordSubmit` transaction — SPEC-ARCHIVAL-001 §4.6.
///
/// This is the single expensive path (up to 24 SLH-DSA-SHAKE-256s verifies,
/// ~5 ms on release builds). Admissibility checks are ordered to reject
/// before touching the verifier whenever possible.
pub fn apply_archival_record_submit<V: SignatureVerifier>(
    store: &mut StateStore,
    tx: &Transaction,
    current_block_height: u64,
    verifier: &V,
) -> Result<(), ApplyError> {
    let payload = decode_archival_record_submit_payload(&tx.payload)?;

    // ── Cheap check 1: epoch must be in the past (or the currently-closing one). ──
    let current_epoch = current_epoch_number(current_block_height);
    if payload.epoch_number > current_epoch {
        return Err(ApplyError::ArchivalEpochInFuture);
    }

    // ── Cheap check 2: idempotency — first record for this epoch wins. ──
    if store.get_archival_record(payload.epoch_number).is_some() {
        return Err(ApplyError::DuplicateArchivalRecord);
    }

    // ── Cheap check 3: threshold on the signer COUNT, before any SLH verify. ──
    //
    // SLH-DSA-SHAKE-256s verify is ~200 µs on release; with a full 24-validator
    // signer set that's ~5 ms per tx. Rejecting below-threshold submissions
    // before any verify is the difference between "tolerable" and "a DoS
    // vector". The count check is signer-unique (duplicate signer addresses
    // are collapsed here — the wire format permits dup-sender but they yield
    // one voting weight).
    let (m, _n) = store.archival_threshold();
    let unique_signers: std::collections::BTreeSet<[u8; 32]> =
        payload.slh_sig_set.iter().map(|(a, _)| a.0).collect();
    if (unique_signers.len() as u32) < u32::from(m) {
        return Err(ApplyError::ArchivalThresholdNotMet);
    }

    // ── Cheap check 4: every signer must be in the archival_signer_set. ──
    //
    // The spec computes the signer-set membership at h_boundary; we use the
    // live set at apply-time in the M4.2 slice (the signer-set is currently
    // seeded at genesis with all Active validators and is governance-mutated
    // only via a path not yet wired — so apply-time matches h_boundary-time
    // for all flows in M4.2).
    for (addr, _) in &payload.slh_sig_set {
        if !store.is_archival_signer(addr) {
            return Err(ApplyError::ArchivalSignerNotAuthorized);
        }
    }

    // ── Expensive check: SLH-DSA-SHAKE-256s verify each signature. ──
    //
    // Each signer's pk is the on-chain `archival_keys[addr]`. A signer
    // without a registered archival key fails admission at `ArchivalMissingKey`
    // — production devnet-2 nodes call `ValidatorRegisterArchivalKey` before
    // they can sign an epoch (see M4.4 for the sidecar cron path).
    let fork_digest = pqc_types::ForkDigest::viper_research_1();
    let preimage = archival_sig_preimage(&fork_digest, payload.epoch_number, &payload.epoch_root);
    let mut verified: u32 = 0;
    for (addr, sig_bytes) in &payload.slh_sig_set {
        let key = store
            .get_archival_key(addr)
            .ok_or(ApplyError::ArchivalMissingKey)?;
        let alg =
            AlgId::from_u16(key.archival_alg_id).ok_or(ApplyError::ArchivalAlgorithmNotAllowed)?;
        let pk = PublicKey {
            alg_id: alg,
            bytes: key.archival_pk.clone(),
        };
        let sig = Signature {
            alg_id: alg,
            bytes: sig_bytes.clone(),
        };
        verifier
            .verify(&pk, &preimage, &sig)
            .map_err(|_| ApplyError::ArchivalSignatureInvalid)?;
        verified = verified.saturating_add(1);
    }
    if verified < u32::from(m) {
        return Err(ApplyError::ArchivalThresholdNotMet);
    }

    // ── All checks passed — apply state mutation. ──
    //
    // Sort the signature set by address bytes (SPEC-ARCHIVAL-001 §4.4) so the
    // stored record is byte-stable regardless of submission order. D1's
    // `ArchivalRecord` uses parallel `signer_addresses` + `slh_signatures`
    // vecs rather than a `Vec<(Address, Sig)>`; we split after sorting.
    let mut sig_set = payload.slh_sig_set;
    sig_set.sort_by(|a, b| a.0 .0.cmp(&b.0 .0));
    sig_set.dedup_by(|a, b| a.0 .0 == b.0 .0);
    let signer_addresses: Vec<[u8; 32]> = sig_set.iter().map(|(a, _)| a.0).collect();
    let slh_signatures: Vec<Vec<u8>> = sig_set.into_iter().map(|(_, s)| s).collect();

    let record = ArchivalRecord {
        epoch_number: payload.epoch_number,
        epoch_root: payload.epoch_root,
        signer_addresses,
        slh_signatures,
        timestamp_anchors: Vec::new(),
        evidence_record_version: 0,
    };
    store.insert_archival_record(record);
    Ok(())
}

// ── Apply: ArchivalRecordAddAnchor ────────────────────────────────────────────

/// Apply an `ArchivalRecordAddAnchor` transaction — SPEC-ARCHIVAL-001 §4.6 / §6.
///
/// Any account MAY submit anchor attachments (the sidecar uses a dedicated
/// funded account; see M4.5). The record must already exist.
///
/// # Mapping to D1's `TimestampAnchor`
///
/// D1's anchor struct has (kind, tsa_ref, external_hash, posted_at_height).
/// Our wire payload carries (anchor_kind, tst_bytes, external_hash,
/// created_at) — the `tst_bytes` and `created_at` fields do not have homes
/// in D1's struct; we encode the TST DER into `external_hash` via the
/// submitter's SHAKE-256 (per SPEC §6.1 the chain doesn't verify the TST
/// cryptographically on apply) and drop the optional `created_at` wire
/// hint. The `tsa_ref` is left empty (`None`) — the apply path in M4.2
/// doesn't parse the DER; M4.5 (sidecar) will populate it when it lands.
pub fn apply_archival_record_add_anchor(
    store: &mut StateStore,
    tx: &Transaction,
    current_block_height: u64,
) -> Result<(), ApplyError> {
    let payload = decode_archival_record_add_anchor_payload(&tx.payload)?;

    let kind =
        AnchorKind::from_u8(payload.anchor_kind).ok_or(ApplyError::ArchivalUnknownAnchorKind)?;

    if payload.external_hash.len() > ARCHIVAL_ANCHOR_MAX_LEN
        || payload.tst_bytes.len() > ARCHIVAL_ANCHOR_MAX_LEN
    {
        return Err(ApplyError::ArchivalAnchorTooLarge);
    }

    if store.get_archival_record(payload.epoch_number).is_none() {
        return Err(ApplyError::ArchivalRecordNotFound);
    }

    let anchor = TimestampAnchor {
        kind,
        tsa_ref: None,
        external_hash: payload.external_hash,
        posted_at_height: current_block_height,
    };
    store.push_archival_anchor(payload.epoch_number, anchor);
    Ok(())
}

// ── Apply: ArchivalRecordRenew ────────────────────────────────────────────────

/// Apply an `ArchivalRecordRenew` transaction — SPEC-ARCHIVAL-001 §8.3.
///
/// Sender must be an Active validator OR a governance-registered
/// `archival_renewer`. On apply, `evidence_record_version` is incremented by
/// one and the submitter-computed ERS bundle hash is folded into the state
/// root (via the record's own leaf-hash recompute inside
/// `increment_archival_record_version`).
pub fn apply_archival_record_renew(
    store: &mut StateStore,
    tx: &Transaction,
    current_block_height: u64,
) -> Result<(), ApplyError> {
    let payload = decode_archival_record_renew_payload(&tx.payload)?;

    // Sender must be Active validator or an archival_renewer.
    let is_active_validator = store
        .get_validator(&tx.sender)
        .map(|r| r.status == ValidatorStatus::Active)
        .unwrap_or(false);
    let is_renewer = store.is_archival_renewer(&tx.sender);
    if !is_active_validator && !is_renewer {
        return Err(ApplyError::ArchivalNotRenewer);
    }

    if store.get_archival_record(payload.epoch_number).is_none() {
        return Err(ApplyError::ArchivalRecordNotFound);
    }

    store.increment_archival_record_version(
        payload.epoch_number,
        payload.ers_bundle_hash,
        current_block_height,
    );
    Ok(())
}

// ── Leaf-hash helpers (mirrored in store.rs) ──────────────────────────────────
//
// Exposed at module scope so the tests can assert leaf-hash byte-stability
// under known fixtures. These are the ground-truth for the state-root
// folding in `StateStore::state_root()`.

pub(crate) fn compute_archival_record_leaf_hash(record: &ArchivalRecord) -> [u8; 32] {
    let mut d = TaggedHasher::new(b"VIPER-ARCHIVAL-RECORDS-V1");
    d.push_chunk(&record.epoch_number.to_be_bytes());
    d.push_chunk(&record.epoch_root);
    d.push_u64(record.signer_addresses.len() as u64);
    for addr in &record.signer_addresses {
        d.push_chunk(addr);
    }
    d.push_u64(record.slh_signatures.len() as u64);
    for sig in &record.slh_signatures {
        d.push_u64(sig.len() as u64);
        d.push_chunk(sig);
    }
    d.push_u64(record.timestamp_anchors.len() as u64);
    for a in &record.timestamp_anchors {
        d.push_chunk(&[a.kind.as_u8()]);
        push_tsa_ref(&mut d, a.tsa_ref.as_ref());
        d.push_u64(a.external_hash.len() as u64);
        d.push_chunk(&a.external_hash);
        d.push_chunk(&a.posted_at_height.to_be_bytes());
    }
    d.push_chunk(&(record.evidence_record_version as u64).to_be_bytes());
    d.finish()
}

fn push_tsa_ref(d: &mut TaggedHasher, tsa_ref: Option<&TsaRef>) {
    match tsa_ref {
        Some(r) => {
            d.push_chunk(&[1u8]);
            d.push_u64(r.url.len() as u64);
            d.push_chunk(r.url.as_bytes());
            d.push_chunk(&r.cert_fingerprint_sha256);
            match &r.policy_oid {
                Some(oid) => {
                    d.push_chunk(&[1u8]);
                    d.push_u64(oid.len() as u64);
                    d.push_chunk(oid.as_bytes());
                }
                None => d.push_chunk(&[0u8]),
            }
        }
        None => d.push_chunk(&[0u8]),
    }
}

pub(crate) fn compute_archival_key_leaf_hash(key: &ValidatorArchivalKey) -> [u8; 32] {
    let mut d = TaggedHasher::new(b"VIPER-ARCHIVAL-KEYS-V1");
    d.push_chunk(&key.operator);
    d.push_chunk(&key.archival_alg_id.to_be_bytes());
    d.push_u64(key.archival_pk.len() as u64);
    d.push_chunk(&key.archival_pk);
    d.push_chunk(&key.registered_at_height.to_be_bytes());
    d.finish()
}

// SPDX-License-Identifier: BUSL-1.1
//! Tests for `cold_storage`.
//!
//! Extracted from `cold_storage.rs` 2026-05-10. `use super::*;`
//! brings every private item from the parent module into scope.

use super::*;
use pqc_consensus::{AssemblyConfig, LocalProposer, LocalProposerConfig, RocksDbChainStore};
use pqc_crypto::{sign::StubVerifier, slh_dsa_shake_256s_generate, AlgId};
use pqc_mempool::{admission::try_admit, Mempool};
use pqc_state::StateStore;
use pqc_tx::{codec::encode_tx, validate::FeeParams};
use pqc_types::{
    account::{Account, Address},
    keyset::{allowed_tx, KeyEntry, KeySet, KeyStatus},
    transaction::{MsgType, Transaction},
};
use std::time::UNIX_EPOCH;

use crate::keystore::{Keystore, KeystoreEntry};

struct TempDir(std::path::PathBuf);
impl TempDir {
    fn new(label: &str) -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("pqcd-cold-{label}-{}-{nanos}", std::process::id()));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn signer_account(addr: Address, balance: u128) -> Account {
    Account {
        address: addr,
        balance,
        nonce: 0,
        keys: KeySet(vec![KeyEntry {
            alg_id: AlgId::MlDsa65,
            pk_bytes: vec![0u8; 32].into(),
            key_version: 1,
            valid_from_height: 0,
            status: KeyStatus::Active,
            allowed_tx_types: allowed_tx::ALL,
        }]),
        policy_version: 0,
        policy_hash: None,
        verifier_template_id: pqc_types::account::VERIFIER_TEMPLATE_ID_EOA,
        auth_data: Vec::new(),
    }
}

fn transfer_tx(sender: Address, recipient: Address, nonce: u64) -> Transaction {
    let mut payload = Vec::new();
    ciborium::into_writer(
        &ciborium::value::Value::Map(vec![
            (
                ciborium::value::Value::Integer(1u64.into()),
                ciborium::value::Value::Bytes(recipient.0.to_vec()),
            ),
            (
                ciborium::value::Value::Integer(2u64.into()),
                ciborium::value::Value::Integer(100u64.into()),
            ),
        ]),
        &mut payload,
    )
    .unwrap();
    Transaction {
        tx_version: 1,
        chain_id: Vec::new(),
        msg_type: MsgType::TokenTransfer,
        sender,
        nonce,
        fee: 100,
        fee_tip: 0,
        gas_limit: 100_000,
        payload,
        sig_alg_id: AlgId::MlDsa65,
        sig_key_version: 1,
        signature: vec![0xAB; 3_309],
    }
}

fn build_chain(dir: &TempDir, n: u64) -> RocksDbChainStore {
    let mut store = RocksDbChainStore::open_no_wal(&dir.0, BlockHash([0x11; 32])).expect("open ok");
    let sender = Address([0xA1; 32]);
    let recipient = Address([0x22; 32]);
    let mut state = StateStore::new();
    state.insert_account(signer_account(sender.clone(), 100_000_000));
    let mut pool = Mempool::new();
    let mut proposer = LocalProposer::new(
        [0x99; 32],
        LocalProposerConfig {
            assembly: AssemblyConfig::default(),
            initial_prev_hash: BlockHash([0x11; 32]),
        },
    );
    let base_ts: u64 = 1_710_000_000;
    for h in 1..=n {
        let tx = transfer_tx(sender.clone(), recipient.clone(), h - 1);
        let raw = encode_tx(&tx).unwrap();
        try_admit(&mut pool, raw, &state, &StubVerifier, &FeeParams::default()).unwrap();
        let result = proposer
            .run_once(
                &mut state,
                &mut pool,
                base_ts.saturating_add(h * 1_000_000_000),
            )
            .expect("run_once ok");
        store.append_block_trusted(&result).expect("append ok");
    }
    store
}

#[test]
fn export_zero_cutoff_is_rejected() {
    let dir = TempDir::new("zero");
    let store = build_chain(&dir, 3);
    let out = TempDir::new("zero-out");
    let err = export_cold_storage(
        &store,
        "deadbeef".into(),
        0,
        100,
        &out.0,
        None,
        &ExportOptions::default(),
    )
    .unwrap_err();
    assert!(format!("{err}").contains("cutoff > 0"));
}

#[test]
fn export_cutoff_above_tip_is_rejected() {
    let dir = TempDir::new("above");
    let store = build_chain(&dir, 3);
    let out = TempDir::new("above-out");
    let err = export_cold_storage(
        &store,
        "deadbeef".into(),
        99,
        100,
        &out.0,
        None,
        &ExportOptions::default(),
    )
    .unwrap_err();
    assert!(format!("{err}").contains("exceeds current tip"));
}

#[test]
fn export_zero_batch_size_is_rejected() {
    let dir = TempDir::new("bs0");
    let store = build_chain(&dir, 3);
    let out = TempDir::new("bs0-out");
    let err = export_cold_storage(
        &store,
        "deadbeef".into(),
        3,
        0,
        &out.0,
        None,
        &ExportOptions::default(),
    )
    .unwrap_err();
    assert!(format!("{err}").contains("--batch-size"));
}

#[test]
fn export_happy_path_writes_files_and_manifest() {
    let dir = TempDir::new("happy");
    let store = build_chain(&dir, 5);
    let out = TempDir::new("happy-out");
    let manifest = export_cold_storage(
        &store,
        "deadbeef".into(),
        5,
        2,
        &out.0,
        None,
        &ExportOptions::default(),
    )
    .unwrap();

    // v2 schema_version with no signature, no tsa.
    assert_eq!(manifest.schema_version, MANIFEST_SCHEMA_VERSION_V2);
    assert!(manifest.signature.is_none());
    assert!(manifest.tsa_token.is_none());
    assert_eq!(manifest.chain_id_hex, "deadbeef");
    assert_eq!(manifest.low_height, 1);
    assert_eq!(manifest.high_height, 5);
    // batch_size = 2 → batches at 1-2, 3-4, 5-5.
    assert_eq!(manifest.batch_count, 3);
    assert_eq!(manifest.batches.len(), 3);

    for entry in &manifest.batches {
        let path = out.0.join(&entry.file_name);
        let bytes = fs::read(&path).expect("batch file readable");
        assert_eq!(bytes.len() as u64, entry.compressed_bytes);
        let mut h = Sha256::new();
        h.update(&bytes);
        assert_eq!(hex::encode(h.finalize()), entry.sha256);
        assert_eq!(&bytes[..4], &[0x28, 0xb5, 0x2f, 0xfd]);
        assert_eq!(entry.anchor_block_hash.len(), 64);
    }

    let manifest_path = out.0.join("manifest.json");
    let raw = fs::read(&manifest_path).unwrap();
    let parsed: ColdStorageManifest = serde_json::from_slice(&raw).unwrap();
    assert_eq!(parsed, manifest);
}

#[test]
fn batch_decompression_round_trip_recovers_block_bytes() {
    let dir = TempDir::new("rt");
    let store = build_chain(&dir, 3);
    let out = TempDir::new("rt-out");
    let _ = export_cold_storage(
        &store,
        "deadbeef".into(),
        3,
        5,
        &out.0,
        None,
        &ExportOptions::default(),
    )
    .unwrap();

    let batch_path = out.0.join("blocks-00000001-00000003.zst");
    let compressed = fs::read(&batch_path).unwrap();
    let decompressed = zstd::decode_all(compressed.as_slice()).unwrap();

    let mut expected = Vec::new();
    for h in 1..=3u64 {
        expected.extend_from_slice(&store.export_block_bytes(h).unwrap().expect("block bytes"));
    }
    assert_eq!(decompressed, expected);
}

/// Helper: build a keystore with a single SLH-DSA-SHAKE-256s entry.
/// Returns the operator address and the public key bytes (32 bytes
/// of address, 64 bytes of pk).
fn keystore_with_slh(operator: [u8; 32]) -> (Keystore, Vec<u8>) {
    let (pk, sk) = slh_dsa_shake_256s_generate().expect("slh keygen");
    assert_eq!(pk.len(), 64);
    assert_eq!(sk.len(), 128);
    // Derive a real ML-DSA pk from the all-zero commit seed so the
    // KeystoreEntry public_key field is well-formed even though
    // this test only exercises the archival_sk path.
    let dummy_pk = pqc_crypto::ml_dsa_public_key_from_seed(AlgId::MlDsa65, &[0u8; 32]).unwrap();
    let mut ks = Keystore::new();
    ks.upsert(
        operator,
        KeystoreEntry {
            sig_alg_id: AlgId::MlDsa65,
            commit_seed: [0u8; 32],
            key_version: crate::keystore::DEFAULT_KEY_VERSION,
            public_key: dummy_pk,
            archival_sk: Some(sk),
        },
    );
    (ks, pk)
}

#[test]
fn signed_manifest_round_trip_recovers_pk() {
    // Sign a manifest, then verify the signature embedded in it
    // matches the freshly-derived public key from the secret key.
    let dir = TempDir::new("sign-rt");
    let store = build_chain(&dir, 2);
    let out = TempDir::new("sign-rt-out");
    let operator = [0xC4u8; 32];
    let (ks, expected_pk) = keystore_with_slh(operator);

    let manifest = export_cold_storage(
        &store,
        "deadbeef".into(),
        2,
        5,
        &out.0,
        Some(&ks),
        &ExportOptions {
            sign_with_operator_hex: Some(hex::encode(operator)),
            anchor_tsa_url: None,
            tsa_best_effort: false,
        },
    )
    .unwrap();

    let sig = manifest.signature.as_ref().expect("manifest signed");
    assert_eq!(sig.alg, "slh-dsa-shake-256s");
    assert_eq!(sig.signer_address_hex, hex::encode(operator));
    let recovered_pk = hex::decode(&sig.signer_pk_hex).unwrap();
    assert_eq!(recovered_pk, expected_pk);

    // Verify path returns the signer pk on success.
    let pk = verify_manifest_signature(&manifest).expect("verify ok");
    assert_eq!(pk, expected_pk);
}

#[test]
fn verify_rejects_tampered_manifest() {
    let dir = TempDir::new("tamper");
    let store = build_chain(&dir, 2);
    let out = TempDir::new("tamper-out");
    let operator = [0xC5u8; 32];
    let (ks, _) = keystore_with_slh(operator);

    let mut manifest = export_cold_storage(
        &store,
        "deadbeef".into(),
        2,
        5,
        &out.0,
        Some(&ks),
        &ExportOptions {
            sign_with_operator_hex: Some(hex::encode(operator)),
            anchor_tsa_url: None,
            tsa_best_effort: false,
        },
    )
    .unwrap();

    // Mutate a manifest field (chain_id_hex) — the signature MUST
    // no longer verify.
    manifest.chain_id_hex = "f00dface".to_string();
    let err = verify_manifest_signature(&manifest).unwrap_err();
    assert!(format!("{err}").contains("verification failed"));
}

#[test]
fn sign_with_unknown_operator_is_rejected() {
    let dir = TempDir::new("noop");
    let store = build_chain(&dir, 1);
    let out = TempDir::new("noop-out");
    let known_operator = [0x33u8; 32];
    let (ks, _) = keystore_with_slh(known_operator);

    let unknown = [0x44u8; 32];
    let err = export_cold_storage(
        &store,
        "deadbeef".into(),
        1,
        5,
        &out.0,
        Some(&ks),
        &ExportOptions {
            sign_with_operator_hex: Some(hex::encode(unknown)),
            anchor_tsa_url: None,
            tsa_best_effort: false,
        },
    )
    .unwrap_err();
    // anyhow chains contexts: the export wrapper adds "manifest signing failed",
    // the inner sign_manifest_in_place adds the per-operator detail. Use
    // alternate Display ({:#}) to walk the chain.
    let chain = format!("{err:#}");
    assert!(
        chain.contains("keystore has no entry"),
        "missing inner context in {chain}"
    );
}

#[test]
fn import_refuses_unsigned_manifest_without_insecure_flag() {
    let src_dir = TempDir::new("src");
    let store = build_chain(&src_dir, 3);
    let out = TempDir::new("unsigned");
    let _ = export_cold_storage(
        &store,
        "deadbeef".into(),
        3,
        5,
        &out.0,
        None,
        &ExportOptions::default(),
    )
    .unwrap();

    // Fresh empty target store.
    let target = TempDir::new("target");
    let mut tgt =
        RocksDbChainStore::open_no_wal(&target.0, BlockHash([0x11; 32])).expect("open ok");

    let err = import_cold_storage(&mut tgt, &out.0, &ImportOptions::default()).unwrap_err();
    assert!(format!("{err}").contains("no signature"));
}

#[test]
fn import_refuses_tampered_batch_sha() {
    let src_dir = TempDir::new("src-tamper");
    let store = build_chain(&src_dir, 3);
    let out = TempDir::new("out-tamper");
    let operator = [0x77u8; 32];
    let (ks, _) = keystore_with_slh(operator);
    let _ = export_cold_storage(
        &store,
        "deadbeef".into(),
        3,
        5,
        &out.0,
        Some(&ks),
        &ExportOptions {
            sign_with_operator_hex: Some(hex::encode(operator)),
            anchor_tsa_url: None,
            tsa_best_effort: false,
        },
    )
    .unwrap();

    // Corrupt one byte in the batch file (after the zstd magic).
    let batch_path = out.0.join("blocks-00000001-00000003.zst");
    let mut bytes = fs::read(&batch_path).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    fs::write(&batch_path, &bytes).unwrap();

    let target = TempDir::new("target-tamper");
    let mut tgt =
        RocksDbChainStore::open_no_wal(&target.0, BlockHash([0x11; 32])).expect("open ok");
    let err = import_cold_storage(&mut tgt, &out.0, &ImportOptions::default()).unwrap_err();
    assert!(format!("{err}").contains("SHA-256 mismatch"));
}

#[test]
fn export_then_import_round_trip_replays_blocks() {
    let src_dir = TempDir::new("rt-src");
    let store = build_chain(&src_dir, 4);
    let expected_tip = store.tip_hash().cloned().expect("tip");

    let out = TempDir::new("rt-out");
    let operator = [0x88u8; 32];
    let (ks, _) = keystore_with_slh(operator);
    let _manifest = export_cold_storage(
        &store,
        "deadbeef".into(),
        4,
        2,
        &out.0,
        Some(&ks),
        &ExportOptions {
            sign_with_operator_hex: Some(hex::encode(operator)),
            anchor_tsa_url: None,
            tsa_best_effort: false,
        },
    )
    .unwrap();

    // Drop the source store explicitly so RocksDB releases its lock
    // before we open the target — the two TempDirs are different
    // anyway, but this keeps the test order obvious.
    drop(store);

    let target = TempDir::new("rt-target");
    let mut tgt =
        RocksDbChainStore::open_no_wal(&target.0, BlockHash([0x11; 32])).expect("open ok");
    let summary =
        import_cold_storage(&mut tgt, &out.0, &ImportOptions::default()).expect("import ok");

    assert_eq!(summary.schema_version, MANIFEST_SCHEMA_VERSION_V2);
    assert_eq!(summary.low_height, 1);
    assert_eq!(summary.high_height, 4);
    assert_eq!(summary.batches_replayed, 2);
    assert_eq!(summary.blocks_replayed, 4);
    assert!(summary.signature_verified);
    assert!(!summary.tsa_token_present);
    assert_eq!(summary.final_tip_hash_hex, hex::encode(expected_tip.0));
    assert_eq!(tgt.height(), 4);
}

#[test]
fn require_tsa_flag_rejects_unanchored_manifest() {
    let src_dir = TempDir::new("rt-src-tsa");
    let store = build_chain(&src_dir, 2);
    let out = TempDir::new("rt-out-tsa");
    let operator = [0x99u8; 32];
    let (ks, _) = keystore_with_slh(operator);
    let _ = export_cold_storage(
        &store,
        "deadbeef".into(),
        2,
        5,
        &out.0,
        Some(&ks),
        &ExportOptions {
            sign_with_operator_hex: Some(hex::encode(operator)),
            anchor_tsa_url: None,
            tsa_best_effort: false,
        },
    )
    .unwrap();

    let target = TempDir::new("rt-target-tsa");
    let mut tgt =
        RocksDbChainStore::open_no_wal(&target.0, BlockHash([0x11; 32])).expect("open ok");
    let err = import_cold_storage(
        &mut tgt,
        &out.0,
        &ImportOptions {
            insecure_no_verify: false,
            require_tsa: true,
        },
    )
    .unwrap_err();
    assert!(format!("{err}").contains("--require-tsa"));
}

#[test]
fn canonical_bytes_strip_signature_and_tsa() {
    // The canonical preimage MUST be identical for a manifest with
    // sig+tsa and one without, given the same v1-fields.
    let m_unsigned = ColdStorageManifest {
        schema_version: MANIFEST_SCHEMA_VERSION_V2.into(),
        chain_id_hex: "abcd".into(),
        exported_at_unix: 100,
        low_height: 1,
        high_height: 2,
        batch_count: 1,
        batches: vec![BatchEntry {
            file_name: "blocks-00000001-00000002.zst".into(),
            low_height: 1,
            high_height: 2,
            anchor_block_hash: "ee".repeat(32),
            sha256: "11".repeat(32),
            uncompressed_bytes: 100,
            compressed_bytes: 60,
        }],
        signature: None,
        tsa_token: None,
    };
    let mut m_signed = m_unsigned.clone();
    m_signed.signature = Some(ManifestSignature {
        alg: "slh-dsa-shake-256s".into(),
        signer_address_hex: "cc".repeat(32),
        signer_pk_hex: "aa".repeat(64),
        value_hex: "bb".repeat(29_792),
    });
    m_signed.tsa_token = Some("dGVzdA==".into());

    let a = canonical_manifest_bytes(&m_unsigned).unwrap();
    let b = canonical_manifest_bytes(&m_signed).unwrap();
    assert_eq!(a, b, "canonical bytes must drop sig+tsa fields");
}

#[test]
fn rfc3161_request_carries_sha256_oid_and_digest() {
    // The encoder lives in `pqc-tsa`; this pin is a sanity check that
    // pqcd's call site stays wired to the shared crate (catches a
    // future re-introduction of an inline duplicate).
    let digest = [0x42u8; 32];
    let der = pqc_tsa::build_timestamp_request(&digest);
    assert_eq!(der[0], 0x30, "TimeStampReq must start with SEQUENCE tag");
    assert!(der.windows(32).any(|w| w == digest), "digest in DER");
    let oid = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
    assert!(
        der.windows(oid.len()).any(|w| w == oid),
        "SHA-256 OID missing"
    );
}

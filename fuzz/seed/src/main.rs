// SPDX-License-Identifier: BUSL-1.1
//! Seed-corpus generator for the libFuzzer targets under `fuzz/fuzz_targets/`.
//!
//! Produces a small set of canonical CBOR-encoded `Transaction` samples using
//! the real `pqc_tx::codec::encode_tx` path (so the output exactly matches what
//! `decode_tx` accepts) plus a few deliberately-corrupted / truncated / extended
//! variants to exercise edge-case handling.
//!
//! This is a one-shot helper. Invocation:
//!
//! ```bash
//! cd fuzz/seed
//! cargo run --release
//! # .bin files land in ../corpus/fuzz_decode_tx/ and ../corpus/fuzz_validate_tx/
//! # Optionally delete ./target to avoid committing build artefacts.
//! ```
//!
//! The generator is deterministic — re-running it produces identical bytes.
//! Checked-in seeds can therefore be regenerated at any time.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use pqc_crypto::AlgId;
use pqc_tx::codec::encode_tx;
use pqc_types::{
    account::Address,
    transaction::{MsgType, Transaction},
};

/// Expected ML-DSA-65 signature length (SPEC-CRYPTO-001 §2).
/// The fuzz targets also use this value — keep in sync.
const ML_DSA_65_SIG_LEN: usize = 3_309;

fn base_tx(msg_type: MsgType, sender: u8, nonce: u64, payload: Vec<u8>) -> Transaction {
    Transaction {
        tx_version: 1,
        chain_id: b"pqc-devnet".to_vec(),
        msg_type,
        sender: Address([sender; 32]),
        nonce,
        fee: 1_000,
        fee_tip: 0,
        gas_limit: 100_000,
        payload,
        sig_alg_id: AlgId::MlDsa65,
        sig_key_version: 1,
        signature: vec![0u8; ML_DSA_65_SIG_LEN],
    }
}

fn write_seed(dir: &Path, idx: usize, bytes: &[u8]) -> std::io::Result<()> {
    let path: PathBuf = dir.join(format!("seed_{idx:02}.bin"));
    let mut f = fs::File::create(&path)?;
    f.write_all(bytes)?;
    println!("  wrote {} ({} bytes)", path.display(), bytes.len());
    Ok(())
}

fn main() -> std::io::Result<()> {
    // Resolve corpus dirs relative to this crate (../corpus/<target>).
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let corpus_root: PathBuf = Path::new(manifest_dir).join("..").join("corpus");
    let decode_dir = corpus_root.join("fuzz_decode_tx");
    let validate_dir = corpus_root.join("fuzz_validate_tx");
    let shake_dir = corpus_root.join("fuzz_shake256");

    for d in [&decode_dir, &validate_dir, &shake_dir] {
        fs::create_dir_all(d)?;
    }

    // ── Valid canonical transactions ─────────────────────────────────────────
    println!("generating valid CBOR transaction seeds…");

    let valid_txs: Vec<(&str, Transaction)> = vec![
        (
            "TokenTransfer (minimal, fee_tip=0)",
            base_tx(MsgType::TokenTransfer, 0x11, 1, vec![]),
        ),
        (
            "TokenTransfer (small payload)",
            base_tx(MsgType::TokenTransfer, 0x22, 2, vec![0xaa; 16]),
        ),
        ("TokenTransfer (with fee_tip)", {
            let mut t = base_tx(MsgType::TokenTransfer, 0x33, 3, vec![0xbb; 8]);
            t.fee_tip = 50;
            t
        }),
        (
            "VaultCreate",
            base_tx(MsgType::VaultCreate, 0x44, 1, vec![0xcc; 32]),
        ),
        (
            "VaultPolicyUpdate",
            base_tx(MsgType::VaultPolicyUpdate, 0x55, 1, vec![0xdd; 64]),
        ),
        (
            "AttestationCreate",
            base_tx(MsgType::AttestationCreate, 0x66, 1, vec![0xee; 128]),
        ),
        (
            "AttestationRevoke",
            base_tx(MsgType::AttestationRevoke, 0x77, 1, vec![0xff; 32]),
        ),
        (
            "KeyRotate",
            base_tx(MsgType::KeyRotate, 0x88, 1, vec![0x10; 96]),
        ),
        (
            "ValidatorRegister",
            base_tx(MsgType::ValidatorRegister, 0x99, 1, vec![0x20; 64]),
        ),
        ("TokenTransfer (large payload 1 KiB)", {
            base_tx(MsgType::TokenTransfer, 0xaa, 1, vec![0x5a; 1024])
        }),
    ];

    let mut encoded: Vec<Vec<u8>> = Vec::with_capacity(valid_txs.len());
    let mut idx = 0usize;
    for (label, tx) in &valid_txs {
        let bytes = encode_tx(tx).expect("encode_tx failed on valid fixture");
        println!("  [{idx:02}] {label} → {} bytes", bytes.len());
        write_seed(&decode_dir, idx, &bytes)?;
        encoded.push(bytes);
        idx += 1;
    }

    // ── Edge-case variants: truncated / extended ────────────────────────────
    //
    // These are deliberately *invalid* canonical encodings. They exercise the
    // decoder's error paths (short read, trailing garbage, bit-flip, zero-len).
    println!("generating edge-case corrupted seeds…");

    // Truncated first valid tx (keep only first 16 bytes).
    let mut trunc = encoded[0].clone();
    trunc.truncate(16);
    write_seed(&decode_dir, idx, &trunc)?;
    idx += 1;

    // Truncated second valid tx (half-length).
    let mut trunc2 = encoded[1].clone();
    let half = trunc2.len() / 2;
    trunc2.truncate(half);
    write_seed(&decode_dir, idx, &trunc2)?;
    idx += 1;

    // Extended: valid tx + trailing garbage bytes.
    let mut extended = encoded[0].clone();
    extended.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
    write_seed(&decode_dir, idx, &extended)?;
    idx += 1;

    // Bit-flipped middle byte (corrupted but structurally close to valid).
    let mut flipped = encoded[2].clone();
    let mid = flipped.len() / 2;
    flipped[mid] ^= 0xff;
    write_seed(&decode_dir, idx, &flipped)?;
    idx += 1;

    // Empty input — the most trivial edge case.
    write_seed(&decode_dir, idx, &[])?;
    idx += 1;

    println!("fuzz_decode_tx: {idx} seeds written");

    // ── fuzz_validate_tx: reuse the decode seeds ─────────────────────────────
    //
    // The validate target already runs `decode_tx` on the raw bytes then pushes
    // the result through validate_tx. Re-using the same corpus gives libFuzzer
    // a warm start on both code paths.
    println!("copying decode seeds into fuzz_validate_tx corpus…");
    let mut vidx = 0usize;
    for entry in fs::read_dir(&decode_dir)? {
        let entry = entry?;
        let src = entry.path();
        if src.extension().and_then(|e| e.to_str()) != Some("bin") {
            continue;
        }
        let bytes = fs::read(&src)?;
        write_seed(&validate_dir, vidx, &bytes)?;
        vidx += 1;
    }
    println!("fuzz_validate_tx: {vidx} seeds written");

    // ── fuzz_shake256: raw byte variety ──────────────────────────────────────
    println!("generating fuzz_shake256 seeds…");

    // Empty
    write_seed(&shake_dir, 0, &[])?;
    // One byte
    write_seed(&shake_dir, 1, &[0x00])?;
    // One byte, high value
    write_seed(&shake_dir, 2, &[0xff])?;
    // 32 bytes zero
    write_seed(&shake_dir, 3, &[0u8; 32])?;
    // 32 bytes 0xaa alternating
    write_seed(&shake_dir, 4, &[0xaa; 32])?;
    // 64 bytes ascending
    let asc: Vec<u8> = (0..64u8).collect();
    write_seed(&shake_dir, 5, &asc)?;
    // 135 bytes — SHAKE-256 rate boundary (r = 1088 bits = 136 bytes; exercise -1 byte)
    write_seed(&shake_dir, 6, &vec![0x5a; 135])?;
    // 136 bytes — one block
    write_seed(&shake_dir, 7, &vec![0x5a; 136])?;
    // 137 bytes — one block + 1
    write_seed(&shake_dir, 8, &vec![0x5a; 137])?;
    // 8 KiB deterministic pattern
    let mut big = Vec::with_capacity(8 * 1024);
    for i in 0..(8 * 1024) {
        big.push((i & 0xff) as u8);
    }
    write_seed(&shake_dir, 9, &big)?;

    println!("fuzz_shake256: 10 seeds written");
    println!("done.");
    Ok(())
}

// SPDX-License-Identifier: Apache-2.0
//! Benchmarks for PQ signature verification and signing on this node hardware.
//!
//! Run with:
//!   cargo bench -p pqc-crypto --features ml-dsa-backend --bench sig_verify
//!
//! Results from this bench inform TBD-FEE-03/04/05 in specs/fee-model.md.
//! The benchmark_class_fee for each fee class (V-A, V-B, V-C) must be derived
//! from measured per-verify latency on reference hardware.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use getrandom::rand_core::UnwrapErr;
use ml_dsa::{
    signature::{Keypair, SignatureEncoding, Signer},
    EncodedVerifyingKey, KeyGen, MlDsa44, MlDsa65, MlDsa87, Signature as MlDsaSig, VerifyingKey,
};
use pqc_crypto::{
    hash::shake256_32,
    sign::{PublicKey, Signature, SignatureVerifier},
    AlgId, MlDsaVerifier,
};

// Typical PQ Chain signed preimage: prefix + CBOR-encoded tx fields (sans signature).
// The actual size depends on the transaction; 256 bytes is representative.
const PREIMAGE: &[u8] = &[
    b'P', b'Q', b'C', b'-', b'T', b'X', b'-', b'V', b'1', 0x00,
    // 246 bytes of placeholder CBOR content (representative tx body)
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
    0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,
    0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,
    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
    0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
    0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,
    0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,
    0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef,
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5,
];

// ── ML-DSA-44 (fee class V-B) ──────────────────────────────────────────────

fn bench_mldsa44_verify(c: &mut Criterion) {
    let mut rng = UnwrapErr(getrandom::SysRng);
    let kp = MlDsa44::key_gen(&mut rng);
    let vk = kp.verifying_key();
    let sig: MlDsaSig<MlDsa44> = kp.signing_key().sign(PREIMAGE);

    let pk = PublicKey {
        alg_id: AlgId::MlDsa44,
        bytes: vk.encode().to_vec(),
    };
    let signature = Signature {
        alg_id: AlgId::MlDsa44,
        bytes: sig.to_bytes().as_slice().to_vec(),
    };

    c.bench_function("ml_dsa_44/verify", |b| {
        b.iter(|| {
            MlDsaVerifier
                .verify(black_box(&pk), black_box(PREIMAGE), black_box(&signature))
                .expect("valid sig")
        })
    });
}

fn bench_mldsa44_sign(c: &mut Criterion) {
    let mut rng = UnwrapErr(getrandom::SysRng);
    let kp = MlDsa44::key_gen(&mut rng);

    c.bench_function("ml_dsa_44/sign", |b| {
        b.iter(|| {
            let sig: MlDsaSig<MlDsa44> = kp.signing_key().sign(black_box(PREIMAGE));
            black_box(sig.to_bytes().as_slice().to_vec())
        })
    });
}

// ── ML-DSA-65 (fee class V-B reference) ───────────────────────────────────

fn bench_mldsa65_verify(c: &mut Criterion) {
    let mut rng = UnwrapErr(getrandom::SysRng);
    let kp = MlDsa65::key_gen(&mut rng);
    let vk = kp.verifying_key();
    let sig: MlDsaSig<MlDsa65> = kp.signing_key().sign(PREIMAGE);

    let pk = PublicKey {
        alg_id: AlgId::MlDsa65,
        bytes: vk.encode().to_vec(),
    };
    let signature = Signature {
        alg_id: AlgId::MlDsa65,
        bytes: sig.to_bytes().as_slice().to_vec(),
    };

    c.bench_function("ml_dsa_65/verify", |b| {
        b.iter(|| {
            MlDsaVerifier
                .verify(black_box(&pk), black_box(PREIMAGE), black_box(&signature))
                .expect("valid sig")
        })
    });
}

fn bench_mldsa65_sign(c: &mut Criterion) {
    let mut rng = UnwrapErr(getrandom::SysRng);
    let kp = MlDsa65::key_gen(&mut rng);

    c.bench_function("ml_dsa_65/sign", |b| {
        b.iter(|| {
            let sig: MlDsaSig<MlDsa65> = kp.signing_key().sign(black_box(PREIMAGE));
            black_box(sig.to_bytes().as_slice().to_vec())
        })
    });
}

// ── ML-DSA-87 (fee class V-B) ──────────────────────────────────────────────

fn bench_mldsa87_verify(c: &mut Criterion) {
    let mut rng = UnwrapErr(getrandom::SysRng);
    let kp = MlDsa87::key_gen(&mut rng);
    let vk = kp.verifying_key();
    let sig: MlDsaSig<MlDsa87> = kp.signing_key().sign(PREIMAGE);

    let pk = PublicKey {
        alg_id: AlgId::MlDsa87,
        bytes: vk.encode().to_vec(),
    };
    let signature = Signature {
        alg_id: AlgId::MlDsa87,
        bytes: sig.to_bytes().as_slice().to_vec(),
    };

    c.bench_function("ml_dsa_87/verify", |b| {
        b.iter(|| {
            MlDsaVerifier
                .verify(black_box(&pk), black_box(PREIMAGE), black_box(&signature))
                .expect("valid sig")
        })
    });
}

fn bench_mldsa87_sign(c: &mut Criterion) {
    let mut rng = UnwrapErr(getrandom::SysRng);
    let kp = MlDsa87::key_gen(&mut rng);

    c.bench_function("ml_dsa_87/sign", |b| {
        b.iter(|| {
            let sig: MlDsaSig<MlDsa87> = kp.signing_key().sign(black_box(PREIMAGE));
            black_box(sig.to_bytes().as_slice().to_vec())
        })
    });
}

// ── Key decode overhead (hot path on every verify call) ────────────────────

fn bench_mldsa65_key_decode(c: &mut Criterion) {
    let mut rng = UnwrapErr(getrandom::SysRng);
    let kp = MlDsa65::key_gen(&mut rng);
    let vk = kp.verifying_key();
    let encoded = vk.encode();

    c.bench_function("ml_dsa_65/key_decode", |b| {
        b.iter(|| {
            let enc = EncodedVerifyingKey::<MlDsa65>::try_from(encoded.as_slice()).unwrap();
            black_box(VerifyingKey::<MlDsa65>::decode(&enc))
        })
    });
}

// ── SHAKE-256 hashing (tx_hash + state_root hot path) ─────────────────────

fn bench_shake256_32(c: &mut Criterion) {
    // Representative inputs: tx bytes (~4 KB with ML-DSA-65 sig) and state digest (~256 B)
    let mut group = c.benchmark_group("shake256_32");

    for size in [64usize, 256, 1024, 4096] {
        let input: Vec<u8> = (0..size).map(|i| (i & 0xff) as u8).collect();
        group.bench_with_input(BenchmarkId::from_parameter(size), &input, |b, data| {
            b.iter(|| black_box(shake256_32(black_box(data))))
        });
    }

    group.finish();
}

// ── Commit material: ML-DSA-65 sign over block preimage ────────────────────
//
// In the producer loop, each block commit requires one ML-DSA-65 sign over
// commit_preimage(height, block_hash). This bench isolates that cost.

fn bench_commit_material_sign(c: &mut Criterion) {
    let mut rng = UnwrapErr(getrandom::SysRng);
    let kp = MlDsa65::key_gen(&mut rng);

    // commit_preimage = b"PQC-COMMIT-V1" || uint64_be(height) || block_hash (32 bytes)
    let mut preimage = b"PQC-COMMIT-V1".to_vec();
    preimage.extend_from_slice(&42u64.to_be_bytes());
    preimage.extend_from_slice(&[0xAB; 32]);

    c.bench_function("commit_material/ml_dsa_65_sign", |b| {
        b.iter(|| {
            let sig: MlDsaSig<MlDsa65> = kp.signing_key().sign(black_box(&preimage));
            black_box(sig.to_bytes().as_slice().to_vec())
        })
    });
}

fn bench_commit_material_verify(c: &mut Criterion) {
    let mut rng = UnwrapErr(getrandom::SysRng);
    let kp = MlDsa65::key_gen(&mut rng);
    let vk = kp.verifying_key();

    let mut preimage = b"PQC-COMMIT-V1".to_vec();
    preimage.extend_from_slice(&42u64.to_be_bytes());
    preimage.extend_from_slice(&[0xAB; 32]);
    let sig: MlDsaSig<MlDsa65> = kp.signing_key().sign(&preimage);

    let pk = PublicKey {
        alg_id: AlgId::MlDsa65,
        bytes: vk.encode().to_vec(),
    };
    let signature = Signature {
        alg_id: AlgId::MlDsa65,
        bytes: sig.to_bytes().as_slice().to_vec(),
    };

    c.bench_function("commit_material/ml_dsa_65_verify", |b| {
        b.iter(|| {
            MlDsaVerifier
                .verify(black_box(&pk), black_box(&preimage), black_box(&signature))
                .expect("valid sig")
        })
    });
}

criterion_group!(
    benches,
    bench_mldsa44_verify,
    bench_mldsa44_sign,
    bench_mldsa65_verify,
    bench_mldsa65_sign,
    bench_mldsa87_verify,
    bench_mldsa87_sign,
    bench_mldsa65_key_decode,
    bench_shake256_32,
    bench_commit_material_sign,
    bench_commit_material_verify,
);
criterion_main!(benches);

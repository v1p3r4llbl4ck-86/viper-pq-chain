// SPDX-License-Identifier: Apache-2.0
//! Timing-profile harness for PQ signing and verification (TASK-155).
//!
//! This is **NOT a dudect-grade constant-time proof**. It is a pragmatic
//! timing-variance profile that produces evidence for the Phase 8
//! security audit dossier (see `docs/phase-8-audit-readiness.md` §4
//! gap C9 / `KNOWN-ISSUES.md` item in §2). For a formal CT claim,
//! Cryspen/Quarkslab/Fraunhofer will run `dudect` with statistical
//! bounds under controlled hardware (fixed CPU affinity, governor
//! disabled, interrupts pinned away, thermal throttling off).
//!
//! What this harness does:
//! * Warm up each signing / verification path
//! * Run N trials across *different input messages* for each path
//! * Record wall-clock duration per operation
//! * Compute p50 / p90 / p99 / p99÷p50 ratio / CV (coefficient of variation)
//! * Assert loose sanity bounds (CV < 0.5; p99/p50 < 10) so CI-level
//!   noise can be distinguished from truly divergent behaviour
//! * Print a Markdown-formatted block that can be archived in
//!   `reports/timing/<date>.md`
//!
//! The harness is `#[ignore]`'d and feature-gated on `pq-verifier` so
//! it never runs on the default `cargo test` path. To execute:
//!
//! ```sh
//! cargo test -p pqc-crypto --features pq-verifier \
//!     --test timing_profile -- --ignored --nocapture
//! ```
//!
//! Numbers vary with CPU / thermal state / concurrent load and are
//! NOT a bound on the primitive itself — they are a bound on our
//! wrapper, which the auditor can diff against upstream crate
//! benchmarks to detect glue-code regressions.

#![cfg(feature = "pq-verifier")]

use pqc_crypto::{
    ml_dsa_public_key_from_seed, ml_dsa_sign_with_seed, slh_dsa_shake_192s_generate,
    slh_dsa_shake_192s_sign, slh_dsa_shake_256s_generate, slh_dsa_shake_256s_sign, AlgId,
    PqVerifier, PublicKey, Signature, SignatureVerifier,
};
use std::time::{Duration, Instant};

const ML_DSA_TRIALS: usize = 200;
// SLH-DSA signing is ~2 s per sig on commodity x86 (SHAKE-192s, sk 96 B,
// sig 16 224 B, 22 layers). 20 trials * 2 s = 40 s is already a stretch
// for a test — the auditor runs this with --ignored so the budget is OK,
// but more than this is wasteful on CI fallback.
const SLH_DSA_TRIALS: usize = 20;

/// Summary statistics over a sample of Duration measurements.
#[allow(dead_code)]
struct Stats {
    n: usize,
    min: Duration,
    p50: Duration,
    p90: Duration,
    p99: Duration,
    max: Duration,
    mean_ns: f64,
    stddev_ns: f64,
    cv: f64,
    p99_over_p50: f64,
}

impl Stats {
    fn from(mut samples: Vec<Duration>) -> Self {
        samples.sort();
        let n = samples.len();
        let min = samples[0];
        let max = samples[n - 1];
        let p50 = samples[n / 2];
        let p90 = samples[(n * 90) / 100];
        let p99 = samples[(n * 99) / 100];

        let mean_ns: f64 = samples.iter().map(|d| d.as_nanos() as f64).sum::<f64>() / n as f64;
        let var_ns: f64 = samples
            .iter()
            .map(|d| {
                let x = d.as_nanos() as f64;
                (x - mean_ns).powi(2)
            })
            .sum::<f64>()
            / n as f64;
        let stddev_ns = var_ns.sqrt();
        let cv = if mean_ns > 0.0 {
            stddev_ns / mean_ns
        } else {
            0.0
        };
        let p99_over_p50 = p99.as_nanos() as f64 / p50.as_nanos().max(1) as f64;

        Self {
            n,
            min,
            p50,
            p90,
            p99,
            max,
            mean_ns,
            stddev_ns,
            cv,
            p99_over_p50,
        }
    }

    fn print_md(&self, label: &str) {
        println!(
            "| {} | {} | {:>10} | {:>10} | {:>10} | {:>10} | {:>10} | {:>10.3} | {:>6.3} |",
            label,
            self.n,
            format!("{:?}", self.min),
            format!("{:?}", self.p50),
            format!("{:?}", self.p90),
            format!("{:?}", self.p99),
            format!("{:?}", self.max),
            self.cv,
            self.p99_over_p50,
        );
    }
}

// Derive a fresh 32-byte message from `i` so successive trials have
// different inputs — the goal is to stress timing variance across
// *input content*, not repeat the same ciphertext.
fn message(i: usize) -> [u8; 32] {
    use sha3::{
        digest::{ExtendableOutput, Update, XofReader},
        Shake256,
    };
    let mut h = Shake256::default();
    h.update(b"TIMING-PROFILE-V1");
    h.update(&(i as u64).to_be_bytes());
    let mut out = [0u8; 32];
    h.finalize_xof().read(&mut out);
    out
}

fn print_header() {
    println!();
    println!("## Timing profile — TASK-155");
    println!();
    println!("| path | n | min | p50 | p90 | p99 | max | CV | p99/p50 |");
    println!("|------|---|-----|-----|-----|-----|-----|----|---------|");
}

fn print_footer() {
    println!();
    println!(
        "_CV = coefficient of variation (σ/μ). p99/p50 = tail-to-median ratio. \
         These numbers are timing-profile evidence, not a constant-time proof — \
         see module docstring._"
    );
    println!();
}

/// ML-DSA-65 sign timing profile over 200 distinct inputs.
#[test]
#[ignore = "timing profile — run explicitly with --ignored (slow)"]
fn ml_dsa_65_sign_timing_profile() {
    let seed = [0xA5u8; 32];
    // Warm up — the first few signs prime branch predictors and caches.
    for i in 0..10 {
        let _ = ml_dsa_sign_with_seed(AlgId::MlDsa65, &seed, &message(i)).expect("warm-up sign");
    }

    let mut samples = Vec::with_capacity(ML_DSA_TRIALS);
    for i in 0..ML_DSA_TRIALS {
        let preimage = message(i);
        let t0 = Instant::now();
        let _sig = ml_dsa_sign_with_seed(AlgId::MlDsa65, &seed, &preimage).expect("sign");
        samples.push(t0.elapsed());
    }

    let stats = Stats::from(samples);
    print_header();
    stats.print_md("ML-DSA-65 sign");
    print_footer();

    // ML-DSA signing uses **rejection sampling** per FIPS 204 §6.2:
    // the main sign loop repeatedly generates candidate signatures
    // until one satisfies the bound checks (z.infty_norm < gamma1-beta,
    // r0.infty_norm < gamma2-beta, hints count ≤ omega). Iteration
    // count varies per-message, which makes sign **non-constant-time
    // by design** without leaking private-key bits. Observed CV on
    // commodity hardware is 0.3–0.7 with long-tail outliers up to
    // p99/p50 ≈ 10-20. These bounds accept that rejection-sampling
    // variance while still catching truly pathological behaviour.
    // See libcrux documentation and FIPS 204 §3.7.
    assert!(
        stats.cv < 1.5,
        "ML-DSA-65 sign CV {:.3} exceeds rejection-sampling bound 1.5",
        stats.cv
    );
    assert!(
        stats.p99_over_p50 < 25.0,
        "ML-DSA-65 sign p99/p50 ratio {:.2} exceeds rejection-sampling bound 25",
        stats.p99_over_p50
    );
}

/// ML-DSA-65 verify timing profile over 200 distinct (msg, sig) pairs.
#[test]
#[ignore = "timing profile — run explicitly with --ignored (slow)"]
fn ml_dsa_65_verify_timing_profile() {
    let seed = [0xA5u8; 32];
    let pk_bytes = ml_dsa_public_key_from_seed(AlgId::MlDsa65, &seed).expect("pk");
    let verifier = PqVerifier;
    let pk = PublicKey {
        alg_id: AlgId::MlDsa65,
        bytes: pk_bytes,
    };

    // Pre-generate signatures so verify timing is measured in isolation.
    let mut sigs: Vec<(Vec<u8>, Vec<u8>)> = Vec::with_capacity(ML_DSA_TRIALS);
    for i in 0..ML_DSA_TRIALS {
        let preimage = message(i);
        let sig_bytes =
            ml_dsa_sign_with_seed(AlgId::MlDsa65, &seed, &preimage).expect("sign for verify");
        sigs.push((preimage.to_vec(), sig_bytes));
    }

    // Warm up.
    for (preimage, sig_bytes) in sigs.iter().take(10) {
        let sig = Signature {
            alg_id: AlgId::MlDsa65,
            bytes: sig_bytes.clone(),
        };
        verifier
            .verify(&pk, preimage, &sig)
            .expect("warm-up verify");
    }

    let mut samples = Vec::with_capacity(ML_DSA_TRIALS);
    for (preimage, sig_bytes) in sigs.iter() {
        let sig = Signature {
            alg_id: AlgId::MlDsa65,
            bytes: sig_bytes.clone(),
        };
        let t0 = Instant::now();
        verifier.verify(&pk, preimage, &sig).expect("verify");
        samples.push(t0.elapsed());
    }

    let stats = Stats::from(samples);
    print_header();
    stats.print_md("ML-DSA-65 verify");
    print_footer();

    assert!(stats.cv < 0.5, "ML-DSA-65 verify CV {:.3}", stats.cv);
    assert!(
        stats.p99_over_p50 < 10.0,
        "ML-DSA-65 verify p99/p50 {:.2}",
        stats.p99_over_p50
    );
}

/// SLH-DSA-SHAKE-192s sign timing profile over 20 distinct inputs.
/// Trial count is low because SLH-DSA signing takes ~seconds per call;
/// 20 is enough to see first-order variance without being a CI tax.
#[test]
#[ignore = "timing profile — run explicitly with --ignored (very slow: ~20 s each for SLH)"]
fn slh_dsa_shake_192s_sign_timing_profile() {
    let (_pk, sk) = slh_dsa_shake_192s_generate().expect("keygen");

    // Warm up.
    for i in 0..2 {
        let _ = slh_dsa_shake_192s_sign(&sk, &message(i)).expect("warm-up sign");
    }

    let mut samples = Vec::with_capacity(SLH_DSA_TRIALS);
    for i in 0..SLH_DSA_TRIALS {
        let preimage = message(i);
        let t0 = Instant::now();
        let _sig = slh_dsa_shake_192s_sign(&sk, &preimage).expect("sign");
        samples.push(t0.elapsed());
    }

    let stats = Stats::from(samples);
    print_header();
    stats.print_md("SLH-DSA-SHAKE-192s sign");
    print_footer();

    // SLH-DSA is a Merkle-tree signature with many SHAKE-256 absorb calls;
    // its variance profile is typically tighter than ML-DSA (no rejection
    // sampling) but the total wall time is dominated by the deterministic
    // hash tree — CV should be very small.
    assert!(
        stats.cv < 0.3,
        "SLH-DSA-SHAKE-192s sign CV {:.3} — SLH primitives are deterministic, high variance is suspicious",
        stats.cv
    );
    assert!(
        stats.p99_over_p50 < 3.0,
        "SLH-DSA-SHAKE-192s sign p99/p50 ratio {:.2}",
        stats.p99_over_p50
    );
}

/// SLH-DSA-SHAKE-256s sign timing profile over 20 distinct inputs (TASK-162).
///
/// The Cat-5 archival signing path per ADR-045 / SPEC-ARCHIVAL-001 §4.7.
/// 256s signatures are ~2× slower than 192s (deeper Merkle tree + 32-byte
/// WOTS digests) so a full 20 trials can take 2–5 minutes — budget
/// accordingly when the auditor runs this with `--ignored`.
#[test]
#[ignore = "timing profile — run explicitly with --ignored (very slow: ~2-5 min for SLH-256s)"]
fn slh_dsa_shake_256s_sign_timing_profile() {
    let (_pk, sk) = slh_dsa_shake_256s_generate().expect("keygen");

    // Warm up — same two-trial prologue as the 192s profile.
    for i in 0..2 {
        let _ = slh_dsa_shake_256s_sign(&sk, &message(i)).expect("warm-up sign");
    }

    let mut samples = Vec::with_capacity(SLH_DSA_TRIALS);
    for i in 0..SLH_DSA_TRIALS {
        let preimage = message(i);
        let t0 = Instant::now();
        let _sig = slh_dsa_shake_256s_sign(&sk, &preimage).expect("sign");
        samples.push(t0.elapsed());
    }

    let stats = Stats::from(samples);
    print_header();
    stats.print_md("SLH-DSA-SHAKE-256s sign");
    print_footer();

    // Same deterministic-Merkle-tree reasoning as 192s: tight variance
    // expected (no rejection sampling). Bounds match the 192s profile.
    assert!(
        stats.cv < 0.3,
        "SLH-DSA-SHAKE-256s sign CV {:.3} — SLH primitives are deterministic, high variance is suspicious",
        stats.cv
    );
    assert!(
        stats.p99_over_p50 < 3.0,
        "SLH-DSA-SHAKE-256s sign p99/p50 ratio {:.2}",
        stats.p99_over_p50
    );
}

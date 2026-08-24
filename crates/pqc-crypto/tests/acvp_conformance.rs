// SPDX-License-Identifier: Apache-2.0
//! ACVP (FIPS 204 / FIPS 205) conformance harness — TASK-154.
//!
//! Loads NIST ACVP-Server `sigVer` AFT (Algorithm Function Test) vectors
//! committed under `tests/acvp/<alg>/sigVer_aft.json` and drives them through
//! the production `PqVerifier`. Evidence for the Phase 8 tier-1 audit kickoff
//! (readiness review §4 gap C8 — "zero committed NIST test vectors").
//!
//! The harness is `#[ignore]`'d so it does not run on every `cargo test`.
//! Run explicitly with:
//!
//!     cargo test -p pqc-crypto --features pq-verifier \
//!         --test acvp_conformance -- --ignored --nocapture
//!
//! # Why these tests are `#[ignore]`
//!
//! 1. They require the `pq-verifier` feature (ML-DSA + SLH-DSA backends).
//! 2. SLH-DSA-SHAKE-256s verification takes ~seconds per case; running them
//!    on every pre-commit CI cycle is wasteful.
//! 3. They are auditor evidence, not a gating test — the fast round-trip
//!    tests in `verify.rs` already gate every commit.
//!
//! # Wrapper vs. backend split
//!
//! ACVP AFT vectors include a random `context` byte string per test case
//! (0–255 bytes). Our production `PqVerifier::verify()` signature has no
//! context parameter — it is hard-wired to the empty context, which is the
//! only form used on-chain (see ADR-011 §3, SPEC-TX-001 §6).
//!
//! To exercise every ACVP vector we split the dispatch:
//!
//! * `context == ""` cases → through `PqVerifier::verify()` (full wrapper).
//! * `context != ""` cases → through the backend crate's `verify_with_context`
//!   (ML-DSA) or `try_verify_with_context` (SLH-DSA) directly. These prove the
//!   *committed vectors themselves* are conformant against the upstream
//!   FIPS 204 / FIPS 205 implementation we depend on. The wrapper does not
//!   expose a context path; tracked separately (see `tests/acvp/README.md`
//!   "Known limitations").
//!
//! Both paths must return `Ok(())` iff `testPassed == true`.

#![cfg(feature = "pq-verifier")]

use std::fs;
use std::path::{Path, PathBuf};

use ml_dsa::{EncodedVerifyingKey, MlDsa44, MlDsa65, MlDsa87, Signature as MlDsaSig, VerifyingKey};
use pqc_crypto::{
    sign::{PublicKey, Signature, SignatureVerifier},
    AlgId, PqVerifier,
};
use serde::Deserialize;
use slh_dsa::{Shake128s, Shake192s, Shake256s, VerifyingKey as SlhVk};

/// Root directory that holds the committed ACVP fixture tree.
/// The path is relative to the pqc-crypto crate (CARGO_MANIFEST_DIR).
const ACVP_ROOT_REL: &str = "../../tests/acvp";

#[derive(Debug, Deserialize)]
struct VectorFile {
    #[allow(dead_code)]
    source: String,
    #[allow(dead_code)]
    #[serde(rename = "acvpCommit")]
    acvp_commit: String,
    algorithm: String,
    revision: String,
    #[serde(rename = "testGroups")]
    groups: Vec<TestGroup>,
}

#[derive(Debug, Deserialize)]
struct TestGroup {
    #[serde(rename = "parameterSet")]
    parameter_set: String,
    #[serde(rename = "testType")]
    test_type: String,
    tests: Vec<TestCase>,
}

#[derive(Debug, Deserialize)]
struct TestCase {
    #[serde(rename = "tcId")]
    tc_id: u32,
    /// Hex-encoded random context (may be empty).
    context: String,
    /// Hex-encoded message.
    message: String,
    /// Hex-encoded public verifying key.
    pk: String,
    /// Hex-encoded signature.
    signature: String,
    /// Expected result per ACVP expectedResults.json: `true` means the signature
    /// is well-formed and verifies; `false` means it must be rejected.
    #[serde(rename = "testPassed")]
    test_passed: bool,
}

/// Running tally across all parameter sets.
#[derive(Default, Debug)]
struct Stats {
    wrapper_ok: u32,
    wrapper_skipped_ctx: u32,
    backend_ok: u32,
    wrapper_failures: Vec<String>,
    backend_failures: Vec<String>,
}

fn vector_path(alg_dir: &str) -> PathBuf {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .join(ACVP_ROOT_REL)
        .join(alg_dir)
        .join("sigVer_aft.json")
}

fn load(alg_dir: &str) -> VectorFile {
    let path = vector_path(alg_dir);
    let raw = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("could not read {}: {e}", path.display()));
    serde_json::from_str(&raw).unwrap_or_else(|e| panic!("could not parse {}: {e}", path.display()))
}

fn hex(s: &str) -> Vec<u8> {
    hex::decode(s).expect("malformed hex in ACVP vector")
}

/// Return the wrapper AlgId for a given ACVP parameter set name.
fn alg_id_of(param: &str) -> Option<AlgId> {
    match param {
        "ML-DSA-44" => Some(AlgId::MlDsa44),
        "ML-DSA-65" => Some(AlgId::MlDsa65),
        "ML-DSA-87" => Some(AlgId::MlDsa87),
        "SLH-DSA-SHAKE-128s" => Some(AlgId::SlhDsaShake128s),
        "SLH-DSA-SHAKE-192s" => Some(AlgId::SlhDsaShake192s),
        "SLH-DSA-SHAKE-256s" => Some(AlgId::SlhDsaShake256s),
        _ => None,
    }
}

/// Verify with explicit context by calling the backend crate directly,
/// bypassing the wrapper (which does not expose a context parameter).
fn backend_verify_with_ctx(
    alg: AlgId,
    pk: &[u8],
    msg: &[u8],
    ctx: &[u8],
    sig: &[u8],
) -> Result<(), String> {
    match alg {
        AlgId::MlDsa44 => {
            let enc =
                EncodedVerifyingKey::<MlDsa44>::try_from(pk).map_err(|_| "pk size".to_string())?;
            let vk = VerifyingKey::<MlDsa44>::decode(&enc);
            let s = MlDsaSig::<MlDsa44>::try_from(sig).map_err(|_| "sig size".to_string())?;
            if vk.verify_with_context(msg, ctx, &s) {
                Ok(())
            } else {
                Err("verify_with_context returned false".to_string())
            }
        }
        AlgId::MlDsa65 => {
            let enc =
                EncodedVerifyingKey::<MlDsa65>::try_from(pk).map_err(|_| "pk size".to_string())?;
            let vk = VerifyingKey::<MlDsa65>::decode(&enc);
            let s = MlDsaSig::<MlDsa65>::try_from(sig).map_err(|_| "sig size".to_string())?;
            if vk.verify_with_context(msg, ctx, &s) {
                Ok(())
            } else {
                Err("verify_with_context returned false".to_string())
            }
        }
        AlgId::MlDsa87 => {
            let enc =
                EncodedVerifyingKey::<MlDsa87>::try_from(pk).map_err(|_| "pk size".to_string())?;
            let vk = VerifyingKey::<MlDsa87>::decode(&enc);
            let s = MlDsaSig::<MlDsa87>::try_from(sig).map_err(|_| "sig size".to_string())?;
            if vk.verify_with_context(msg, ctx, &s) {
                Ok(())
            } else {
                Err("verify_with_context returned false".to_string())
            }
        }
        AlgId::SlhDsaShake128s => {
            let vk = SlhVk::<Shake128s>::try_from(pk).map_err(|_| "pk size".to_string())?;
            let s = slh_dsa::Signature::<Shake128s>::try_from(sig)
                .map_err(|_| "sig size".to_string())?;
            vk.try_verify_with_context(msg, ctx, &s)
                .map_err(|e| format!("try_verify_with_context: {e:?}"))
        }
        AlgId::SlhDsaShake192s => {
            let vk = SlhVk::<Shake192s>::try_from(pk).map_err(|_| "pk size".to_string())?;
            let s = slh_dsa::Signature::<Shake192s>::try_from(sig)
                .map_err(|_| "sig size".to_string())?;
            vk.try_verify_with_context(msg, ctx, &s)
                .map_err(|e| format!("try_verify_with_context: {e:?}"))
        }
        AlgId::SlhDsaShake256s => {
            let vk = SlhVk::<Shake256s>::try_from(pk).map_err(|_| "pk size".to_string())?;
            let s = slh_dsa::Signature::<Shake256s>::try_from(sig)
                .map_err(|_| "sig size".to_string())?;
            vk.try_verify_with_context(msg, ctx, &s)
                .map_err(|e| format!("try_verify_with_context: {e:?}"))
        }
        other => Err(format!("unsupported alg {other:?}")),
    }
}

/// Run every test case in `file` and update `stats` in place.
///
/// For `context == ""` cases the harness exercises the full
/// `PqVerifier::verify()` dispatch. For non-empty contexts the backend is
/// invoked directly with the context (wrapper does not plumb contexts —
/// see module docstring and README).
fn run_file(file: &VectorFile, stats: &mut Stats) {
    assert!(file.algorithm.starts_with("ML-DSA") || file.algorithm.starts_with("SLH-DSA"));
    assert!(
        matches!(file.revision.as_str(), "FIPS204" | "FIPS205"),
        "unexpected revision {}",
        file.revision
    );

    for g in &file.groups {
        let Some(alg) = alg_id_of(&g.parameter_set) else {
            println!(
                "[skip] unsupported parameter set {} (not in AlgId dispatch)",
                g.parameter_set
            );
            continue;
        };
        assert_eq!(
            g.test_type, "AFT",
            "only AFT groups are vetted by this harness"
        );

        for t in &g.tests {
            let pk = hex(&t.pk);
            let msg = hex(&t.message);
            let ctx = hex(&t.context);
            let sig = hex(&t.signature);

            let tag = format!(
                "{}/tcId={} (ctx_len={}, msg_len={}, expected_pass={})",
                g.parameter_set,
                t.tc_id,
                ctx.len(),
                msg.len(),
                t.test_passed,
            );

            if ctx.is_empty() {
                // Full wrapper dispatch
                let public = PublicKey {
                    alg_id: alg,
                    bytes: pk.clone(),
                };
                let signature = Signature {
                    alg_id: alg,
                    bytes: sig.clone(),
                };
                let result = PqVerifier.verify(&public, &msg, &signature);
                let verified = result.is_ok();
                if verified == t.test_passed {
                    stats.wrapper_ok += 1;
                    println!("[pass  wrapper] {tag}");
                } else {
                    let err = result
                        .err()
                        .map(|e| format!("{e:?}"))
                        .unwrap_or_else(|| "Ok".into());
                    let msg = format!(
                        "{tag}: expected_pass={} but wrapper returned verified={} ({err})",
                        t.test_passed, verified
                    );
                    println!("[FAIL  wrapper] {msg}");
                    stats.wrapper_failures.push(msg);
                }
            } else {
                stats.wrapper_skipped_ctx += 1;
                let result = backend_verify_with_ctx(alg, &pk, &msg, &ctx, &sig);
                let verified = result.is_ok();
                if verified == t.test_passed {
                    stats.backend_ok += 1;
                    println!("[pass  backend] {tag}");
                } else {
                    let err = result.err().unwrap_or_default();
                    let msg = format!(
                        "{tag}: expected_pass={} but backend returned verified={} ({err})",
                        t.test_passed, verified
                    );
                    println!("[FAIL  backend] {msg}");
                    stats.backend_failures.push(msg);
                }
            }
        }
    }
}

fn run_all(alg_dirs: &[&str]) {
    let mut stats = Stats::default();
    for d in alg_dirs {
        let file = load(d);
        println!(
            "\n=== {} {} ({} group{}) ===",
            file.algorithm,
            file.revision,
            file.groups.len(),
            if file.groups.len() == 1 { "" } else { "s" }
        );
        run_file(&file, &mut stats);
    }
    println!("\n---- ACVP conformance summary ----");
    println!("wrapper ok              : {}", stats.wrapper_ok);
    println!("wrapper ctx-skip→backend: {}", stats.wrapper_skipped_ctx);
    println!("  of which backend ok   : {}", stats.backend_ok);
    println!("wrapper failures        : {}", stats.wrapper_failures.len());
    println!("backend failures        : {}", stats.backend_failures.len());
    for f in &stats.wrapper_failures {
        println!("  wrapper FAIL: {f}");
    }
    for f in &stats.backend_failures {
        println!("  backend FAIL: {f}");
    }
    assert!(
        stats.wrapper_failures.is_empty(),
        "{} wrapper failures (see stdout)",
        stats.wrapper_failures.len()
    );
    assert!(
        stats.backend_failures.is_empty(),
        "{} backend failures (see stdout)",
        stats.backend_failures.len()
    );
}

#[test]
#[ignore = "acvp: run with `--ignored` — auditor evidence, not a gating test"]
fn ml_dsa_fips204_sigver_aft() {
    run_all(&["ml-dsa-44", "ml-dsa-65", "ml-dsa-87"]);
}

#[test]
#[ignore = "acvp: run with `--ignored` — auditor evidence, not a gating test"]
fn slh_dsa_fips205_shake_sigver_aft() {
    run_all(&[
        "slh-dsa-shake-128s",
        "slh-dsa-shake-192s",
        "slh-dsa-shake-256s",
    ]);
}

// SPDX-License-Identifier: Apache-2.0
//! In-memory Algorithm Registry — Phase 1 initial entries.
//!
//! This module holds the static baseline. Once the chain is running, the
//! authoritative registry lives in state storage; this is the genesis snapshot.
//!
//! SPEC-ACCOUNT-001 §7 — full field definitions.

use crate::alg::{AlgId, Lifecycle, SigClass};

/// Per-algorithm static parameters from the Algorithm Registry.
///
/// `spec_ref` accepts either a `&'static str` (for the phase-1 hardcoded
/// baseline) or an owned `String` (for governance-added entries landed via
/// `ProposalEffect::AddAlgorithm`, ADR-049). `std::borrow::Cow` is the natural
/// fit: callers who already had `&'static str` can use `Cow::Borrowed(...)`
/// (or the provided `From` impls) without any allocation, while governance
/// proposals that carry a runtime `String` use `Cow::Owned(...)`.
#[derive(Debug, Clone)]
pub struct AlgEntry {
    pub alg_id: AlgId,
    pub spec_ref: std::borrow::Cow<'static, str>,
    pub pk_size: usize,
    pub sig_size: usize,
    pub sig_class: Option<SigClass>, // None for KEM algorithms
    pub min_fee: u64,
    pub lifecycle: Lifecycle,
    /// Approximate single-core verify/s on reference hardware (AMD Ryzen 7 7700).
    /// Used for fee class calibration. Source: TESTING.md benchmark table.
    pub benchmark_verify_per_sec: u32,
}

impl AlgEntry {
    /// Construct an `AlgEntry` from an owned `String` spec_ref — used by the
    /// governance `AddAlgorithm` proposal (ADR-049). Callers who have a
    /// `&'static str` should construct the struct literal directly using
    /// `Cow::Borrowed(...)` or rely on the `From<&'static str>` impl on `Cow`.
    #[allow(clippy::too_many_arguments)]
    pub fn new_governance(
        alg_id: AlgId,
        spec_ref: String,
        pk_size: usize,
        sig_size: usize,
        sig_class: Option<SigClass>,
        min_fee: u64,
        lifecycle: Lifecycle,
        benchmark_verify_per_sec: u32,
    ) -> Self {
        Self {
            alg_id,
            spec_ref: std::borrow::Cow::Owned(spec_ref),
            pk_size,
            sig_size,
            sig_class,
            min_fee,
            lifecycle,
            benchmark_verify_per_sec,
        }
    }
}

/// Phase 1 initial Algorithm Registry.
///
/// All entries start as `Active`. Lifecycle changes require governance proposals
/// (SPEC-GOV-001 §5.1).
///
/// **FN-DSA-padded-512 caveat (post-audit 2026-05-11)**: the entry below is a
/// *reserved slot* for the FIPS 206 (FN-DSA / FALCON) draft. The verifier
/// returns `NotASigningAlgorithm` for `FnDsaPadded512` until the FIPS 206
/// standard is finalised and a Rust implementation lands (see
/// [`crate::verify::PqVerifier::verify`] FnDsa arm, GAP-01 in AUDIT-SCOPE-001
/// §6). The `Lifecycle::Active` label here is therefore *registry-level
/// reservation*, not *verifier-level operational readiness*. A transaction
/// signed with FnDsa is admitted to the mempool but **rejected at signature
/// verification before block inclusion** — so the slot does not actually
/// expose a signing capability, only reserves the `alg_id` codepoint.
///
/// The `Lifecycle` enum does not currently include a `Reserved` state; a
/// dedicated state would extend the lifecycle schema (consensus-relevant,
/// requires its own activation-height migration). Until then, the doc comment
/// is the authority on FN-DSA's operational status. The verifier reject path
/// is the actual safety property — see the
/// `fn_dsa_is_registered_but_verifier_rejects` integration test in
/// `verify.rs::pq_verifier_tests`.
pub fn phase1_registry() -> Vec<AlgEntry> {
    vec![
        AlgEntry {
            alg_id: AlgId::MlDsa44,
            spec_ref: std::borrow::Cow::Borrowed("FIPS 204"),
            pk_size: 1_312,
            sig_size: 2_420,
            sig_class: Some(SigClass::Standard),
            min_fee: 0,
            lifecycle: Lifecycle::Active,
            benchmark_verify_per_sec: 89_000,
        },
        AlgEntry {
            alg_id: AlgId::MlDsa65,
            spec_ref: std::borrow::Cow::Borrowed("FIPS 204"),
            pk_size: 1_952,
            sig_size: 3_309,
            sig_class: Some(SigClass::Standard),
            min_fee: 0,
            lifecycle: Lifecycle::Active,
            benchmark_verify_per_sec: 55_000,
        },
        AlgEntry {
            alg_id: AlgId::MlDsa87,
            spec_ref: std::borrow::Cow::Borrowed("FIPS 204"),
            pk_size: 2_592,
            sig_size: 4_627,
            sig_class: Some(SigClass::Standard),
            min_fee: 0,
            lifecycle: Lifecycle::Active,
            benchmark_verify_per_sec: 37_000,
        },
        // RESERVED SLOT — FIPS 206 (FN-DSA / FALCON) is still in draft.
        // The verifier rejects FnDsaPadded512 with NotASigningAlgorithm
        // (see verify.rs GAP-01 arm). Sizes below match the FIPS 206
        // draft parameters and stay reserved here so a future
        // `ProposalEffect::AddAlgorithm` governance vote can re-register
        // them without an enum change. See the module-level docstring
        // (Lifecycle::Active means "registered", not "implemented").
        //
        // **CONSENSUS-CRITICAL**: `spec_ref` is absorbed into the
        // alg-registry state-leaf hash at
        // `crates/pqc-state/src/store/state_merkle.rs:109`. Changing
        // this string changes the genesis state-root and breaks
        // cold-sync replay on every running chain. The verbose
        // "verifier returns NotASigningAlgorithm; reserved slot only"
        // qualification belongs in the module-level docstring + the
        // verifier-arm comment, NOT in this string literal. Do not
        // edit the bytes below without an ADR + activation-height
        // migration.
        AlgEntry {
            alg_id: AlgId::FnDsaPadded512,
            spec_ref: std::borrow::Cow::Borrowed("FIPS 206 (draft)"),
            pk_size: 897,
            sig_size: 666,
            sig_class: Some(SigClass::Reduced),
            min_fee: 0,
            lifecycle: Lifecycle::Active,
            benchmark_verify_per_sec: 62_000,
        },
        AlgEntry {
            alg_id: AlgId::SlhDsaSha2128s,
            spec_ref: std::borrow::Cow::Borrowed("FIPS 205"),
            pk_size: 32,
            sig_size: 7_856,
            sig_class: Some(SigClass::Premium),
            min_fee: 0,
            lifecycle: Lifecycle::Active,
            benchmark_verify_per_sec: 951,
        },
        AlgEntry {
            alg_id: AlgId::SlhDsaShake128s,
            spec_ref: std::borrow::Cow::Borrowed("FIPS 205"),
            pk_size: 32,
            sig_size: 7_856,
            sig_class: Some(SigClass::Premium),
            min_fee: 0,
            lifecycle: Lifecycle::Active,
            benchmark_verify_per_sec: 951,
        },
        AlgEntry {
            alg_id: AlgId::SlhDsaShake192s,
            spec_ref: std::borrow::Cow::Borrowed("FIPS 205"),
            pk_size: 48,
            sig_size: 16_224,
            sig_class: Some(SigClass::Premium),
            min_fee: 0,
            lifecycle: Lifecycle::Active,
            benchmark_verify_per_sec: 312, // approx: 192s is ~3x slower than 128s
        },
        AlgEntry {
            alg_id: AlgId::SlhDsaShake256s,
            spec_ref: std::borrow::Cow::Borrowed("FIPS 205"),
            pk_size: 64,
            sig_size: 29_792,
            sig_class: Some(SigClass::Premium),
            min_fee: 0,
            lifecycle: Lifecycle::Active,
            benchmark_verify_per_sec: 132, // approx
        },
        AlgEntry {
            alg_id: AlgId::MlKem768,
            spec_ref: std::borrow::Cow::Borrowed("FIPS 203"),
            pk_size: 1_184,
            sig_size: 0,     // KEM ciphertext is 1,088 B; not a signature size
            sig_class: None, // not a signing algorithm
            min_fee: 0,
            lifecycle: Lifecycle::Active,
            benchmark_verify_per_sec: 0,
        },
    ]
}

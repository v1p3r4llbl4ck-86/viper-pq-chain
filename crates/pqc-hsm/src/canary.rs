// SPDX-License-Identifier: BUSL-1.1
//! Canary preimage for boot-time signer self-test.
//!
//! Per `HSM-PHASE-PLAN.md` §"Boot-time validation": at startup, every
//! configured `CommitSigner` signs `CANARY_PREIMAGE` and verifies the
//! signature against its cached pubkey. A mismatch surfaces a
//! mis-wired HSM credential, a stale seed, or a backend-version
//! mismatch — all of which are better caught at boot than at first
//! block production (where they produce a quorum-loss with no
//! actionable diagnostic).
//!
//! The constant is part of the public API so test fixtures and the
//! `viper-hsm-probe` stretch binary can re-use the exact same bytes.

/// Fixed preimage signed during `CommitSigner::self_test`. The string
/// is intentionally specific — a backend that auto-canaries with a
/// different domain prefix MUST NOT collide with this one.
///
/// Versioned (`-V1`) so a future breaking change to the self-test shape
/// can be coordinated by bumping the suffix without falsely signaling a
/// pubkey mismatch on still-correct legacy backends.
pub const CANARY_PREIMAGE: &[u8] = b"VIPER-HSM-CANARY-V1";

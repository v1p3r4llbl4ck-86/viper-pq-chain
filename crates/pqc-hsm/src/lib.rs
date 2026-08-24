// SPDX-License-Identifier: BUSL-1.1
//! Validator commit-signing abstraction — HSM-friendly trait surface.
//!
//! See the private design notes for the full phase plan and
//! the private design notes for the ops runbook this
//! crate plugs into. This crate is the post-Phase-4 trait scaffolding:
//! it consolidates the existing in-process commit-signing path
//! (previously living scattered between `pqcd::keystore` and
//! `pqcd::devnet::snapshot_block_signers`) into a `CommitSigner` trait
//! that admits drop-in implementations for SoftHSM (PKCS#11), AWS
//! CloudHSM, and future YubiHSM / Thales backends.
//!
//! # Status
//!
//! - **`CommitSigner` trait + `SignerError` + `SignerKind` + `SignerConfig`**
//!   (this commit) — the trait surface and config types. No backend
//!   impls yet; those land in subsequent commits.
//! - **`LocalKeystoreSigner`** — refactor of the in-process ML-DSA
//!   signing path into the trait. Lands next.
//! - **`SoftHsmSigner` / `AwsCloudHsmSigner`** — stretch / future.
//!
//! # Boot-time self-test
//!
//! `CommitSigner::self_test` signs the canary preimage `CANARY_PREIMAGE`
//! and verifies the signature against the cached pubkey. The pqcd
//! daemon calls this at startup before consensus loops spin up; failure
//! exits the process non-zero with a clear message tied to the
//! `SignerKind` and config that caused the mismatch. This catches a
//! mis-wired HSM or a stale seed at boot rather than at first block
//! production.

#![cfg_attr(not(test), deny(unsafe_code))]

pub mod canary;
pub mod config;
pub mod error;
pub mod local;
pub mod signer;

#[cfg(feature = "softhsm")]
pub mod softhsm;

pub use canary::CANARY_PREIMAGE;
pub use config::{SignerConfig, SignerKind};
pub use error::SignerError;
pub use local::LocalKeystoreSigner;
pub use signer::CommitSigner;

#[cfg(feature = "softhsm")]
pub use softhsm::SoftHsmSigner;

/// Re-export `AlgId` so call sites consuming `CommitSigner::alg_id`
/// don't need a separate `use pqc_crypto::AlgId`.
pub use pqc_crypto::AlgId;

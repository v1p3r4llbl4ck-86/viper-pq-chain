// SPDX-License-Identifier: BUSL-1.1
//! Mempool rejection errors.
//!
//! Wraps TxError for admission failures and adds mempool-specific rejections.

use pqc_tx::TxError;
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum MempoolError {
    /// Transaction failed the validation pipeline (SPEC-TX-001 §8).
    #[error("validation failed: {0}")]
    ValidationFailed(#[from] TxError),

    /// Duplicate: exact same raw bytes already in the pool.
    #[error("DUPLICATE: identical transaction is already in the mempool")]
    Duplicate,

    /// Same (sender, nonce) exists but replacement conditions not met — SPEC-FEE-001 §11.
    /// new_fee must be ≥ old_fee × 1.10 AND new_tip ≥ old_tip.
    #[error(
        "REPLACEMENT_UNDERPRICED: existing tx fee={existing_fee} tip={existing_tip}; \
         new tx must have fee ≥ {min_required_fee} and tip ≥ {existing_tip}"
    )]
    ReplacementUnderpriced {
        existing_fee: u64,
        existing_tip: u64,
        min_required_fee: u64,
    },

    /// Same (sender, nonce) exists and is already included in a finalized block.
    #[error("ALREADY_INCLUDED: a transaction with this (sender, nonce) is already finalized")]
    AlreadyIncluded,

    /// Per-sender verify budget exhausted for this time window — SPEC-FEE-001 §10.1.
    #[error("RATE_LIMITED: per-sender verify budget exceeded for this window")]
    RateLimited,

    /// V-C (SLH-DSA) per-block admission cap reached — SPEC-FEE-001 §10.2.
    #[error("VC_CAP_REACHED: V-C algorithm per-block admission cap is full")]
    VcCapReached,
}

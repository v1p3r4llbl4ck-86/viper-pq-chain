// SPDX-License-Identifier: Apache-2.0
//! Transaction validation rejection codes.
//!
//! Each variant corresponds to a named rejection in SPEC-TX-001 §8.
//! The ordering of checks in the validation pipeline is:
//!   structural → pre-crypto → cryptographic → economic

use pqc_types::keyset::KeyLookupError;
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TxError {
    // ── Structural (steps 1-4) ──────────────────────────────────────────────
    #[error("ENCODING_INVALID: transaction is not valid deterministic CBOR")]
    EncodingInvalid,

    #[error("VERSION_UNSUPPORTED: tx_version {0} is not supported")]
    VersionUnsupported(u8),

    #[error("CHAIN_ID_MISMATCH: chain_id does not match this network")]
    ChainIdMismatch,

    #[error("MSG_TYPE_UNKNOWN: msg_type 0x{0:04x} is not a known operation")]
    MsgTypeUnknown(u16),

    // ── Pre-crypto (steps 5-7) ──────────────────────────────────────────────
    #[error("ALGORITHM_NOT_FOUND: alg_id 0x{0:04x} is not in the Algorithm Registry")]
    AlgorithmNotFound(u16),

    #[error("ALGORITHM_BANNED: alg_id 0x{0:04x} is banned; transaction rejected at mempool")]
    AlgorithmBanned(u16),

    #[error("SENDER_NOT_FOUND: no account for sender address")]
    SenderNotFound,

    // ── Key lookup (step 8) ──────────────────────────────────────────────────
    #[error("KEY_LOOKUP_FAILED: {0}")]
    KeyLookupFailed(#[from] KeyLookupError),

    // ── Cryptographic (step 9) ───────────────────────────────────────────────
    #[error("SIGNATURE_INVALID: signature does not verify against the signed preimage")]
    SignatureInvalid,

    // ── Replay / ordering (steps 10-11) ─────────────────────────────────────
    #[error("NONCE_INVALID: expected nonce {expected}, got {got}")]
    NonceInvalid { expected: u64, got: u64 },

    // ── Economic (steps 12-15) ───────────────────────────────────────────────
    #[error("FEE_INSUFFICIENT: fee {paid} < required {required} (base={base} bytes={bytes} sigverify={sigverify} exec={exec})")]
    FeeInsufficient {
        paid: u64,
        required: u64,
        base: u64,
        bytes: u64,
        sigverify: u64,
        exec: u64,
    },

    #[error("GAS_LIMIT_TOO_LOW: gas_limit {0} is below the operation minimum")]
    GasLimitTooLow(u64),

    #[error("BALANCE_INSUFFICIENT: balance {balance} < fee {fee}")]
    BalanceInsufficient { balance: u128, fee: u128 },

    #[error("VERIFY_BUDGET_EXCEEDED: per-sender verify budget for this minute is exhausted")]
    VerifyBudgetExceeded,

    // ── Size cap (step 1 — checked before crypto) ────────────────────────────
    /// Raw transaction bytes exceed the hard 1 MiB cap — SPEC-TX-001 §5.9.
    ///
    /// The cap is enforced before signature verification so an oversized payload
    /// cannot be used as a cheap CPU-exhaustion vector even when fees are non-zero.
    #[error("TX_TOO_LARGE: transaction is {0} bytes; maximum is 1 MiB (1 048 576 bytes)")]
    TxTooLarge(usize),

    // ── Payload (step 15) ────────────────────────────────────────────────────
    #[error("PAYLOAD_INVALID: operation payload failed schema validation")]
    PayloadInvalid(String),

    // ── AIMD fee market (SPEC-FEE-002 §8.1) ─────────────────────────────────
    /// Transaction fee is below the current adaptive market minimum for its lane.
    #[error("FEE_BELOW_MARKET: fee {provided} < market minimum {required}")]
    FeeBelowMarket { required: u64, provided: u64 },
}

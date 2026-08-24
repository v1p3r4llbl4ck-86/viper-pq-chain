// SPDX-License-Identifier: Apache-2.0
//! `StateView` — read-only state interface for mempool admission.
//!
//! Defined in pqc-tx (not pqc-state) to avoid a circular dependency:
//!   pqc-mempool → pqc-tx (for validation) → ok
//!   pqc-mempool → pqc-state (for StateView impl) → ok
//!   pqc-state   → pqc-mempool (would be circular) → FORBIDDEN
//!
//! pqc-state implements this trait; pqc-mempool calls it.

use pqc_crypto::{AlgId, Lifecycle, SigClass};
use pqc_types::account::{Account, Address};
use pqc_types::ForkDigest;

/// Read-only view of chain state required for mempool admission decisions.
///
/// Implementations: `pqc_state::StateStore` (in-memory), future RocksDB backend.
/// Test doubles implement this trait directly without any real state storage.
pub trait StateView: Send + Sync {
    fn get_account(&self, addr: &Address) -> Option<&Account>;
    fn alg_lifecycle(&self, alg_id: AlgId) -> Option<Lifecycle>;
    fn alg_sig_class(&self, alg_id: AlgId) -> Option<SigClass>;
    fn alg_min_fee(&self, alg_id: AlgId) -> Option<u64>;
    fn chain_id(&self) -> &[u8];
    fn current_height(&self) -> u64;

    /// Return the current AIMD adaptive base fee from `FeeMarketState` — SPEC-FEE-002 §6.
    ///
    /// Default returns 0; the live `StateStore` implementation overrides this.
    /// When the return value is 0, callers fall back to `FeeParams.base_fee`.
    fn base_fee_dynamic(&self) -> u64 {
        0
    }

    /// Return the active fork digest for this chain (ADR-053 §T1.2).
    ///
    /// Default is [`ForkDigest::viper_research_1`]. Test doubles and the
    /// live `StateStore` can override to supply a real genesis-derived digest
    /// once chain-config wiring lands. Every mempool admission and every
    /// tx-signature verification path pulls the digest from here, so updating
    /// the returned value is the single switch that rotates the signing
    /// domain across the node.
    fn fork_digest(&self) -> ForkDigest {
        ForkDigest::viper_research_1()
    }
}

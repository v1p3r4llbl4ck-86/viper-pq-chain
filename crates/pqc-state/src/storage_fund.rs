// SPDX-License-Identifier: BUSL-1.1
//! Storage fund state — ADR-053 §T2.2 + §T3.3 / SPEC-FEE-002 revised.
//!
//! Sui-style storage economics: every state-growing transaction pays an
//! upfront `storage_fee = bytes × perpetual_cost_per_byte` into a
//! chain-wide `storage_fund`. The fund is stake-delegated to the active
//! validator set, which earns its yield as storage rewards — that yield
//! pays for the perpetual storage burden a newly-created state entry
//! imposes on every future validator. When a state entry is deleted, a
//! fraction `rebate_fraction_bps / 10_000` of the original contribution
//! is returned to the originator (storage rebate).
//!
//! This aligns long-term storage cost with validator economics without
//! rent (Ethereum's state-expiry research) or free-rider externalities
//! (unlimited-lifetime state paid for once at creation). It is strongly
//! aligned with Viper's notary thesis: a user notarising an attestation
//! in 2026 pays once and the chain carries the commitment forever.
//!
//! This commit lands the *shape* at genesis — the struct, leaf hash,
//! state-root inclusion, and helper formulas — so the on-chain data
//! model is fixed from day one. Wiring storage-fee debits into the tx
//! validation path and storage-rebate credits into the delete path is a
//! follow-up patch tracked under ADR-053 §T2.2 implementation notes;
//! the framework being stable at genesis is what ADR-053 Tier 2
//! requires (P-COMPAT-001 §2 permits adding behaviour via activation
//! height later, but changing the state model would force a state-
//! migration).

/// Default perpetual cost per byte of state growth (venom per byte).
///
/// Governance-tunable (SPEC-FEE-002 revised §7.1). Set conservatively
/// so that a 1 KB attestation costs ≈ 1000 venom at launch; the ratio
/// relative to the compute base fee reserve floor keeps storage and
/// compute pricing within the same order of magnitude.
pub const DEFAULT_PERPETUAL_COST_PER_BYTE: u64 = 1;

/// Default storage rebate in basis points — fraction of the original
/// contribution returned to the originator on state deletion.
///
/// Sui chose 9_900 bps (99%) in their launch parameters, reasoning that
/// the small residual (1%) funds the net perpetual-yield draw from the
/// window in which the state was live. Viper mirrors that choice;
/// governance can adjust under SPEC-FEE-002 revised §7.3.
pub const DEFAULT_REBATE_FRACTION_BPS: u16 = 9_900;

/// Fixed-point denominator for `rebate_fraction_bps`.
pub const REBATE_BPS_DENOM: u64 = 10_000;

/// Storage fund state — ADR-053 §T2.2.
///
/// Included in `state_root` under the `"VIPER-STORAGE-FUND-V1"` leaf
/// domain. Field layout is stable from genesis: any reordering or
/// addition requires an ADR + dual-path decoder per P-COMPAT-001.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StorageFundState {
    /// Accumulated fund balance (venom). Grows on state-create, shrinks
    /// on state-delete rebates. Always >= 0 (saturating arithmetic).
    pub balance: u128,
    /// Governance-tunable cost per byte of created state (venom/byte).
    pub perpetual_cost_per_byte: u64,
    /// Rebate share on deletion, basis points of original contribution
    /// (9_900 = 99%).
    pub rebate_fraction_bps: u16,
}

impl Default for StorageFundState {
    fn default() -> Self {
        Self {
            balance: 0,
            perpetual_cost_per_byte: DEFAULT_PERPETUAL_COST_PER_BYTE,
            rebate_fraction_bps: DEFAULT_REBATE_FRACTION_BPS,
        }
    }
}

impl StorageFundState {
    /// Compute the upfront storage fee for a state entry of `bytes`
    /// payload size. Saturating on `u128` overflow — no realistic input
    /// size approaches the limit, but we guard it for fuzz robustness.
    pub fn storage_fee(&self, bytes: u64) -> u128 {
        (bytes as u128).saturating_mul(self.perpetual_cost_per_byte as u128)
    }

    /// Compute the rebate owed on deletion of a state entry whose
    /// original storage fee was `original_fee`.
    pub fn storage_rebate(&self, original_fee: u128) -> u128 {
        original_fee.saturating_mul(self.rebate_fraction_bps as u128) / REBATE_BPS_DENOM as u128
    }

    /// Credit the fund (state-create path). Saturating add on `u128`.
    pub fn credit(&mut self, amount: u128) {
        self.balance = self.balance.saturating_add(amount);
    }

    /// Debit the fund (state-delete rebate path). Saturating sub —
    /// balance cannot go negative. Returns the amount actually debited
    /// (capped at current balance).
    pub fn debit(&mut self, amount: u128) -> u128 {
        let debit = amount.min(self.balance);
        self.balance -= debit;
        debit
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_launch_parameters() {
        let s = StorageFundState::default();
        assert_eq!(s.balance, 0);
        assert_eq!(s.perpetual_cost_per_byte, DEFAULT_PERPETUAL_COST_PER_BYTE);
        assert_eq!(s.rebate_fraction_bps, DEFAULT_REBATE_FRACTION_BPS);
    }

    #[test]
    fn storage_fee_linear_in_bytes() {
        let s = StorageFundState::default();
        assert_eq!(s.storage_fee(0), 0);
        assert_eq!(s.storage_fee(1), DEFAULT_PERPETUAL_COST_PER_BYTE as u128);
        assert_eq!(
            s.storage_fee(1_024),
            (1_024u128) * DEFAULT_PERPETUAL_COST_PER_BYTE as u128
        );
    }

    #[test]
    fn storage_rebate_is_99_pct_by_default() {
        let s = StorageFundState::default();
        assert_eq!(s.storage_rebate(10_000), 9_900);
        assert_eq!(s.storage_rebate(1), 0); // integer truncation for tiny values
    }

    #[test]
    fn credit_and_debit_are_saturating() {
        let mut s = StorageFundState::default();
        s.credit(100);
        assert_eq!(s.balance, 100);
        // Saturating add — does not panic on overflow.
        s.credit(u128::MAX);
        assert_eq!(s.balance, u128::MAX);
        // Saturating sub — balance floors at zero, debit capped.
        let debited = s.debit(u128::MAX / 2);
        assert_eq!(debited, u128::MAX / 2);
        let more = s.debit(u128::MAX);
        assert!(more <= s.balance + more, "debit caps at remaining balance");
        s.balance = 50;
        let overdraw = s.debit(100);
        assert_eq!(overdraw, 50, "debit caps at balance");
        assert_eq!(s.balance, 0);
    }

    #[test]
    fn storage_fee_saturates_on_pathological_bytes() {
        let s = StorageFundState {
            perpetual_cost_per_byte: u64::MAX,
            ..StorageFundState::default()
        };
        let _ = s.storage_fee(u64::MAX); // must not panic
    }
}

// SPDX-License-Identifier: Apache-2.0
//! Stake-weighted validator churn parameters — ADR-053 §T1.5.
//!
//! Replaces the devnet-era count-based `max(4, active_count / 256)`
//! activation cap (TASK-113) and its companion `max(4, active/32)` exit
//! cap with a limit expressed as a fraction of total Active self-bond.
//! Ethereum learned this the hard way: EIP-7514 shipped a count-based
//! activation cap, then EIP-7251 had to rewrite it to stake-weighted and
//! re-derive the slashing formula. Doing the equivalent rewrite
//! post-launch requires both a spec change and a slashing migration;
//! paying the cost at genesis is ~50 LOC.
//!
//! The per-epoch limit is
//!
//! ```text
//! limit_stake = max(min_stake, active_stake * target_bps / 10_000)
//! ```
//!
//! and the caller iterates the candidate queue in FIFO order accumulating
//! self-bond until the next candidate would push the running total past
//! the limit. The accumulation loop SHOULD also enforce a "progress
//! guarantee" (activate at least one candidate when the queue is
//! non-empty) so a freshly-bootstrapped network whose `active_stake` is
//! still zero is never stuck.
//!
//! This struct lives in `pqc-types` so both `pqc-consensus` (engine
//! configuration) and `pqc-state` (epoch transition application) can
//! depend on it without pulling in each other.

/// Stake-weighted churn parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChurnConfig {
    /// Target activation churn in basis points of total Active self-bond.
    pub activation_target_bps: u16,
    /// Absolute floor for the activation stake limit (venom units).
    /// Ensures small networks can still activate validators even when
    /// `active_stake * target_bps / 10_000` rounds to near-zero.
    pub activation_min_stake: u128,
    /// Target exit churn in basis points of total Active self-bond.
    pub exit_target_bps: u16,
    /// Absolute floor for the exit stake limit (venom units).
    pub exit_min_stake: u128,
}

impl ChurnConfig {
    /// `viper-pq-1` genesis defaults — equivalent bps to the previous
    /// count-based `active/256` (activations, 39 bps) and `active/32`
    /// (exits, 313 bps), assuming roughly equal stake per validator.
    /// `min_stake` defaults to 0; a future governance-tunable patch will
    /// make these on-chain parameters (Tier 2 follow-up).
    pub const fn viper_pq_1() -> Self {
        Self {
            activation_target_bps: 39,
            activation_min_stake: 0,
            exit_target_bps: 313,
            exit_min_stake: 0,
        }
    }
}

impl Default for ChurnConfig {
    fn default() -> Self {
        Self::viper_pq_1()
    }
}

/// Stake-weighted per-epoch activation limit.
///
/// See the module docs for the progress-guarantee contract on the
/// caller side (activate at least one candidate if the queue is
/// non-empty).
pub fn stake_weighted_activation_limit(active_stake: u128, cfg: &ChurnConfig) -> u128 {
    let scaled = active_stake.saturating_mul(cfg.activation_target_bps as u128) / 10_000;
    std::cmp::max(cfg.activation_min_stake, scaled)
}

/// Stake-weighted per-epoch exit limit.
pub fn stake_weighted_exit_limit(active_stake: u128, cfg: &ChurnConfig) -> u128 {
    let scaled = active_stake.saturating_mul(cfg.exit_target_bps as u128) / 10_000;
    std::cmp::max(cfg.exit_min_stake, scaled)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn viper_pq_1_defaults() {
        let cfg = ChurnConfig::viper_pq_1();
        assert_eq!(cfg.activation_target_bps, 39);
        assert_eq!(cfg.exit_target_bps, 313);
        assert_eq!(cfg.activation_min_stake, 0);
        assert_eq!(cfg.exit_min_stake, 0);
    }

    #[test]
    fn activation_limit_scales_with_active_stake() {
        let cfg = ChurnConfig::viper_pq_1();
        assert_eq!(stake_weighted_activation_limit(0, &cfg), 0);
        // 1_000_000 × 39 / 10_000 = 3_900
        assert_eq!(stake_weighted_activation_limit(1_000_000, &cfg), 3_900);
        // 100_000_000 × 39 / 10_000 = 390_000
        assert_eq!(stake_weighted_activation_limit(100_000_000, &cfg), 390_000);
    }

    #[test]
    fn exit_limit_is_wider_than_activation_limit() {
        let cfg = ChurnConfig::viper_pq_1();
        let s = 1_000_000u128;
        assert!(stake_weighted_exit_limit(s, &cfg) > stake_weighted_activation_limit(s, &cfg));
    }

    #[test]
    fn min_stake_floor_dominates_for_small_networks() {
        let cfg = ChurnConfig {
            activation_target_bps: 10,
            activation_min_stake: 50_000,
            exit_target_bps: 10,
            exit_min_stake: 50_000,
        };
        // 1_000_000 × 10 / 10_000 = 1_000 < 50_000 floor.
        assert_eq!(stake_weighted_activation_limit(1_000_000, &cfg), 50_000);
        // 100_000_000 × 10 / 10_000 = 100_000 > 50_000 floor.
        assert_eq!(stake_weighted_activation_limit(100_000_000, &cfg), 100_000);
    }

    #[test]
    fn saturates_at_u128_max() {
        let cfg = ChurnConfig::viper_pq_1();
        // Must not panic on multiplication overflow.
        let _ = stake_weighted_activation_limit(u128::MAX, &cfg);
        let _ = stake_weighted_exit_limit(u128::MAX, &cfg);
    }
}

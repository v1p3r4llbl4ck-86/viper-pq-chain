// SPDX-License-Identifier: BUSL-1.1
//! Epoch model — ADR-042.
//!
//! An epoch is a fixed window of blocks at the boundary of which the validator
//! set transitions (activations, exits) are applied deterministically.
//!
//! Proposer selection uses RANDAO + height-based sortition (v1).
//! EC-VRF is intentionally not used — it is broken by Shor.

/// Default epoch duration for mainnet (~1h at 500ms/block).
pub const EPOCH_DURATION_MAINNET: u64 = 7_200;
/// Default epoch duration for testnet (~6h at 500ms/block).
pub const EPOCH_DURATION_TESTNET: u64 = 43_200;
/// Default epoch duration for devnet (~30s at 500ms/block, fast iteration).
pub const EPOCH_DURATION_DEVNET: u64 = 60;
/// Minimum epoch duration enforced by governance.
///
/// Per consensus.md §5.1 (SPEC-CONSENSUS-001 §5.1, line 98):
///   epoch_duration_floor = 4 × finality_time_blocks
///
/// At the spec default of 1-second block time with ~60-block finality
/// (approximately 1 minute), this yields:
///   epoch_duration_floor = 4 × 60 = 240 blocks
///
/// This implementation enforces a MORE CONSERVATIVE floor of 1800 blocks
/// (approximately 30 minutes at 1-second block time) to provide:
/// - Additional margin for evidence submission before validator set transitions
/// - Buffer for cross-network validator set propagation delays
/// - Operational safety during early testnet phases
///
/// Governance parameter validation MUST reject any epoch_duration_blocks < 1800.
/// This stricter floor is spec-compliant: it exceeds the minimum required by
/// consensus.md §5.1 line 111: "Reducing epoch_duration_blocks below
/// epoch_duration_floor MUST be rejected by the governance execution layer."
pub const EPOCH_DURATION_MIN: u64 = 1_800;

pub use pqc_types::{stake_weighted_activation_limit, stake_weighted_exit_limit, ChurnConfig};

/// Configuration for epoch and churn behavior.
#[derive(Debug, Clone)]
pub struct EpochConfig {
    /// Number of blocks per epoch.
    pub epoch_duration: u64,
    /// Unbonding period in blocks.
    /// Mainnet default: 21 days × 86400s / 0.5s = 3_628_800 blocks.
    /// Devnet default: 120 blocks (~60s).
    pub unbonding_period: u64,
    /// Stake-weighted churn parameters (ADR-053 §T1.5).
    pub churn: ChurnConfig,
}

impl EpochConfig {
    pub fn mainnet() -> Self {
        Self {
            epoch_duration: EPOCH_DURATION_MAINNET,
            unbonding_period: 3_628_800,
            churn: ChurnConfig::viper_pq_1(),
        }
    }

    pub fn devnet() -> Self {
        Self {
            epoch_duration: EPOCH_DURATION_DEVNET,
            unbonding_period: 120,
            churn: ChurnConfig::viper_pq_1(),
        }
    }
}

impl Default for EpochConfig {
    fn default() -> Self {
        Self::devnet()
    }
}

/// Derived epoch information for a given block height.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpochInfo {
    pub epoch_number: u64,
    pub start_height: u64,
    pub end_height: u64,
    pub epoch_duration: u64,
}

impl EpochInfo {
    pub fn for_height(height: u64, epoch_duration: u64) -> Self {
        let epoch_number = height / epoch_duration;
        let start_height = epoch_number * epoch_duration;
        Self {
            epoch_number,
            start_height,
            end_height: start_height + epoch_duration.saturating_sub(1),
            epoch_duration,
        }
    }
}

/// Returns true if `height` is an epoch boundary (start of a new epoch).
/// Height 0 (genesis) is never a boundary.
pub fn is_epoch_boundary(height: u64, epoch_duration: u64) -> bool {
    height > 0 && height.is_multiple_of(epoch_duration)
}

/// Returns the epoch number for a given height.
pub fn epoch_for_height(height: u64, epoch_duration: u64) -> u64 {
    height / epoch_duration
}

/// Select the block proposer using RANDAO + height-based sortition.
///
/// v1 implementation: deterministic selection based on SHAKE-256 of
/// (randao_accumulator || height_be64). No EC-VRF (broken by Shor).
///
/// Returns the index into `validators` of the selected proposer.
/// Returns None if `validators` is empty.
pub fn select_epoch_proposer(
    validators: &[[u8; 32]],
    height: u64,
    randao_accumulator: &[u8; 32],
) -> Option<usize> {
    if validators.is_empty() {
        return None;
    }
    use pqc_crypto::shake256_32;
    let mut input = Vec::with_capacity(32 + 8);
    input.extend_from_slice(randao_accumulator);
    input.extend_from_slice(&height.to_be_bytes());
    let hash = shake256_32(&input);
    // Use first 8 bytes as u64 for modular selection.
    let idx_raw = u64::from_be_bytes(hash[0..8].try_into().unwrap());
    Some((idx_raw % validators.len() as u64) as usize)
}

/// Advance the RANDAO accumulator by mixing in the latest block hash.
///
/// Formula (ADR-053 §T2.4 BIP340 double-tagged):
/// `new_randao = tagged_hash("VIPER-RANDAO-V1", prev_randao || block_hash)`.
pub fn advance_randao(prev: &[u8; 32], block_hash: &[u8; 32]) -> [u8; 32] {
    let mut body = [0u8; 64];
    body[..32].copy_from_slice(prev);
    body[32..].copy_from_slice(block_hash);
    pqc_crypto::tagged_hash(b"VIPER-RANDAO-V1", &body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_boundary_detection() {
        assert!(!is_epoch_boundary(0, 60));
        assert!(!is_epoch_boundary(59, 60));
        assert!(is_epoch_boundary(60, 60));
        assert!(!is_epoch_boundary(61, 60));
        assert!(is_epoch_boundary(120, 60));
    }

    #[test]
    fn epoch_for_height_correct() {
        assert_eq!(epoch_for_height(0, 60), 0);
        assert_eq!(epoch_for_height(59, 60), 0);
        assert_eq!(epoch_for_height(60, 60), 1);
        assert_eq!(epoch_for_height(119, 60), 1);
        assert_eq!(epoch_for_height(120, 60), 2);
    }

    #[test]
    fn randao_advance_is_deterministic() {
        let prev = [0u8; 32];
        let block_hash = [1u8; 32];
        let r1 = advance_randao(&prev, &block_hash);
        let r2 = advance_randao(&prev, &block_hash);
        assert_eq!(r1, r2);
        assert_ne!(r1, [0u8; 32]);
    }

    #[test]
    fn proposer_selection_within_bounds() {
        let validators: Vec<[u8; 32]> = (0..5).map(|i| [i; 32]).collect();
        let randao = [42u8; 32];
        for h in 0..100 {
            let idx = select_epoch_proposer(&validators, h, &randao).unwrap();
            assert!(idx < 5);
        }
    }

    #[test]
    fn proposer_selection_empty_validators() {
        assert_eq!(select_epoch_proposer(&[], 1, &[0u8; 32]), None);
    }
}

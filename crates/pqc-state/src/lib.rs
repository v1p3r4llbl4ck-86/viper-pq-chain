// SPDX-License-Identifier: BUSL-1.1
//! pqc-state — State machine and operation execution.
//!
//! Applies validated transactions to chain state.
//! Operation implementations follow SPEC-OPS-001.

pub mod apply;
pub mod error;
pub mod gas_schedule;
#[cfg(feature = "token_economics")]
pub mod storage_fund;
pub mod store;
pub mod upgrade;

pub use apply::validator::{
    encode_empty_validator_payload, encode_register_payload, encode_rotate_peer_id_payload,
};
pub use apply::{
    check_pending_upgrades, distribute_block_fees, process_governance_tallies, ExecutionContext,
    ExecutionResult, ExecutionStatus, FeeDistributionParams,
};
pub use error::ApplyError;
pub use gas_schedule::{
    scheduled_gas_for_msg_type, scheduled_gas_for_tx, GAS_ATTESTATION_CREATE,
    GAS_GOVERNANCE_PROPOSAL, GAS_KEY_ADD, GAS_KEY_REVOKE, GAS_KEY_ROTATE, GAS_TOKEN_TRANSFER,
    GAS_VAULT_CREATE,
};
#[cfg(feature = "token_economics")]
pub use storage_fund::{
    StorageFundState, DEFAULT_PERPETUAL_COST_PER_BYTE, DEFAULT_REBATE_FRACTION_BPS,
    REBATE_BPS_DENOM,
};
pub use store::{
    fake_exponential, FeeMarketDimension, FeeMarketState, StateStore, VerifierRegistryEntry,
    BASE_FEE_MAX, BASE_FEE_MIN, COMPUTE_FEE_UPDATE_FRACTION, COMPUTE_RESERVE_FLOOR,
    DEFAULT_BASE_FEE, DEFAULT_BLOCK_GAS_LIMIT, DEFAULT_COMPUTE_TARGET,
};
pub use upgrade::{global_registry, UpgradeHandler, UpgradeRegistry};

#[cfg(test)]
mod tests;

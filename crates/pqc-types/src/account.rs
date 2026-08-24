// SPDX-License-Identifier: Apache-2.0
//! Account state — SPEC-ACCOUNT-001 §2.

use crate::keyset::KeySet;

/// Verifier template id for the default EOA-equivalent account
/// (ADR-053 §T3.5).
///
/// Every account at viper-pq-1 genesis ships with this template; semantically
/// it preserves the pre-genesis behaviour — a transaction is authentic iff
/// its signature validates under one of the active keys in [`Account::keys`].
/// The `auth_data` slot is REQUIRED to be empty for accounts on this template;
/// any inbound tx carrying non-empty `auth_data` against an EOA-template
/// account MUST be rejected at apply-time.
pub const VERIFIER_TEMPLATE_ID_EOA: u16 = 0x0001;

/// Inclusive upper bound of the protocol-reserved verifier-template id range
/// (ADR-053 §T3.5). Genesis ships only with [`VERIFIER_TEMPLATE_ID_EOA`];
/// future protocol-defined templates may be added to this range only via a
/// hard fork. Governance-added templates (via
/// `ProposalEffect::AddAuthTemplate`) MUST take an id ≥
/// [`VERIFIER_TEMPLATE_GOV_MIN`].
pub const VERIFIER_TEMPLATE_CORE_RESERVED_MAX: u16 = 0x000F;

/// Inclusive lower bound of the governance-allocatable verifier-template id
/// range (ADR-053 §T3.5).
pub const VERIFIER_TEMPLATE_GOV_MIN: u16 = 0x0010;

/// 32-byte account address.
///
/// Derived from initial public key material at account creation time.
/// Immutable for the lifetime of the account.
///
/// Derivation (ADR-053 §T1.3 — viper-pq-1):
///   `SHAKE-256("VIPER-ADDR-V1" || chain_id || uint16_be(alg_id) || pk_bytes, 32)`
///
/// The `chain_id` binding makes the same public key resolve to a different
/// address on any other host chain, delivering cross-chain replay resistance
/// at the address layer (in addition to the signing-domain separation at the
/// preimage layer — ADR-053 §T1.2).
///
/// Note (TASK-177): `key_version` is NOT part of the derivation. Earlier
/// drafts of the spec included `uint32_be(key_version)` as a third input,
/// but the implementation in `pqc-crypto/src/address.rs::derive_address`
/// has always bound only `(alg_id, pk_bytes)`. Including `key_version`
/// would forbid two keys with the same (alg_id, pk_bytes) at different
/// versions from ever sharing an address.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Address(pub [u8; 32]);

impl Address {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// On-chain account state — SPEC-ACCOUNT-001 §2.1.
#[derive(Debug, Clone)]
pub struct Account {
    pub address: Address,
    /// Native token balance in base units (u128 — fits any realistic supply).
    pub balance: u128,
    /// Monotonically increasing anti-replay counter. Starts at 0.
    /// Incremented on every accepted transaction from this sender.
    pub nonce: u64,
    /// All keys ever associated with this account, including revoked ones.
    /// Revoked keys are retained for audit; they are never removed.
    pub keys: KeySet,
    /// Monotonically increasing vault policy version. `0` means no policy set.
    /// Incremented by `vault_policy_update`; protects against policy replay.
    /// SPEC-OPS-001 §5.2.
    pub policy_version: u32,
    /// SHAKE-256 digest of the current off-chain vault policy document.
    /// `None` when `policy_version = 0` (no policy has been committed).
    pub policy_hash: Option<[u8; 32]>,
    /// ADR-053 §T3.5 unified smart-account model: the on-chain verifier
    /// template that authenticates inbound transactions for this account.
    /// Default is [`VERIFIER_TEMPLATE_ID_EOA`] (id = `0x0001`), which is
    /// sig-verify semantically-identical to a pre-genesis EOA. New templates
    /// are added on-chain via `ProposalEffect::AddAuthTemplate`; dispatching
    /// against a non-default template requires a node-software upgrade,
    /// mirroring the AlgRegistry / HashRegistry pattern. Collapses the
    /// 9-year EIP-86 → EIP-7702 saga into the genesis layout.
    pub verifier_template_id: u16,
    /// ADR-053 §T3.5: template-specific auxiliary authentication data (e.g.
    /// multisig threshold + member list, time-locked guardian list, session-
    /// key allowlist). MUST be empty for [`VERIFIER_TEMPLATE_ID_EOA`]; the
    /// EOA-template apply path rejects any inbound tx whose target account
    /// has non-empty `auth_data` so the field cannot be abused to smuggle
    /// data through the default verifier.
    pub auth_data: Vec<u8>,
}

impl Account {
    /// Account invariants — SPEC-ACCOUNT-001 §2.3.
    ///
    /// Returns Err with a description if any invariant is violated.
    /// Called after every state transition that touches account state.
    pub fn check_invariants(&self) -> Result<(), &'static str> {
        // I-1: at least one active key must exist at all times
        if !self.keys.has_active_key() {
            return Err("I-1: account has no active key");
        }
        // I-2: key_version values within the KeySet must be unique
        if self.keys.has_duplicate_versions() {
            return Err("I-2: duplicate key_version values in KeySet");
        }
        // I-3: EOA template (ADR-053 §T3.5) requires empty auth_data — see
        // doc on `auth_data` for the smuggling-rejection rationale.
        if self.verifier_template_id == VERIFIER_TEMPLATE_ID_EOA && !self.auth_data.is_empty() {
            return Err("I-3: EOA verifier template requires empty auth_data");
        }
        Ok(())
    }
}

#[cfg(test)]
mod adr_053_t3_5_tests {
    use super::*;
    use crate::keyset::{allowed_tx, KeyEntry, KeySet, KeyStatus};
    use pqc_crypto::AlgId;

    fn account_with(template: u16, auth_data: Vec<u8>) -> Account {
        Account {
            address: Address([0xAB; 32]),
            balance: 0,
            nonce: 0,
            keys: KeySet(vec![KeyEntry {
                alg_id: AlgId::MlDsa65,
                pk_bytes: vec![0u8; 32].into(),
                key_version: 1,
                valid_from_height: 0,
                status: KeyStatus::Active,
                allowed_tx_types: allowed_tx::ALL,
            }]),
            policy_version: 0,
            policy_hash: None,
            verifier_template_id: template,
            auth_data,
        }
    }

    #[test]
    fn verifier_template_id_constants_pin() {
        assert_eq!(VERIFIER_TEMPLATE_ID_EOA, 0x0001);
        assert_eq!(VERIFIER_TEMPLATE_CORE_RESERVED_MAX, 0x000F);
        assert_eq!(VERIFIER_TEMPLATE_GOV_MIN, 0x0010);
        const _: () = assert!(VERIFIER_TEMPLATE_ID_EOA <= VERIFIER_TEMPLATE_CORE_RESERVED_MAX);
        const _: () = assert!(VERIFIER_TEMPLATE_CORE_RESERVED_MAX < VERIFIER_TEMPLATE_GOV_MIN);
    }

    #[test]
    fn invariant_i3_eoa_with_empty_auth_data_is_ok() {
        let a = account_with(VERIFIER_TEMPLATE_ID_EOA, Vec::new());
        assert!(a.check_invariants().is_ok());
    }

    #[test]
    fn invariant_i3_eoa_with_nonempty_auth_data_is_err() {
        let a = account_with(VERIFIER_TEMPLATE_ID_EOA, vec![0x42]);
        assert_eq!(
            a.check_invariants().unwrap_err(),
            "I-3: EOA verifier template requires empty auth_data"
        );
    }

    #[test]
    fn invariant_i3_non_eoa_with_nonempty_auth_data_is_ok() {
        // A future template (e.g. 0x0010 = first governance-allocated slot)
        // is permitted to carry non-empty auth_data — the EOA invariant is
        // a smuggling-rejection guard for the default template only.
        let a = account_with(VERIFIER_TEMPLATE_GOV_MIN, vec![0xDE, 0xAD]);
        assert!(a.check_invariants().is_ok());
    }
}

// SPDX-License-Identifier: Apache-2.0
//! KeySet — per-account collection of signing keys.
//!
//! SPEC-ACCOUNT-001 §3 — full field semantics.
//! SPEC-ACCOUNT-001 §4 — state machine (pending → active → revoked).
//! SPEC-ACCOUNT-001 §5 — key lookup procedure (7 ordered steps).

use pqc_crypto::{AlgId, PublicKey};
use std::sync::Arc;

/// Status of a single key entry within the KeySet.
///
/// Transitions: `Pending` → `Active` (automated at valid_from_height)
///              `Active`  → `Revoked` (explicit key_revoke operation)
///              `Pending` → `Revoked` (explicit key_revoke before activation)
/// `Revoked` is terminal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyStatus {
    /// Key added but `valid_from_height` not yet reached.
    Pending,
    /// Key is active and may sign transactions per `allowed_tx_types`.
    Active,
    /// Key has been revoked. Retained for audit; never used for verification.
    Revoked,
}

/// `allowed_tx_types` bit assignments — SPEC-ACCOUNT-001 §3.6.
pub mod allowed_tx {
    pub const VAULT: u32 = 1 << 0;
    pub const ATTESTATION: u32 = 1 << 1;
    pub const KEY_MGMT: u32 = 1 << 2;
    pub const GOVERNANCE: u32 = 1 << 3;

    /// All bits set — key may sign any operation type.
    pub const ALL: u32 = VAULT | ATTESTATION | KEY_MGMT | GOVERNANCE;

    /// SLH-DSA keys MUST have exactly this mask.
    /// Restricted to key management operations only (SPEC-ACCOUNT-001 §3.6).
    pub const SLH_DSA_ONLY: u32 = KEY_MGMT;
}

/// A single key entry in the KeySet — SPEC-ACCOUNT-001 §3.
///
/// `pk_bytes` is stored as `Arc<[u8]>` so that cloning a `KeySet` (e.g. during
/// `StateStore::clone()` in block assembly) only increments a reference count
/// rather than copying the full public key bytes. ML-DSA-65 public keys are
/// 1952 bytes; with 10 K accounts the deep-copy alternative allocates ~19 MB
/// per block proposal.
#[derive(Debug, Clone)]
pub struct KeyEntry {
    pub alg_id: AlgId,
    pub pk_bytes: Arc<[u8]>,
    /// Monotonically increasing within the account. Used by the verifier to
    /// select the correct key. Never reused, even after revocation.
    pub key_version: u32,
    /// Block height from which this key is considered active.
    /// The key transitions from `Pending` to `Active` at this height.
    pub valid_from_height: u64,
    pub status: KeyStatus,
    /// Bitmask restricting which operation families this key may sign.
    pub allowed_tx_types: u32,
}

impl KeyEntry {
    /// Returns true if this key can sign the given operation type at the given block height.
    pub fn can_sign(&self, tx_type_bit: u32, current_height: u64) -> bool {
        self.status == KeyStatus::Active
            && current_height >= self.valid_from_height
            && (self.allowed_tx_types & tx_type_bit) != 0
    }
}

/// The full collection of keys for an account.
#[derive(Debug, Clone, Default)]
pub struct KeySet(pub Vec<KeyEntry>);

impl KeySet {
    /// Key lookup — SPEC-ACCOUNT-001 §5 (7 ordered steps).
    ///
    /// Returns the matching key entry, or an error indicating which step failed.
    pub fn lookup(
        &self,
        alg_id: AlgId,
        key_version: u32,
        tx_type_bit: u32,
        current_height: u64,
    ) -> Result<&KeyEntry, KeyLookupError> {
        // Step 1: find by key_version
        let entry = self
            .0
            .iter()
            .find(|k| k.key_version == key_version)
            .ok_or(KeyLookupError::KeyNotFound)?;

        // Step 2: alg_id must match
        if entry.alg_id != alg_id {
            return Err(KeyLookupError::AlgMismatch);
        }

        // Step 3: must not be revoked
        if entry.status == KeyStatus::Revoked {
            return Err(KeyLookupError::KeyRevoked);
        }

        // Step 4: valid_from_height must be reached
        if current_height < entry.valid_from_height {
            return Err(KeyLookupError::KeyNotYetActive {
                valid_from_height: entry.valid_from_height,
            });
        }

        // Step 5: must be Active (not Pending — Pending becomes Active at valid_from_height,
        // so if height is reached and status is still Pending, the state machine has a bug)
        if entry.status != KeyStatus::Active {
            return Err(KeyLookupError::KeyNotYetActive {
                valid_from_height: entry.valid_from_height,
            });
        }

        // Step 6: allowed_tx_types must include the requested operation
        if (entry.allowed_tx_types & tx_type_bit) == 0 {
            return Err(KeyLookupError::PermissionDenied);
        }

        Ok(entry)
    }

    pub fn has_active_key(&self) -> bool {
        self.0.iter().any(|k| k.status == KeyStatus::Active)
    }

    pub fn has_duplicate_versions(&self) -> bool {
        let mut seen = std::collections::HashSet::new();
        self.0.iter().any(|k| !seen.insert(k.key_version))
    }

    /// Resolve a `PublicKey` from a located KeyEntry.
    pub fn resolve_public_key(entry: &KeyEntry) -> PublicKey {
        PublicKey {
            alg_id: entry.alg_id,
            bytes: entry.pk_bytes.to_vec(),
        }
    }
}

/// Rejection codes from key lookup — SPEC-ACCOUNT-001 §5.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KeyLookupError {
    #[error("KEY_NOT_FOUND: no key with this key_version in the KeySet")]
    KeyNotFound,
    #[error("KEY_ALG_MISMATCH: key_version found but alg_id does not match")]
    AlgMismatch,
    #[error("KEY_REVOKED: key has been revoked")]
    KeyRevoked,
    #[error("KEY_NOT_YET_ACTIVE: valid_from_height {valid_from_height} not yet reached")]
    KeyNotYetActive { valid_from_height: u64 },
    #[error("KEY_PERMISSION_DENIED: key does not permit this operation type")]
    PermissionDenied,
}

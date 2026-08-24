// SPDX-License-Identifier: BUSL-1.1
//! `UpgradeHandler` trait and migration registry — ADR-031.
//!
//! Every time `STATE_FORMAT_VERSION` bumps, a corresponding `UpgradeHandler`
//! must be registered in `global_registry()` so that nodes running the new
//! binary can migrate state from the previous on-disk format without a
//! `make reset-chain`.
//!
//! # Boot-time flow
//!
//! 1. `RocksDbChainStore::apply_upgrade_chain` peeks at the checkpoint version.
//! 2. If `disk_version < STATE_FORMAT_VERSION`, the registry finds the handler
//!    chain from `disk_version` to `STATE_FORMAT_VERSION` and runs each handler
//!    sequentially.
//! 3. The migrated `StateStore` is written back as a new checkpoint with the
//!    updated version and recomputed `state_root`.
//!
//! # Invariant
//!
//! There must be an unbroken chain of handlers from version `N` to the current
//! `STATE_FORMAT_VERSION` for every `N` that could appear on disk.  If a gap
//! exists, `run_migrations` returns `MigrationNoHandler`.
//!
//! Audit scope: this module is in scope for the Phase 4 cryptographic audit
//! (ADR-031 §audit scope).

use crate::{error::ApplyError, store::StateStore};

// ── UpgradeHandler trait ──────────────────────────────────────────────────────

/// A single step in the state migration chain.
///
/// Implementations transform a `StateStore` from `from_version()` to
/// `to_version()`.  Migrations must be:
/// - **Deterministic**: same input state always yields the same output.
/// - **Idempotent on re-run**: safe to call twice (though not expected in practice).
/// - **Additive only**: never remove data — use tombstone / default values instead.
pub trait UpgradeHandler: Send + Sync {
    /// Human-readable identifier used in logs (e.g. `"v1-to-v2-pending-upgrades"`).
    fn name(&self) -> &'static str;

    /// The `STATE_FORMAT_VERSION` value on disk before this handler runs.
    fn source_version(&self) -> u16;

    /// The `STATE_FORMAT_VERSION` value after this handler completes.
    fn to_version(&self) -> u16;

    /// Apply the migration.  Mutates `store` in-place; the caller is responsible
    /// for writing the migrated state back to disk with the new version.
    fn migrate(&self, store: &mut StateStore) -> Result<(), ApplyError>;
}

// ── UpgradeRegistry ───────────────────────────────────────────────────────────

/// Registry of compiled-in upgrade handlers.
///
/// Obtained via `global_registry()`.  Handlers are sorted by `from_version`
/// so `run_migrations` can find the chain in O(N) time.
pub struct UpgradeRegistry {
    handlers: Vec<Box<dyn UpgradeHandler>>,
}

impl UpgradeRegistry {
    fn new() -> Self {
        Self {
            handlers: Vec::new(),
        }
    }

    fn register(&mut self, handler: Box<dyn UpgradeHandler>) {
        self.handlers.push(handler);
        // Keep sorted by from_version for deterministic chain traversal.
        self.handlers.sort_by_key(|h| h.source_version());
    }

    /// Execute the handler chain from `from_version` to `to_version`.
    ///
    /// Runs each handler whose `from_version` falls in `[from_version, to_version)`,
    /// in ascending order.  Returns `ApplyError::MigrationNoHandler` if any step
    /// in the chain is missing.
    ///
    /// Does nothing when `from_version == to_version`.
    pub fn run_migrations(
        &self,
        store: &mut StateStore,
        from_version: u16,
        to_version: u16,
    ) -> Result<(), ApplyError> {
        if from_version == to_version {
            return Ok(());
        }

        // Walk the chain: at each step find the handler with from_version == current.
        let mut current = from_version;
        while current < to_version {
            let handler = self
                .handlers
                .iter()
                .find(|h| h.source_version() == current)
                .ok_or(ApplyError::MigrationNoHandler {
                    from_version: current,
                    to_version,
                })?;

            tracing::info!(
                handler = handler.name(),
                from = current,
                to = handler.to_version(),
                "running state migration step",
            );

            handler.migrate(store)?;
            current = handler.to_version();
        }

        Ok(())
    }
}

// ── Compiled-in handlers ──────────────────────────────────────────────────────

/// v1 → v2: adds the `pending_upgrades` collection to `StateStore`.
///
/// The field defaults to an empty `Vec` when deserializing old checkpoints,
/// so no data transformation is needed.  This handler exists to satisfy the
/// invariant that every version bump has a registered handler, and to recompute
/// the `state_root` with the new algorithm (which now includes the
/// `pending_upgrades` section even when it is empty).
struct V1ToV2Handler;

impl UpgradeHandler for V1ToV2Handler {
    fn name(&self) -> &'static str {
        "v1-to-v2-pending-upgrades"
    }
    fn source_version(&self) -> u16 {
        1
    }
    fn to_version(&self) -> u16 {
        2
    }

    fn migrate(&self, _store: &mut StateStore) -> Result<(), ApplyError> {
        // `pending_upgrades` defaults to an empty HashMap when loading old
        // checkpoints via serde default.  No data transformation is required;
        // the caller will recompute `state_root()` and write back a new
        // checkpoint with `version = 2`.
        Ok(())
    }
}

/// v2 → v3: `compute_validator_leaf_hash` now includes the `tombstoned` field
/// (fix for audit finding F-001, commit 1da7b81).
///
/// Existing validators have `tombstoned = false` (the serde default when
/// loading v2 checkpoints), so no data transformation is required.  The caller
/// will recompute `state_root()` with the updated leaf hash formula and write
/// back a new checkpoint with `version = 3`.
struct V2ToV3Handler;

impl UpgradeHandler for V2ToV3Handler {
    fn name(&self) -> &'static str {
        "v2-to-v3-tombstoned-validator-leaf"
    }
    fn source_version(&self) -> u16 {
        2
    }
    fn to_version(&self) -> u16 {
        3
    }

    fn migrate(&self, _store: &mut StateStore) -> Result<(), ApplyError> {
        // `tombstoned` defaults to `false` on v2 checkpoints via serde default.
        // No data transformation is required; the caller recomputes `state_root()`
        // and writes a new checkpoint with `version = 3`.
        Ok(())
    }
}

// ── Global registry ───────────────────────────────────────────────────────────

/// Build and return the global upgrade registry with all compiled-in handlers.
///
/// Called at boot by `RocksDbChainStore::apply_upgrade_chain` and by tests.
/// Returns a fresh registry each call (cheap — no heap allocation of state data).
pub fn global_registry() -> UpgradeRegistry {
    let mut registry = UpgradeRegistry::new();
    registry.register(Box::new(V1ToV2Handler));
    registry.register(Box::new(V2ToV3Handler));
    registry
}

// SPDX-License-Identifier: BUSL-1.1
//! Keystore boot, reload, and signer-snapshot lifecycle.
//!
//! Extracted from `devnet.rs` 2026-05-10 as the eleventh slice of
//! the split. Centralises the helpers that build the in-memory
//! `Keystore` at startup (D-06 bootstrap), gate it on the boot-time
//! self-test, mtime-reload it from disk on the producer/consensus
//! tick, and snapshot the per-block signer set against the live
//! Active validator set (Phase 4 Gap A `get_for_pk` lookup).
//!
//! `snapshot_block_signers_dyn` is the public re-export consumed by
//! integration tests in `crates/pqcd/tests/consensus_key_rotation_
//! producer.rs`. The parent re-exports it via `pub use` so external
//! callers keep using `pqcd::devnet::snapshot_block_signers_dyn`
//! verbatim.
//!
//! `use super::*;` keeps every sibling type and helper in scope.

use super::*;

/// Build the initial `Keystore` from the node config — D-06 bootstrap path.
///
/// Reuses the existing `resolve_local_commit_signers` validation (seed
/// matches published pk, alg_id is known) but returns a dynamic keystore
/// instead of a frozen `Vec<LocalCommitSigner>`. The producer still runs
/// the quorum-at-startup check via `resolve_local_commit_signers` before
/// this helper is called, so any mismatched seeds are caught early.
///
/// Source precedence — SECURITY-FIX-PLAN.md §1 (Issue #1):
///
/// When `config.devnet.keystore_path` is set AND the file exists, the
/// file is loaded FIRST and is the authoritative source of validator
/// commit seeds. The in-config `validators[].commit_seed_hex` entries
/// are then walked and:
///
///   - If the keystore already has an entry for this validator's
///     address AND the seed in the file disagrees with the seed in
///     `node.json` → `bail!` with the validator's `node_id`.
///   - If the keystore already has an entry AND the seeds agree →
///     skip (file wins; the in-config copy is redundant).
///   - If the keystore has no entry for this address → fall through
///     to the existing pk-cross-check + upsert path so that a fresh
///     genesis or a partial keystore still boots.
///
/// This closes the operational gap where `commit_seed_hex` lived
/// inline in node.json alongside `keystore.json`: with the fix, an
/// operator cannot accidentally desync the two — pqcd refuses to
/// start instead of silently picking one source. The Ansible
/// template-side change (drop `commit_seed_hex` from rendered
/// node.json, set `keystore_path` instead) is the per-host
/// counterpart that lands once this gate is in place.
pub(super) fn build_initial_keystore(
    config: &NodeConfig,
    _commit_policy: Option<&CommitQuorumPolicy>,
) -> Result<Keystore> {
    // 1. Load from the on-disk keystore FIRST when configured.
    //    A declared-but-unreadable file is a hard error: the operator
    //    asked for keystore-driven seeds, so silently falling back to
    //    in-config seeds would mask the misconfiguration.
    let mut keystore = match config.devnet.keystore_path.as_ref() {
        Some(path) if path.exists() => Keystore::load_from_file(path).with_context(|| {
            format!(
                "devnet.keystore_path {} declared but failed to load",
                path.display()
            )
        })?,
        _ => Keystore::new(),
    };

    // 2. Merge in-config seeds. BAIL on disagreement; skip on agreement.
    for validator in &config.devnet.validators {
        let Some(seed_hex) = validator.commit_seed_hex.as_ref() else {
            continue;
        };
        let addr: [u8; 32] =
            decode_hex_array(&validator.address_hex, "devnet.validators[].address_hex")?;
        if let Some(existing) = keystore.get(&addr) {
            let new_seed: [u8; 32] =
                decode_hex_array(seed_hex, "devnet.validators[].commit_seed_hex")?;
            if existing.commit_seed != new_seed {
                bail!(
                    "validator {} commit seed disagrees between node.json and \
                     keystore.json — refusing to start. Strip the seed from \
                     node.json or align them. See SECURITY-FIX-PLAN.md §1.",
                    validator.node_id
                );
            }
            // Seeds agree → file wins, in-config copy is redundant.
            continue;
        }
        // No keystore entry for this address yet → existing path:
        // derive pk, cross-check, upsert. Phase 4 Gap A: tag the
        // genesis-seeded entry as `key_version = 1` and cache the
        // derived pk so `get_for_pk` is cheap on the hot path.
        let signer = local_commit_signer_from_config(validator, seed_hex)?;
        let signer_addr: [u8; 32] = signer
            .validator_address
            .as_slice()
            .try_into()
            .context("validator_address must be 32 bytes")?;
        let archival_sk = match validator.archival_sk_hex.as_ref() {
            Some(h) => Some(
                hex::decode(h.trim_start_matches("0x"))
                    .context("validator archival_sk_hex is not valid hex")?,
            ),
            None => None,
        };
        let derived_pk =
            pqc_crypto::ml_dsa_public_key_from_seed(signer.sig_alg_id, &signer.commit_seed)
                .context("failed to derive pk for genesis keystore entry")?;
        keystore.upsert(
            signer_addr,
            crate::keystore::KeystoreEntry {
                sig_alg_id: signer.sig_alg_id,
                commit_seed: signer.commit_seed,
                key_version: crate::keystore::DEFAULT_KEY_VERSION,
                public_key: derived_pk,
                archival_sk,
            },
        );
    }
    Ok(keystore)
}

/// HSM phase-plan boot-time canary — sign+verify `CANARY_PREIMAGE`
/// with a `pqc_hsm::LocalKeystoreSigner` constructed from each keystore
/// entry. Per the private design notes
/// validation": catches mis-wired HSM credentials / stale seeds /
/// pubkey disagreements at boot rather than at first block production.
///
/// On the canonical happy path, every entry derives a valid pubkey
/// from its seed (the loader cross-checks at file-load time), so the
/// canary is a defensive belt-and-suspenders check. The flow is wired
/// here regardless because the same code path will be reused for the
/// SoftHSM and CloudHSM kinds (where the loader can't cross-check
/// because the seed is inside the HSM).
///
/// Empty keystore is OK — follower nodes with no signing material
/// participate in consensus through gossip-only verification.
pub(super) fn run_local_keystore_self_test(node_id: &str, keystore: &Keystore) -> Result<()> {
    use pqc_hsm::CommitSigner as _;
    if keystore.is_empty() {
        tracing::info!(
            node_id = %node_id,
            "HSM canary: keystore is empty (follower / observer); skipping self-test"
        );
        return Ok(());
    }
    // Iterate every (address, version) pair. Reaching all entries is
    // worth the up-front O(N×ML-DSA-sign) cost: HSM-backed signers will
    // pay this anyway, and N is bounded by validator count (≤ 21 in the
    // launch ladder).
    let total = keystore.len();
    for (address, entry) in keystore.iter_entries() {
        let signer = pqc_hsm::LocalKeystoreSigner::from_keystore_entry(
            address,
            entry.sig_alg_id,
            entry.commit_seed,
            entry.public_key.clone(),
        )
        .with_context(|| {
            format!(
                "HSM canary: failed to construct LocalKeystoreSigner for validator {} \
                 (key_version {}) — keystore is inconsistent (HSM-PHASE-PLAN.md \
                 §Boot-time validation)",
                hex::encode(address),
                entry.key_version,
            )
        })?;
        signer.self_test().with_context(|| {
            format!(
                "HSM canary: self-test failed for validator {} (key_version {}, alg {:?}) — \
                 the configured signer cannot produce signatures verifiable under its \
                 cached pubkey. Check signer_config in node.json.",
                hex::encode(address),
                entry.key_version,
                entry.sig_alg_id,
            )
        })?;
    }
    tracing::info!(
        node_id = %node_id,
        entries = total,
        "HSM canary: boot self-test passed for all keystore entries"
    );
    Ok(())
}

/// Reload the keystore from its on-disk file if the config declared one
/// and the file's mtime has advanced — D-06 dynamic-reload path.
///
/// Best-effort: a missing/unreadable/malformed file is logged at `warn`
/// and does not halt block production. Operators stage additional seeds
/// by atomically writing a new keystore.json (`mv keystore.json.new
/// keystore.json`) alongside the live node.
pub(super) async fn refresh_keystore_from_file(
    state: &std::sync::Arc<tokio::sync::Mutex<LiveNodeState>>,
) {
    let (keystore_handle, path_opt) = {
        let guard = state.lock().await;
        let path = guard.config.devnet.keystore_path.clone();
        (guard.keystore.clone(), path)
    };
    let Some(path) = path_opt else {
        return;
    };
    let mut guard = match keystore_handle.write() {
        Ok(g) => g,
        Err(_) => {
            tracing::warn!("keystore RwLock poisoned; skipping reload");
            return;
        }
    };
    match guard.reload_if_changed(&path) {
        Ok(true) => tracing::info!(path = ?path, len = guard.len(), "keystore reloaded"),
        Ok(false) => {}
        Err(e) => tracing::warn!(error = %e, path = ?path, "keystore reload failed"),
    }
}

/// Snapshot a deterministic per-block signer list from the keystore
/// filtered to the currently-Active validator set — D-06 + Phase 4 Gap A.
///
/// Phase 4 Gap A: this is the producer-side rotation matching point.
/// For each Active validator, the keystore is queried by the on-chain
/// `consensus_pk` (NOT just by address) — `get_for_pk` selects the
/// staged seed whose derived public key matches what the chain
/// currently expects. After
/// `StateStore::activate_pending_consensus_key_rotations` flips the pk
/// at the rotation boundary, the producer transparently picks the new
/// staged version with no operator file swap.
///
/// A validator that is Active on-chain but has no seed in the keystore
/// (or whose required key version was not pre-staged before the
/// activation height) is silently skipped after a `warn!`; the block
/// commit gets fewer signatures and if that drops below quorum the
/// block is rejected and the round advances. The natural fail-mode is
/// "validator drops out of quorum"; the warn is the operator's
/// actionable signal that a rotation pre-ship was missed.
///
/// Accepts any iterator over Active validator records so both call
/// sites (by-reference and by-value) can feed it without cloning the
/// underlying state-store vector.
/// HSM phase-plan trait-object variant of `snapshot_block_signers`.
///
/// Same selection logic (match by on-chain `consensus_pk`, graceful skip
/// on missing entries with operator-actionable warning) but returns
/// `Vec<Box<dyn pqc_hsm::CommitSigner>>` — a future-ready surface for
/// when the producer's commit-signing call sites migrate to the trait.
/// The current call sites still consume the concrete
/// `Vec<LocalCommitSigner>` because they additionally drive the p2p
/// precommit path via `build_signed_precommit(alg, &seed, ...)`; that
/// migration is staged for the next phase. See HSM-PHASE-PLAN.md.
///
/// Used by the consensus-rotation integration test
/// (`crates/pqcd/tests/consensus_key_rotation_producer.rs`) to pin
/// trait-surface parity with the concrete path.
pub fn snapshot_block_signers_dyn(
    keystore: &Keystore,
    active_validators: &[&pqc_types::validator::ValidatorRecord],
) -> Vec<Box<dyn pqc_hsm::CommitSigner>> {
    snapshot_block_signers(keystore, active_validators)
        .into_iter()
        .map(|s| Box::new(s) as Box<dyn pqc_hsm::CommitSigner>)
        .collect()
}

pub(super) fn snapshot_block_signers(
    keystore: &Keystore,
    active_validators: &[&pqc_types::validator::ValidatorRecord],
) -> Vec<LocalCommitSigner> {
    active_validators
        .iter()
        .filter_map(|record| {
            let addr = record.operator.0;
            // Phase 4 Gap A: match by on-chain consensus_pk, not just
            // by address. After a rotation activates, the keystore may
            // hold both the old (v1) and new (v2) seeds — picking the
            // wrong one produces invalid signatures and silent
            // quorum-dropout.
            match keystore.get_for_pk(&addr, &record.consensus_pk) {
                Some(entry) => Some(LocalCommitSigner {
                    validator_address: addr.to_vec(),
                    sig_alg_id: entry.sig_alg_id,
                    commit_seed: entry.commit_seed,
                }),
                None => {
                    // Distinguish two failure modes for the operator:
                    //  - keystore has SOME entry for this address but no
                    //    version matches → rotation pre-ship was missed
                    //    OR the on-chain pk just rotated and the v2 entry
                    //    was never staged.
                    //  - keystore has NO entry for this address → either
                    //    a follower that can't sign for this validator,
                    //    OR a freshly-registered validator whose seed
                    //    has not been loaded yet (D-06 transient).
                    if keystore.contains(&addr) {
                        let staged = keystore.staged_versions_for(&addr);
                        tracing::warn!(
                            validator_address = %hex::encode(addr),
                            expected_pk = %hex::encode(&record.consensus_pk),
                            staged_versions = ?staged,
                            "Phase 4 Gap A: keystore holds no seed matching the on-chain \
                             consensus_pk for this validator; skipping commit signature. \
                             Stage the matching key_version via `pqcd wallet \
                             rotate-consensus-key --in-place` and reload."
                        );
                    }
                    None
                }
            }
        })
        .collect()
}

pub(super) fn local_commit_signer_from_config(
    validator: &ValidatorConfig,
    seed_hex: &str,
) -> Result<LocalCommitSigner> {
    let sig_alg_id = AlgId::from_u16(validator.sig_alg_id).ok_or_else(|| {
        anyhow!(
            "unknown devnet validator alg_id 0x{:04x}",
            validator.sig_alg_id
        )
    })?;
    let commit_seed = decode_hex_array::<32>(seed_hex, "devnet.validators[].commit_seed_hex")?;
    let expected_public_key = crate::node::decode_hex_bytes(
        &validator.public_key_hex,
        "devnet.validators[].public_key_hex",
    )?;
    let actual_public_key = ml_dsa_public_key_from_seed(sig_alg_id, &commit_seed)
        .context("failed to derive ML-DSA public key from commit seed")?;
    if actual_public_key != expected_public_key {
        bail!(
            "devnet validator {} commit_seed_hex does not match public_key_hex",
            validator.node_id
        );
    }

    Ok(LocalCommitSigner {
        validator_address: crate::node::decode_hex_bytes(
            &validator.address_hex,
            "devnet.validators[].address_hex",
        )?,
        sig_alg_id,
        commit_seed,
    })
}

pub(super) fn next_block_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod hsm_self_test_tests {
    //! HSM phase-plan boot-time self-test pin tests.
    //!
    //! `run_local_keystore_self_test` is the function the daemon boot
    //! path calls before consensus loops spin up. These tests cover:
    //! - empty keystore (follower) → Ok, no-op.
    //! - one valid entry → Ok, canary verifies.
    //! - tampered entry (cached pubkey ≠ derived from seed) →
    //!   `BackendMismatch` surfaces with the validator address in the
    //!   error message.
    use super::*;
    use crate::keystore::{Keystore, KeystoreEntry, DEFAULT_KEY_VERSION};
    use pqc_crypto::{ml_dsa_public_key_from_seed, AlgId};
    #[test]
    fn empty_keystore_passes_self_test() {
        let ks = Keystore::new();
        run_local_keystore_self_test("follower-x", &ks).expect("empty keystore is OK at boot");
    }
    #[test]
    fn valid_entry_passes_self_test() {
        let mut ks = Keystore::new();
        let seed = [0xAB; 32];
        let pk = ml_dsa_public_key_from_seed(AlgId::MlDsa65, &seed).unwrap();
        ks.upsert(
            [0x11; 32],
            KeystoreEntry {
                sig_alg_id: AlgId::MlDsa65,
                commit_seed: seed,
                key_version: DEFAULT_KEY_VERSION,
                public_key: pk,
                archival_sk: None,
            },
        );
        run_local_keystore_self_test("validator-x", &ks)
            .expect("valid entry must pass canary self-test");
    }
    #[test]
    fn tampered_entry_fails_self_test() {
        // Cached pubkey doesn't derive from seed → boot path bails.
        let mut ks = Keystore::new();
        let real_seed = [0xAB; 32];
        let wrong_pk = ml_dsa_public_key_from_seed(AlgId::MlDsa65, &[0xCD; 32]).unwrap();
        ks.upsert(
            [0x22; 32],
            KeystoreEntry {
                sig_alg_id: AlgId::MlDsa65,
                commit_seed: real_seed,
                key_version: DEFAULT_KEY_VERSION,
                public_key: wrong_pk,
                archival_sk: None,
            },
        );
        let err =
            run_local_keystore_self_test("validator-bad", &ks).expect_err("tampered must fail");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("HSM canary"),
            "error must point at the canary: {msg}"
        );
    }
}

#[cfg(test)]
mod build_initial_keystore_tests;

#[cfg(test)]
mod snapshot_block_signers_tests;

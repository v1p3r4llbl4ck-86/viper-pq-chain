// SPDX-License-Identifier: BUSL-1.1
//! Devnet validator keystore — dynamic signing-key table for the local
//! block producer.
//!
//! # Why this exists (D-06 + Phase 4 Gap A)
//!
//! The Phase 8 single-process producer signs commit material for every
//! Active validator it holds a seed for. Before D-06, those seeds were
//! captured ONCE at `start_from_config_path` time from
//! `config.devnet.validators[].commit_seed_hex` into an immutable
//! `Vec<LocalCommitSigner>`. That works for the 3-validator static
//! devnet but collapses as soon as the on-chain Active set grows past 4
//! via `ValidatorRegister`: the BFT threshold `ceil((2N+1)/3)` then
//! exceeds 3 and the producer can no longer reach quorum, because the
//! newly-registered operators have no corresponding seed in the
//! producer's local signer list (KNOWN-ISSUES.md D-06, TASK-151, TASK-156
//! Step 6).
//!
//! The D-06 fix introduced `Keystore::get(addr)`. The Phase-4 Gap A fix
//! (`PHASE-4-KEY-ROTATION-RESEARCH.md` §1.3 Option 1) extends the
//! keystore to hold MULTIPLE versions of the same validator's signing
//! material, indexed by a `key_version` field. After
//! `StateStore::activate_pending_consensus_key_rotations` flips
//! `ValidatorRecord.consensus_pk` on-chain at the rotation boundary, the
//! producer side picks the matching seed via `get_for_pk` and never
//! needs an operator-driven file swap. This is the missing producer-side
//! piece of the consensus-key-rotate flow (`CONCERNS-DECISIONS.md` Gap A).
//!
//! Missing-key handling is graceful: when an Active validator has no
//! entry, the producer simply does NOT sign for that validator on this
//! block. If the resulting commit-signature set is below the quorum
//! threshold, the block is rejected on the follower side and the
//! round advances normally — no panics, no inconsistent state.
//!
//! # Production note
//!
//! The on-disk JSON format is a **development / test-harness
//! convenience**. In a production deployment the seeds never leave the
//! HSM: `Keystore` is implemented as a thin wrapper over a PKCS#11
//! session handle, `get_for_pk()` returns a handle to a signer object
//! rather than raw bytes, and `load_from_file` is absent. The trait
//! surface here (`get_for_pk` + `reload_if_changed`) is designed to
//! permit that swap without touching `LocalProposer` or the devnet loops.
//!
//! # File format
//!
//! ```json
//! {
//!   "validators": [
//!     {
//!       "address_hex": "a1a1…",
//!       "sig_alg_id": 2,
//!       "commit_seed_hex": "1111…",
//!       "key_version": 1,                  // optional; defaults to 1
//!       "archival_sk_hex": "cafe…"         // optional (128 bytes, 256 hex chars)
//!     },
//!     {
//!       "address_hex": "a1a1…",            // SAME address — staged rotation
//!       "sig_alg_id": 3,                    // possibly different alg
//!       "commit_seed_hex": "2222…",
//!       "key_version": 2
//!     }
//!   ]
//! }
//! ```
//!
//! `address_hex`, `sig_alg_id`, and `commit_seed_hex` are required.
//! `sig_alg_id` maps to `pqc_crypto::AlgId` (ML-DSA-44 = 1, ML-DSA-65 = 2,
//! ML-DSA-87 = 3). The hex encoding is case-insensitive and may carry an
//! optional `0x` prefix.
//!
//! `key_version` is optional. When omitted, defaults to `1`. When more
//! than one entry exists for the same address, every entry MUST carry a
//! distinct `key_version` (loader rejects duplicates). Phase 4 Gap A
//! relies on this: an operator stages the v2 entry alongside the v1
//! entry, and the producer's `get_for_pk` lookup picks the entry whose
//! derived public key matches the on-chain `ValidatorRecord.consensus_pk`
//! at the current height.
//!
//! `archival_sk_hex` is the SLH-DSA-SHAKE-256s secret key (128 bytes) used
//! by the M4.4 archival-overlay hook to sign `epoch_root` at each epoch
//! boundary. Optional; validators without an archival key simply don't
//! participate in the archival signer set (SPEC-ARCHIVAL-001 §4.2). Rotate
//! by rewriting this field and resubmitting `ValidatorRegisterArchivalKey`.

use std::{collections::HashMap, fs, path::Path, time::SystemTime};

use anyhow::{anyhow, bail, Context, Result};
use pqc_crypto::{ml_dsa_public_key_from_seed, AlgId};
use serde::{Deserialize, Serialize};

use crate::node::{decode_hex_array, ValidatorConfig};

/// Default `key_version` assigned to entries that don't specify one.
/// Maintains back-compat with single-entry-per-address keystores written
/// before Phase 4 Gap A.
pub const DEFAULT_KEY_VERSION: u32 = 1;

/// A single signer entry — what the producer needs to sign commit
/// material on behalf of one validator at one specific key-version.
#[derive(Clone, Debug)]
pub struct KeystoreEntry {
    pub sig_alg_id: AlgId,
    pub commit_seed: [u8; 32],
    /// Monotonic version tag distinguishing successive consensus keys for
    /// the same operator. Defaults to `1` for legacy single-entry
    /// keystores. The producer's `get_for_pk` lookup matches by derived
    /// public key, not by this number — `key_version` is the on-disk
    /// staging label, not a consensus-relevant identifier.
    pub key_version: u32,
    /// Public key derived from `(sig_alg_id, commit_seed)` at load time
    /// and cached. Used by `get_for_pk` to match against the on-chain
    /// `ValidatorRecord.consensus_pk` without a per-block re-derivation.
    pub public_key: Vec<u8>,
    /// Optional SLH-DSA-SHAKE-256s secret key (128 bytes, FIPS 205 §10.3)
    /// for the M4.4 archival-overlay signer path. `None` means this
    /// validator does not co-sign `epoch_root` for the archival overlay.
    pub archival_sk: Option<Vec<u8>>,
}

/// In-memory table mapping 32-byte validator operator addresses to
/// (potentially multiple) signing-material entries — one per
/// `key_version`.
///
/// Thread-safety: `Keystore` is `Send + Sync` by virtue of its fields
/// being `Send + Sync`. Concurrent callers share instances via
/// `Arc<std::sync::RwLock<Keystore>>`.
#[derive(Debug, Default)]
pub struct Keystore {
    /// Per-address vector of versioned entries. Invariant: every entry's
    /// `key_version` is unique within its address slot. The vector is
    /// kept sorted by ascending `key_version` so `get_latest` is O(1).
    entries: HashMap<[u8; 32], Vec<KeystoreEntry>>,
    /// Last observed mtime of the file backing this keystore, used to
    /// skip re-parsing when nothing has changed. `None` means "never
    /// loaded from disk" OR "file did not exist at last check".
    last_mtime: Option<SystemTime>,
}

/// On-disk JSON envelope — see module docs for the format.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct KeystoreFile {
    validators: Vec<KeystoreFileEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct KeystoreFileEntry {
    address_hex: String,
    sig_alg_id: u16,
    commit_seed_hex: String,
    /// Optional `key_version` (Phase 4 Gap A). Omitted → defaults to
    /// `DEFAULT_KEY_VERSION` (1) for back-compat with pre-Phase-4
    /// single-entry keystores.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    key_version: Option<u32>,
    /// Optional SLH-DSA-SHAKE-256s secret key (hex, 128 bytes). See module
    /// docs; omitted for validators that don't participate in archival.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    archival_sk_hex: Option<String>,
}

impl Keystore {
    /// Construct an empty keystore with no entries.
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            last_mtime: None,
        }
    }

    /// Build a keystore from the `devnet.validators[]` section of a
    /// `NodeConfig`. When `include_seeds` is false (typical for follower
    /// nodes that never sign), validators without a `commit_seed_hex`
    /// are silently skipped and the returned keystore is empty.
    ///
    /// Every entry with a seed is validated: the derived public key must
    /// match the configured `public_key_hex`, otherwise an error is
    /// returned. This preserves the pre-D-06 invariant that the
    /// producer cannot start with a mis-wired seed. Entries seeded from
    /// `node.json` are tagged `key_version = 1` — Phase 4 Gap A relies
    /// on the rotate-CLI to append v2+ entries to the on-disk
    /// `keystore.json` after a `ConsensusKeyRotate` tx is staged.
    pub fn from_validators(validators: &[ValidatorConfig], include_seeds: bool) -> Result<Self> {
        let mut store = Self::new();
        if !include_seeds {
            return Ok(store);
        }
        for v in validators {
            let Some(seed_hex) = v.commit_seed_hex.as_ref() else {
                continue;
            };
            let address =
                decode_hex_array::<32>(&v.address_hex, "devnet.validators[].address_hex")?;
            let commit_seed =
                decode_hex_array::<32>(seed_hex, "devnet.validators[].commit_seed_hex")?;
            let sig_alg_id = AlgId::from_u16(v.sig_alg_id)
                .ok_or_else(|| anyhow!("unknown devnet validator alg_id 0x{:04x}", v.sig_alg_id))?;
            // Cross-check the seed against the declared pk — a mis-wired
            // config would silently produce invalid signatures otherwise.
            let derived_pk = ml_dsa_public_key_from_seed(sig_alg_id, &commit_seed)
                .context("failed to derive ML-DSA public key from commit seed")?;
            let expected_pk = crate::node::decode_hex_bytes(
                &v.public_key_hex,
                "devnet.validators[].public_key_hex",
            )?;
            if derived_pk != expected_pk {
                bail!(
                    "devnet validator {} commit_seed_hex does not match public_key_hex",
                    v.node_id
                );
            }
            let archival_sk = v
                .archival_sk_hex
                .as_ref()
                .and_then(|h| hex::decode(h.trim_start_matches("0x")).ok());
            let entry = KeystoreEntry {
                sig_alg_id,
                commit_seed,
                key_version: DEFAULT_KEY_VERSION,
                public_key: derived_pk,
                archival_sk,
            };
            store.insert_versioned(address, entry)?;
        }
        Ok(store)
    }

    /// Parse a keystore file from disk. See module docs for the format.
    ///
    /// The file's mtime is recorded so subsequent `reload_if_changed`
    /// calls can short-circuit when it has not moved forward.
    ///
    /// Multi-version semantics (Phase 4 Gap A): the same `address_hex`
    /// MAY appear more than once provided each occurrence carries a
    /// distinct `key_version`. Duplicates within the same file are
    /// rejected — the operator MUST resolve the ambiguity before the
    /// file is loaded.
    pub fn load_from_file(path: &Path) -> Result<Self> {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("failed to read keystore file {}", path.display()))?;
        let parsed: KeystoreFile = serde_json::from_str(&raw)
            .with_context(|| format!("failed to parse keystore file {}", path.display()))?;
        let mtime = fs::metadata(path).and_then(|m| m.modified()).ok();

        let mut store = Self::new();
        store.last_mtime = mtime;
        for entry in parsed.validators {
            let address = decode_hex_array::<32>(&entry.address_hex, "keystore.address_hex")?;
            let commit_seed =
                decode_hex_array::<32>(&entry.commit_seed_hex, "keystore.commit_seed_hex")?;
            let sig_alg_id = AlgId::from_u16(entry.sig_alg_id).ok_or_else(|| {
                anyhow!(
                    "unknown keystore entry sig_alg_id 0x{:04x}",
                    entry.sig_alg_id
                )
            })?;
            // Derive + cache the pk so `get_for_pk` is cheap on the hot
            // path. This also catches a bad seed at load time — a
            // human-edited keystore is the most likely place for a
            // typo to creep in.
            let public_key = ml_dsa_public_key_from_seed(sig_alg_id, &commit_seed)
                .context("keystore entry commit_seed_hex does not derive a valid ML-DSA key")?;
            let archival_sk = match entry.archival_sk_hex {
                Some(hex_str) => {
                    let bytes = hex::decode(hex_str.trim_start_matches("0x"))
                        .context("keystore entry archival_sk_hex is not valid hex")?;
                    if bytes.len() != pqc_types::archival::SLH_DSA_SHAKE_256S_SK_LEN {
                        bail!(
                            "keystore entry archival_sk_hex must be {} bytes (FIPS 205 §10.3), got {}",
                            pqc_types::archival::SLH_DSA_SHAKE_256S_SK_LEN,
                            bytes.len()
                        );
                    }
                    Some(bytes)
                }
                None => None,
            };
            let key_version = entry.key_version.unwrap_or(DEFAULT_KEY_VERSION);
            let new_entry = KeystoreEntry {
                sig_alg_id,
                commit_seed,
                key_version,
                public_key,
                archival_sk,
            };
            store.insert_versioned(address, new_entry)?;
        }
        Ok(store)
    }

    /// Insert one entry, enforcing the per-address `(address, key_version)`
    /// uniqueness invariant. Returns an error on a duplicate
    /// `(address, key_version)` pair. The vector is kept sorted by
    /// ascending `key_version` so `get_latest` is O(1).
    fn insert_versioned(&mut self, address: [u8; 32], entry: KeystoreEntry) -> Result<()> {
        let bucket = self.entries.entry(address).or_default();
        if bucket.iter().any(|e| e.key_version == entry.key_version) {
            bail!(
                "duplicate keystore entry for address {} at key_version {}",
                hex::encode(address),
                entry.key_version
            );
        }
        bucket.push(entry);
        // Maintain ascending order by key_version.
        bucket.sort_by_key(|e| e.key_version);
        Ok(())
    }

    /// Look up a signing entry whose derived public key matches
    /// `expected_pk` (the on-chain `ValidatorRecord.consensus_pk` for the
    /// given operator address). This is the Phase-4 Gap-A producer-path
    /// lookup: after `activate_pending_consensus_key_rotations` flips
    /// the on-chain pk at the rotation boundary, this method
    /// transparently selects the staged v2 entry without any operator
    /// file swap.
    ///
    /// Returns `None` when no version of this validator's key is staged
    /// in the keystore. The caller (typically `snapshot_block_signers`)
    /// treats `None` as "skip signing for this validator on this block"
    /// — the natural fail-mode is a quorum-loss warning, not a panic.
    pub fn get_for_pk(&self, address: &[u8; 32], expected_pk: &[u8]) -> Option<&KeystoreEntry> {
        self.entries
            .get(address)?
            .iter()
            .find(|e| e.public_key.as_slice() == expected_pk)
    }

    /// Return the highest-`key_version` entry for `address`. Used by
    /// non-rotation call sites that simply want "this validator's
    /// current signing material" (archival key derivation, cold-storage
    /// signing, light-client attestation, etc.). Equivalent to the
    /// pre-Phase-4 `get(addr)` when the keystore holds only one entry
    /// per address.
    pub fn get_latest(&self, address: &[u8; 32]) -> Option<&KeystoreEntry> {
        // Vector is sorted ascending by key_version; `last()` returns
        // the highest version.
        self.entries.get(address)?.last()
    }

    /// Back-compat alias for `get_latest`. Pre-Phase-4 callers used
    /// `get(addr)` to fetch the single entry per validator. With
    /// multi-version keystores the equivalent semantics is "the highest
    /// staged version" — those call sites are NOT consensus-rotation
    /// paths (archival, cold-storage, light-client) and should keep
    /// using the latest-version entry.
    ///
    /// The producer's commit-signing path (`snapshot_block_signers`)
    /// uses `get_for_pk` instead — the on-chain `consensus_pk` selects
    /// the version, not "latest staged".
    pub fn get(&self, address: &[u8; 32]) -> Option<&KeystoreEntry> {
        self.get_latest(address)
    }

    /// True if the keystore has any entry for `address` (any version).
    pub fn contains(&self, address: &[u8; 32]) -> bool {
        self.entries
            .get(address)
            .map(|v| !v.is_empty())
            .unwrap_or(false)
    }

    /// Total number of (address, key_version) entries currently loaded —
    /// NOT the number of distinct validators. A validator with two
    /// staged versions counts as two.
    pub fn len(&self) -> usize {
        self.entries.values().map(|v| v.len()).sum()
    }

    /// Number of distinct validator addresses with at least one entry.
    pub fn distinct_addresses(&self) -> usize {
        self.entries.len()
    }

    /// True when the keystore is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Iterate every `(address, &entry)` pair across all addresses and
    /// staged versions. Used by the HSM phase-plan boot-time
    /// self-test (`pqcd::devnet::run_local_keystore_self_test`) to
    /// canary every signer at startup. Order is HashMap-internal
    /// (non-deterministic across runs) but stable within a single
    /// process invocation — the canary doesn't depend on order.
    pub fn iter_entries(&self) -> impl Iterator<Item = ([u8; 32], &KeystoreEntry)> {
        self.entries
            .iter()
            .flat_map(|(addr, bucket)| bucket.iter().map(move |e| (*addr, e)))
    }

    /// All `key_version` values currently staged for `address`, in
    /// ascending order. Returns an empty slice when no entry exists.
    /// Used by tests and by the operator-facing `pqcd wallet
    /// rotate-consensus-key --in-place` to avoid allocating a new
    /// version that collides with one already on disk.
    pub fn staged_versions_for(&self, address: &[u8; 32]) -> Vec<u32> {
        self.entries
            .get(address)
            .map(|v| v.iter().map(|e| e.key_version).collect())
            .unwrap_or_default()
    }

    /// Insert or replace one entry by `(address, key_version)`. Returned
    /// bool is `true` when the entry was newly inserted, `false` when it
    /// replaced an existing entry with the same address AND
    /// `key_version`. Mainly useful for tests that want to populate the
    /// keystore programmatically.
    pub fn upsert(&mut self, address: [u8; 32], entry: KeystoreEntry) -> bool {
        let bucket = self.entries.entry(address).or_default();
        if let Some(slot) = bucket
            .iter_mut()
            .find(|e| e.key_version == entry.key_version)
        {
            *slot = entry;
            return false;
        }
        bucket.push(entry);
        bucket.sort_by_key(|e| e.key_version);
        true
    }

    /// Merge every entry from `other` into `self`. Phase 4 Gap A
    /// semantics: file-driven entries are merged by `(address,
    /// key_version)`, NOT by `address` alone. A file entry with the
    /// same `(address, key_version)` overrides the genesis entry
    /// (preserves pre-Phase-4 semantics for the common single-version
    /// case). A file entry with a NEW `key_version` ADDS a new staged
    /// version slot for that address — the rotation-staging path.
    pub fn merge(&mut self, other: Keystore) {
        for (addr, entries) in other.entries {
            for entry in entries {
                let _ = self.upsert(addr, entry);
            }
        }
    }

    /// Reload `path` into `self` if its mtime has advanced since the
    /// last successful load. Returns `Ok(true)` when a reload actually
    /// happened, `Ok(false)` when the file was untouched (or does not
    /// exist — the caller treats a missing keystore file as "no extra
    /// seeds"). Errors propagate from parsing.
    ///
    /// Reload semantics: entries in the file are merged ON TOP of the
    /// existing map by `(address, key_version)` (Phase 4 Gap A) —
    /// entries seeded from genesis config are preserved when the file
    /// adds new versions for the same address; same-version overrides
    /// match the pre-Phase-4 single-version behaviour for D-06
    /// dynamic-seed staging.
    pub fn reload_if_changed(&mut self, path: &Path) -> Result<bool> {
        let metadata = match fs::metadata(path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // Absent file: treat as "no extra seeds" and remember
                // the absence so we do not spam re-reads.
                self.last_mtime = None;
                return Ok(false);
            }
            Err(e) => {
                return Err(e)
                    .with_context(|| format!("failed to stat keystore file {}", path.display()));
            }
        };
        let mtime = metadata.modified().ok();
        if mtime == self.last_mtime && self.last_mtime.is_some() {
            return Ok(false);
        }
        let reloaded = Self::load_from_file(path)?;
        self.merge(reloaded);
        self.last_mtime = mtime;
        Ok(true)
    }
}

#[cfg(test)]
mod tests;

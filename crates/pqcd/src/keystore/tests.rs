// SPDX-License-Identifier: BUSL-1.1
//! Tests for `keystore`.
//!
//! Extracted from `keystore.rs` 2026-05-10. `use super::*;`
//! brings every private item from the parent module into scope.

use super::*;
use crate::node::ValidatorConfig;
use pqc_crypto::AlgId;
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn tempdir(label: &str) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let path = std::env::temp_dir().join(format!(
        "pqcd-keystore-{label}-{}-{unique}-{n}",
        std::process::id()
    ));
    fs::create_dir_all(&path).unwrap();
    path
}

fn validator_cfg(
    node_id: &str,
    address: [u8; 32],
    seed: [u8; 32],
    include_seed: bool,
) -> ValidatorConfig {
    let pk = ml_dsa_public_key_from_seed(AlgId::MlDsa65, &seed).unwrap();
    ValidatorConfig {
        node_id: node_id.to_owned(),
        address_hex: hex::encode(address),
        sig_alg_id: AlgId::MlDsa65.as_u16(),
        public_key_hex: hex::encode(pk),
        archival_sk_hex: None,
        commit_seed_hex: if include_seed {
            Some(hex::encode(seed))
        } else {
            None
        },
    }
}

/// Helper: build a single `KeystoreEntry` from raw seed material with
/// the public key derived + cached. Mirrors the production loader.
fn make_entry(seed: [u8; 32], key_version: u32) -> KeystoreEntry {
    let pk = ml_dsa_public_key_from_seed(AlgId::MlDsa65, &seed).unwrap();
    KeystoreEntry {
        sig_alg_id: AlgId::MlDsa65,
        commit_seed: seed,
        key_version,
        public_key: pk,
        archival_sk: None,
    }
}

#[test]
fn from_validators_with_seeds_loads_entries() {
    let cfgs = vec![
        validator_cfg("v1", [0xA1; 32], [0x11; 32], true),
        validator_cfg("v2", [0xA2; 32], [0x22; 32], true),
    ];
    let ks = Keystore::from_validators(&cfgs, true).expect("build");
    assert_eq!(ks.len(), 2);
    assert_eq!(ks.distinct_addresses(), 2);
    let e = ks.get(&[0xA1; 32]).expect("a1 present");
    assert_eq!(e.sig_alg_id, AlgId::MlDsa65);
    assert_eq!(e.commit_seed, [0x11; 32]);
    assert_eq!(e.key_version, DEFAULT_KEY_VERSION);
    assert!(ks.contains(&[0xA2; 32]));
    assert!(!ks.contains(&[0xA3; 32]));
}

#[test]
fn from_validators_without_seeds_is_empty() {
    let cfgs = vec![
        validator_cfg("v1", [0xA1; 32], [0x11; 32], false),
        validator_cfg("v2", [0xA2; 32], [0x22; 32], false),
    ];
    let ks = Keystore::from_validators(&cfgs, false).expect("build");
    assert!(ks.is_empty());
}

#[test]
fn from_validators_skips_entries_without_commit_seed() {
    let cfgs = vec![
        validator_cfg("v1", [0xA1; 32], [0x11; 32], true),
        validator_cfg("v2", [0xA2; 32], [0x22; 32], false),
    ];
    let ks = Keystore::from_validators(&cfgs, true).expect("build");
    assert_eq!(ks.len(), 1);
    assert!(ks.contains(&[0xA1; 32]));
    assert!(!ks.contains(&[0xA2; 32]));
}

#[test]
fn from_validators_rejects_seed_pk_mismatch() {
    // Build a config with mismatched seed vs declared pk.
    let address = [0xA1; 32];
    let real_seed = [0x11; 32];
    let bogus_seed = [0x99; 32];
    let real_pk = ml_dsa_public_key_from_seed(AlgId::MlDsa65, &real_seed).unwrap();
    let cfg = ValidatorConfig {
        node_id: "v1".into(),
        address_hex: hex::encode(address),
        sig_alg_id: AlgId::MlDsa65.as_u16(),
        archival_sk_hex: None,
        // pk says real_seed, but seed field gives bogus_seed → fail.
        public_key_hex: hex::encode(real_pk),
        commit_seed_hex: Some(hex::encode(bogus_seed)),
    };
    let err = Keystore::from_validators(&[cfg], true).expect_err("mismatch must error");
    let msg = format!("{err}");
    assert!(
        msg.contains("does not match public_key_hex"),
        "expected mismatch msg, got: {msg}"
    );
}

#[test]
fn missing_key_lookup_returns_none() {
    let cfgs = vec![validator_cfg("v1", [0xA1; 32], [0x11; 32], true)];
    let ks = Keystore::from_validators(&cfgs, true).expect("build");
    assert!(ks.get(&[0xFF; 32]).is_none());
    assert!(ks.get_latest(&[0xFF; 32]).is_none());
    assert!(ks.get_for_pk(&[0xFF; 32], &[0u8; 1952]).is_none());
}

#[test]
fn load_from_file_parses_json_envelope() {
    let dir = tempdir("load_from_file");
    let path = dir.join("keystore.json");
    let body = serde_json::json!({
        "validators": [
            {
                "address_hex": hex::encode([0xB1u8; 32]),
                "sig_alg_id": AlgId::MlDsa65.as_u16(),
                "commit_seed_hex": hex::encode([0x42u8; 32]),
            },
            {
                "address_hex": format!("0x{}", hex::encode([0xB2u8; 32])),
                "sig_alg_id": AlgId::MlDsa65.as_u16(),
                "commit_seed_hex": hex::encode([0x43u8; 32]),
            }
        ]
    });
    fs::write(&path, serde_json::to_vec_pretty(&body).unwrap()).unwrap();
    let ks = Keystore::load_from_file(&path).expect("load");
    assert_eq!(ks.len(), 2);
    assert_eq!(ks.get(&[0xB1; 32]).unwrap().commit_seed, [0x42; 32]);
    assert_eq!(ks.get(&[0xB2; 32]).unwrap().commit_seed, [0x43; 32]);
    // Default key_version = 1 when omitted (back-compat).
    assert_eq!(ks.get(&[0xB1; 32]).unwrap().key_version, 1);
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn reload_if_changed_picks_up_new_entries() {
    let dir = tempdir("reload_adds");
    let path = dir.join("keystore.json");
    // Start with one entry.
    let body_v1 = serde_json::json!({
        "validators": [
            {
                "address_hex": hex::encode([0xC1u8; 32]),
                "sig_alg_id": AlgId::MlDsa65.as_u16(),
                "commit_seed_hex": hex::encode([0x01u8; 32]),
            }
        ]
    });
    fs::write(&path, serde_json::to_vec_pretty(&body_v1).unwrap()).unwrap();

    let mut ks = Keystore::new();
    let changed = ks.reload_if_changed(&path).expect("first load");
    assert!(changed, "first load must report changed=true");
    assert_eq!(ks.len(), 1);

    // A second call with no file changes is a no-op (short-circuits
    // on matching mtime — at 1-ns mtime resolution this can still
    // register a false-positive on some filesystems, so we only
    // assert the result is sane, not strictly `changed=false`).
    let _ = ks.reload_if_changed(&path).expect("no-op reload");

    // Rewrite with a second entry; force mtime to move forward.
    let body_v2 = serde_json::json!({
        "validators": [
            {
                "address_hex": hex::encode([0xC1u8; 32]),
                "sig_alg_id": AlgId::MlDsa65.as_u16(),
                "commit_seed_hex": hex::encode([0x01u8; 32]),
            },
            {
                "address_hex": hex::encode([0xC2u8; 32]),
                "sig_alg_id": AlgId::MlDsa65.as_u16(),
                "commit_seed_hex": hex::encode([0x02u8; 32]),
            }
        ]
    });
    // Wait a short moment to ensure mtime moves on low-resolution fs.
    std::thread::sleep(std::time::Duration::from_millis(15));
    fs::write(&path, serde_json::to_vec_pretty(&body_v2).unwrap()).unwrap();

    let changed = ks.reload_if_changed(&path).expect("second load");
    assert!(changed, "second load must report changed=true");
    assert_eq!(ks.len(), 2);
    assert!(ks.contains(&[0xC1; 32]));
    assert!(ks.contains(&[0xC2; 32]));
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn reload_if_changed_missing_file_returns_false() {
    let dir = tempdir("reload_missing");
    let path = dir.join("nope.json");
    let mut ks = Keystore::new();
    let changed = ks.reload_if_changed(&path).expect("missing ok");
    assert!(!changed);
    assert!(ks.is_empty());
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn reload_merges_onto_genesis_entries() {
    // Simulate the integrated scenario: keystore starts with a
    // genesis-seeded entry, then a file reload adds new validators
    // that were registered on-chain.
    let genesis_cfg = vec![validator_cfg("v1", [0xD1; 32], [0x11; 32], true)];
    let mut ks = Keystore::from_validators(&genesis_cfg, true).expect("genesis");
    assert_eq!(ks.len(), 1);

    let dir = tempdir("reload_merge");
    let path = dir.join("keystore.json");
    let body = serde_json::json!({
        "validators": [
            {
                "address_hex": hex::encode([0xD2u8; 32]),
                "sig_alg_id": AlgId::MlDsa65.as_u16(),
                "commit_seed_hex": hex::encode([0x22u8; 32]),
            }
        ]
    });
    fs::write(&path, serde_json::to_vec_pretty(&body).unwrap()).unwrap();

    let changed = ks.reload_if_changed(&path).expect("reload");
    assert!(changed);
    assert_eq!(ks.len(), 2, "genesis entry preserved + file entry added");
    assert!(ks.contains(&[0xD1; 32]));
    assert!(ks.contains(&[0xD2; 32]));
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn upsert_replaces_existing_entry_at_same_version() {
    let mut ks = Keystore::new();
    let addr = [0xE1; 32];
    assert!(ks.upsert(addr, make_entry([0x01; 32], 1)));
    assert!(!ks.upsert(addr, make_entry([0x02; 32], 1)));
    assert_eq!(ks.get(&addr).unwrap().commit_seed, [0x02; 32]);
}

// ── Phase 4 Gap A: multi-version semantics ─────────────────────────

#[test]
fn keystore_loads_multi_version_entries() {
    // Phase 4 Gap A core: two entries for the same address, distinct
    // key_version values. Both must be present and queryable.
    let dir = tempdir("multi_version_load");
    let path = dir.join("keystore.json");
    let addr = [0xF1u8; 32];
    let v1_seed = [0x11u8; 32];
    let v2_seed = [0x22u8; 32];
    let body = serde_json::json!({
        "validators": [
            {
                "address_hex": hex::encode(addr),
                "sig_alg_id": AlgId::MlDsa65.as_u16(),
                "commit_seed_hex": hex::encode(v1_seed),
                "key_version": 1,
            },
            {
                "address_hex": hex::encode(addr),
                "sig_alg_id": AlgId::MlDsa65.as_u16(),
                "commit_seed_hex": hex::encode(v2_seed),
                "key_version": 2,
            }
        ]
    });
    fs::write(&path, serde_json::to_vec_pretty(&body).unwrap()).unwrap();
    let ks = Keystore::load_from_file(&path).expect("load multi-version");
    assert_eq!(ks.len(), 2, "two staged entries");
    assert_eq!(ks.distinct_addresses(), 1, "one validator address");
    assert_eq!(ks.staged_versions_for(&addr), vec![1, 2]);
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn get_for_pk_finds_correct_version() {
    // Build a multi-version keystore in-memory + assert the lookup
    // resolves by derived public key, not by version number.
    let mut ks = Keystore::new();
    let addr = [0xF2u8; 32];
    let v1 = make_entry([0x11; 32], 1);
    let v2 = make_entry([0x22; 32], 2);
    let v1_pk = v1.public_key.clone();
    let v2_pk = v2.public_key.clone();
    ks.upsert(addr, v1);
    ks.upsert(addr, v2);

    let found_v1 = ks.get_for_pk(&addr, &v1_pk).expect("v1 lookup");
    assert_eq!(found_v1.key_version, 1);
    assert_eq!(found_v1.commit_seed, [0x11; 32]);

    let found_v2 = ks.get_for_pk(&addr, &v2_pk).expect("v2 lookup");
    assert_eq!(found_v2.key_version, 2);
    assert_eq!(found_v2.commit_seed, [0x22; 32]);
}

#[test]
fn get_for_pk_returns_none_when_pk_not_staged() {
    // Operator missed the pre-ship deadline: the on-chain
    // `consensus_pk` doesn't match any staged version. Producer must
    // get None (not panic, not return the wrong key).
    let mut ks = Keystore::new();
    let addr = [0xF3u8; 32];
    ks.upsert(addr, make_entry([0x11; 32], 1));

    // Random pk that doesn't match any staged seed.
    let rogue_pk = vec![0xFFu8; 32];
    assert!(
        ks.get_for_pk(&addr, &rogue_pk).is_none(),
        "unstaged pk must return None (caller skips signing)"
    );

    // Sanity: get_latest still returns the v1 entry — non-rotation
    // call sites that don't care about pk-match are unaffected.
    assert_eq!(ks.get_latest(&addr).unwrap().commit_seed, [0x11; 32]);
}

#[test]
fn get_latest_back_compat_returns_highest_version() {
    // get_latest() / get() must return the highest-key_version
    // entry, NOT the first-inserted. Critical for non-rotation
    // call-sites (archival, cold-storage, light-client) that want
    // "the current signing material".
    let mut ks = Keystore::new();
    let addr = [0xF4u8; 32];

    // Insert v3 first, then v1, then v2 — exercises the ascending-sort
    // invariant maintained by insert_versioned/upsert.
    ks.upsert(addr, make_entry([0x33; 32], 3));
    ks.upsert(addr, make_entry([0x11; 32], 1));
    ks.upsert(addr, make_entry([0x22; 32], 2));

    let latest = ks.get_latest(&addr).expect("latest");
    assert_eq!(latest.key_version, 3);
    assert_eq!(latest.commit_seed, [0x33; 32]);

    // get() is the back-compat alias.
    assert_eq!(ks.get(&addr).unwrap().key_version, 3);
}

#[test]
fn legacy_single_entry_loader_back_compat() {
    // A keystore.json written before Phase 4 (no `key_version` field)
    // MUST still load. Defaults to `key_version = 1`. This is the
    // operator-no-break invariant from the research §1.5 test list.
    let dir = tempdir("legacy_format");
    let path = dir.join("keystore.json");
    let body = serde_json::json!({
        "validators": [
            {
                "address_hex": hex::encode([0xB1u8; 32]),
                "sig_alg_id": AlgId::MlDsa65.as_u16(),
                "commit_seed_hex": hex::encode([0x42u8; 32]),
                // NO key_version — legacy file shape
            }
        ]
    });
    fs::write(&path, serde_json::to_vec_pretty(&body).unwrap()).unwrap();
    let ks = Keystore::load_from_file(&path).expect("legacy load");
    let entry = ks.get(&[0xB1; 32]).unwrap();
    assert_eq!(entry.key_version, 1, "legacy entries default to v1");
    assert_eq!(entry.commit_seed, [0x42; 32]);
    assert_eq!(ks.staged_versions_for(&[0xB1; 32]), vec![1]);
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn load_from_file_rejects_duplicate_address_and_version() {
    // Two entries with the same (address, key_version) is a config
    // error — the loader MUST refuse, since `get_for_pk` would have
    // ambiguous semantics.
    let dir = tempdir("dup_version");
    let path = dir.join("keystore.json");
    let addr = [0xA8u8; 32];
    let body = serde_json::json!({
        "validators": [
            {
                "address_hex": hex::encode(addr),
                "sig_alg_id": AlgId::MlDsa65.as_u16(),
                "commit_seed_hex": hex::encode([0x11u8; 32]),
                "key_version": 2,
            },
            {
                "address_hex": hex::encode(addr),
                "sig_alg_id": AlgId::MlDsa65.as_u16(),
                "commit_seed_hex": hex::encode([0x22u8; 32]),
                "key_version": 2,  // duplicate
            }
        ]
    });
    fs::write(&path, serde_json::to_vec_pretty(&body).unwrap()).unwrap();
    let err = Keystore::load_from_file(&path).expect_err("dup must error");
    let msg = format!("{err}");
    assert!(
        msg.contains("duplicate keystore entry") && msg.contains("key_version 2"),
        "expected duplicate error, got: {msg}"
    );
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn load_from_file_rejects_archival_sk_with_wrong_length() {
    // SLH-DSA-SHAKE-256s sk is 128 bytes (FIPS 205 §10.3). Anything
    // else is operator error and must not silently load — `archival_sk`
    // would be passed downstream to the SLH signer with a malformed
    // length and produce confusing failures at first epoch_root.
    let dir = tempdir("archival_sk_wrong_len");
    let path = dir.join("keystore.json");
    let body = serde_json::json!({
        "validators": [
            {
                "address_hex": hex::encode([0xC1u8; 32]),
                "sig_alg_id": AlgId::MlDsa65.as_u16(),
                "commit_seed_hex": hex::encode([0x11u8; 32]),
                // 64 bytes instead of 128 — wrong length for SLH-DSA-SHAKE-256s
                "archival_sk_hex": hex::encode([0xAAu8; 64]),
            }
        ]
    });
    fs::write(&path, serde_json::to_vec_pretty(&body).unwrap()).unwrap();
    let err = Keystore::load_from_file(&path).expect_err("wrong-length archival sk must error");
    let msg = format!("{err}");
    assert!(
        msg.contains("archival_sk_hex must be") && msg.contains("128"),
        "expected length-mismatch error citing 128, got: {msg}"
    );
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn load_from_file_rejects_archival_sk_with_invalid_hex() {
    // Non-hex characters in archival_sk_hex must surface as a parse
    // error, not silently produce an empty `archival_sk`.
    let dir = tempdir("archival_sk_bad_hex");
    let path = dir.join("keystore.json");
    let body = serde_json::json!({
        "validators": [
            {
                "address_hex": hex::encode([0xC2u8; 32]),
                "sig_alg_id": AlgId::MlDsa65.as_u16(),
                "commit_seed_hex": hex::encode([0x22u8; 32]),
                // 'z' is not a hex digit
                "archival_sk_hex": "zz".repeat(128),
            }
        ]
    });
    fs::write(&path, serde_json::to_vec_pretty(&body).unwrap()).unwrap();
    let err = Keystore::load_from_file(&path).expect_err("non-hex archival sk must error");
    let msg = format!("{err}");
    assert!(
        msg.contains("archival_sk_hex is not valid hex"),
        "expected hex-decode error, got: {msg}"
    );
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn load_from_file_accepts_well_formed_archival_sk() {
    // Positive case mirroring the two negative tests above — a
    // 128-byte hex string is accepted and round-trips into the
    // entry's `archival_sk` field.
    let dir = tempdir("archival_sk_ok");
    let path = dir.join("keystore.json");
    let archival = vec![0xCDu8; pqc_types::archival::SLH_DSA_SHAKE_256S_SK_LEN];
    let body = serde_json::json!({
        "validators": [
            {
                "address_hex": hex::encode([0xC3u8; 32]),
                "sig_alg_id": AlgId::MlDsa65.as_u16(),
                "commit_seed_hex": hex::encode([0x33u8; 32]),
                "archival_sk_hex": hex::encode(&archival),
            }
        ]
    });
    fs::write(&path, serde_json::to_vec_pretty(&body).unwrap()).unwrap();
    let ks = Keystore::load_from_file(&path).expect("well-formed archival sk loads");
    let entry = ks.get(&[0xC3u8; 32]).expect("entry present");
    assert_eq!(
        entry.archival_sk.as_deref(),
        Some(archival.as_slice()),
        "archival_sk should round-trip into the entry"
    );
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn merge_combines_versions_per_address() {
    // Genesis from-validators path produces v1 entries. A subsequent
    // file load adds v2 for the SAME address. Merge MUST keep both —
    // the producer's `get_for_pk` will pick whichever matches
    // on-chain `consensus_pk`.
    let addr = [0xD1u8; 32];
    let v1_seed = [0x11u8; 32];
    let v2_seed = [0x22u8; 32];

    let genesis_cfg = vec![validator_cfg("v1", addr, v1_seed, true)];
    let mut ks = Keystore::from_validators(&genesis_cfg, true).expect("genesis");
    assert_eq!(ks.staged_versions_for(&addr), vec![1]);

    let dir = tempdir("merge_versions");
    let path = dir.join("keystore.json");
    let body = serde_json::json!({
        "validators": [
            {
                "address_hex": hex::encode(addr),
                "sig_alg_id": AlgId::MlDsa65.as_u16(),
                "commit_seed_hex": hex::encode(v2_seed),
                "key_version": 2,
            }
        ]
    });
    fs::write(&path, serde_json::to_vec_pretty(&body).unwrap()).unwrap();
    let changed = ks.reload_if_changed(&path).expect("merge");
    assert!(changed);
    assert_eq!(
        ks.staged_versions_for(&addr),
        vec![1, 2],
        "both versions present after merge"
    );

    // get_for_pk picks the right one for each.
    let v1_pk = ml_dsa_public_key_from_seed(AlgId::MlDsa65, &v1_seed).unwrap();
    let v2_pk = ml_dsa_public_key_from_seed(AlgId::MlDsa65, &v2_seed).unwrap();
    assert_eq!(ks.get_for_pk(&addr, &v1_pk).unwrap().commit_seed, v1_seed);
    assert_eq!(ks.get_for_pk(&addr, &v2_pk).unwrap().commit_seed, v2_seed);

    // get_latest picks v2.
    assert_eq!(ks.get_latest(&addr).unwrap().key_version, 2);
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn upsert_sorts_by_ascending_version() {
    // Invariant: the in-memory vector is sorted ascending so
    // `last()` is the highest version. Insert out of order and
    // verify.
    let mut ks = Keystore::new();
    let addr = [0xE7u8; 32];
    ks.upsert(addr, make_entry([0x05; 32], 5));
    ks.upsert(addr, make_entry([0x02; 32], 2));
    ks.upsert(addr, make_entry([0x09; 32], 9));
    ks.upsert(addr, make_entry([0x01; 32], 1));
    assert_eq!(ks.staged_versions_for(&addr), vec![1, 2, 5, 9]);
    assert_eq!(ks.get_latest(&addr).unwrap().key_version, 9);
}

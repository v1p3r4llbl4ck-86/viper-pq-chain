// SPDX-License-Identifier: BUSL-1.1
//! Tests for `wallet`.
//!
//! Extracted from `wallet.rs` 2026-05-10. `use super::*;`
//! brings every private item from the parent module into scope.

//! Phase 4 Gap A — `pqcd wallet rotate-consensus-key --in-place`
//! helper unit tests. Pin the file-format invariants used by the
//! operator workflow:
//!
//! - pre-flight returns the right next-version slot per address;
//! - append produces a file that loads back via the same
//!   `Keystore::load_from_file` the running pqcd uses.
use super::*;
use pqcd::keystore::Keystore;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn tempdir(label: &str) -> std::path::PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let path = std::env::temp_dir().join(format!(
        "pqcd-in-place-{label}-{}-{unique}-{n}",
        std::process::id()
    ));
    std::fs::create_dir_all(&path).unwrap();
    path
}

fn write_keystore(path: &std::path::Path, body: serde_json::Value) {
    std::fs::write(path, serde_json::to_vec_pretty(&body).unwrap()).unwrap();
}

#[test]
fn preflight_returns_next_version_for_known_address() {
    let dir = tempdir("preflight_known");
    let path = dir.join("keystore.json");
    let addr = [0xAAu8; 32];
    write_keystore(
        &path,
        serde_json::json!({
            "validators": [
                {
                    "address_hex": hex::encode(addr),
                    "sig_alg_id": 4u16,
                    "commit_seed_hex": hex::encode([0x11u8; 32]),
                    "key_version": 1,
                }
            ]
        }),
    );
    let next = preflight_in_place_keystore(&path, &addr).expect("preflight");
    assert_eq!(next, 2, "max(1) + 1 = 2");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn preflight_returns_two_when_address_missing_legacy_default() {
    // Legacy file without a key_version field — the implicit
    // default is 1, so the next slot is 2.
    let dir = tempdir("preflight_legacy");
    let path = dir.join("keystore.json");
    let addr = [0xBBu8; 32];
    write_keystore(
        &path,
        serde_json::json!({
            "validators": [
                {
                    "address_hex": hex::encode(addr),
                    "sig_alg_id": 4u16,
                    "commit_seed_hex": hex::encode([0x22u8; 32]),
                    // NO key_version
                }
            ]
        }),
    );
    let next = preflight_in_place_keystore(&path, &addr).expect("preflight");
    assert_eq!(next, 2, "legacy entry is implicit v1 → next is 2");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn preflight_returns_two_when_address_unseen() {
    // The address has no entries in the file (D-06: dynamically
    // registered validator that hasn't been pre-staged). Next slot
    // is DEFAULT_KEY_VERSION + 1 = 2 — we never write a v1 entry
    // here because the running pqcd's `from_validators` pass already
    // produced one.
    let dir = tempdir("preflight_unseen");
    let path = dir.join("keystore.json");
    let known_addr = [0xCCu8; 32];
    let unknown_addr = [0xDDu8; 32];
    write_keystore(
        &path,
        serde_json::json!({
            "validators": [
                {
                    "address_hex": hex::encode(known_addr),
                    "sig_alg_id": 4u16,
                    "commit_seed_hex": hex::encode([0x33u8; 32]),
                    "key_version": 1,
                }
            ]
        }),
    );
    let next = preflight_in_place_keystore(&path, &unknown_addr).expect("preflight");
    assert_eq!(next, 2);
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn preflight_picks_max_plus_one_after_multiple_rotations() {
    // Operator has already rotated several times — file holds v1 +
    // v2 + v3. The CLI should pick v4 next.
    let dir = tempdir("preflight_max3");
    let path = dir.join("keystore.json");
    let addr = [0xEEu8; 32];
    let body = serde_json::json!({
        "validators": [
            {
                "address_hex": hex::encode(addr),
                "sig_alg_id": 4u16,
                "commit_seed_hex": hex::encode([0x11u8; 32]),
                "key_version": 1,
            },
            {
                "address_hex": hex::encode(addr),
                "sig_alg_id": 4u16,
                "commit_seed_hex": hex::encode([0x22u8; 32]),
                "key_version": 2,
            },
            {
                "address_hex": hex::encode(addr),
                "sig_alg_id": 4u16,
                "commit_seed_hex": hex::encode([0x33u8; 32]),
                "key_version": 3,
            }
        ]
    });
    write_keystore(&path, body);
    let next = preflight_in_place_keystore(&path, &addr).expect("preflight");
    assert_eq!(next, 4);
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn preflight_bails_on_missing_file() {
    let dir = tempdir("preflight_missing");
    let path = dir.join("nope.json");
    let err = preflight_in_place_keystore(&path, &[0u8; 32]).expect_err("must error");
    assert!(format!("{err}").contains("does not exist"));
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn append_round_trips_through_keystore_loader() {
    // The file written by `append_versioned_keystore_entry` MUST be
    // loadable by `Keystore::load_from_file` — the same parser the
    // running pqcd uses on the `refresh_keystore_from_file` tick.
    // A file that only round-trips through `serde_json` would be a
    // silent operator footgun.
    use pqc_crypto::{ml_dsa_public_key_from_seed, AlgId};

    let dir = tempdir("append_round_trip");
    let path = dir.join("keystore.json");
    let addr = [0xFFu8; 32];
    let v1_seed = [0x11u8; 32];
    // Initial file: v1 entry.
    write_keystore(
        &path,
        serde_json::json!({
            "validators": [
                {
                    "address_hex": hex::encode(addr),
                    "sig_alg_id": AlgId::MlDsa65.as_u16(),
                    "commit_seed_hex": hex::encode(v1_seed),
                    "key_version": 1,
                }
            ]
        }),
    );

    // Append v2.
    let v2_seed = [0x22u8; 32];
    append_versioned_keystore_entry(&path, &addr, AlgId::MlDsa65, &v2_seed, 2).expect("append");

    // Now reload via the production loader.
    let ks = Keystore::load_from_file(&path).expect("load");
    assert_eq!(ks.staged_versions_for(&addr), vec![1, 2]);

    // get_for_pk must find both seeds.
    let v1_pk = ml_dsa_public_key_from_seed(AlgId::MlDsa65, &v1_seed).unwrap();
    let v2_pk = ml_dsa_public_key_from_seed(AlgId::MlDsa65, &v2_seed).unwrap();
    assert_eq!(ks.get_for_pk(&addr, &v1_pk).unwrap().commit_seed, v1_seed);
    assert_eq!(ks.get_for_pk(&addr, &v2_pk).unwrap().commit_seed, v2_seed);
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn append_atomic_no_tmp_left_behind() {
    // After a successful append, the .tmp file MUST NOT exist
    // (the rename consumed it).
    use pqc_crypto::AlgId;

    let dir = tempdir("append_no_tmp");
    let path = dir.join("keystore.json");
    let addr = [0x77u8; 32];
    write_keystore(
        &path,
        serde_json::json!({
            "validators": [
                {
                    "address_hex": hex::encode(addr),
                    "sig_alg_id": AlgId::MlDsa65.as_u16(),
                    "commit_seed_hex": hex::encode([0x11u8; 32]),
                    "key_version": 1,
                }
            ]
        }),
    );
    append_versioned_keystore_entry(&path, &addr, AlgId::MlDsa65, &[0x22u8; 32], 2)
        .expect("append");
    let tmp_path = path.with_extension("json.tmp");
    assert!(!tmp_path.exists(), "tmp file must be renamed away");
    std::fs::remove_dir_all(&dir).ok();
}

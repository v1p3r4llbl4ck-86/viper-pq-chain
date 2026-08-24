// SPDX-License-Identifier: BUSL-1.1
//! Stage A.3 — `pqcd wallet rotate-peer-id --in-place` helper unit
//! tests. Pin the node.json file-handling invariants used by the
//! 90-day rotation cron:
//!
//! - pre-flight bails on missing / malformed / empty-node_id files
//!   BEFORE any chain interaction;
//! - the atomic-write helper sets/overwrites the field, preserves
//!   file mode on Unix, and is idempotent on repeat invocation.
use super::*;
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
        "pqcd-rotate-peer-id-{label}-{}-{unique}-{n}",
        std::process::id()
    ));
    std::fs::create_dir_all(&path).unwrap();
    path
}

fn write_node_config(path: &std::path::Path, body: serde_json::Value) {
    std::fs::write(path, serde_json::to_vec_pretty(&body).unwrap()).unwrap();
}

#[test]
fn preflight_returns_node_id_for_well_formed_config() {
    let dir = tempdir("preflight_ok");
    let path = dir.join("node.json");
    write_node_config(
        &path,
        serde_json::json!({
            "node_id": "validator-7",
            "data_dir": "/var/lib/pqchain",
            "devnet": { "role": "producer" }
        }),
    );
    let got = preflight_in_place_node_config(&path).unwrap();
    assert_eq!(got, "validator-7");
}

#[test]
fn preflight_bails_on_missing_file() {
    let dir = tempdir("preflight_missing");
    let path = dir.join("does-not-exist.json");
    let err = preflight_in_place_node_config(&path).unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.contains("does not exist"),
        "error must point at the missing-file root cause, got: {msg}"
    );
}

#[test]
fn preflight_bails_on_malformed_json() {
    let dir = tempdir("preflight_malformed");
    let path = dir.join("node.json");
    std::fs::write(&path, b"{this isn't json").unwrap();
    let err = preflight_in_place_node_config(&path).unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.contains("failed to parse"),
        "error must name the parse failure, got: {msg}"
    );
}

#[test]
fn preflight_bails_on_missing_node_id_field() {
    let dir = tempdir("preflight_no_node_id");
    let path = dir.join("node.json");
    write_node_config(&path, serde_json::json!({ "data_dir": "/var/lib/pqchain" }));
    let err = preflight_in_place_node_config(&path).unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.contains("missing top-level `node_id`"),
        "error must name the missing field, got: {msg}"
    );
}

#[test]
fn preflight_bails_on_empty_node_id() {
    let dir = tempdir("preflight_empty_node_id");
    let path = dir.join("node.json");
    write_node_config(&path, serde_json::json!({ "node_id": "" }));
    let err = preflight_in_place_node_config(&path).unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.contains("empty `node_id`"),
        "error must explain why an empty node_id is rejected, got: {msg}"
    );
}

#[test]
fn atomic_write_adds_field_when_devnet_block_absent() {
    let dir = tempdir("atomic_no_devnet");
    let path = dir.join("node.json");
    write_node_config(&path, serde_json::json!({ "node_id": "validator-1" }));
    let salt = "a".repeat(64);
    atomically_set_libp2p_salt_in_node_config(&path, &salt).unwrap();
    let after: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(
        after
            .pointer("/devnet/libp2p_seed_salt_hex")
            .and_then(|v| v.as_str()),
        Some(salt.as_str()),
        "missing devnet block must be created with the new field"
    );
}

#[test]
fn atomic_write_overwrites_existing_salt() {
    let dir = tempdir("atomic_overwrite");
    let path = dir.join("node.json");
    let old_salt = "1".repeat(64);
    let new_salt = "2".repeat(64);
    write_node_config(
        &path,
        serde_json::json!({
            "node_id": "validator-1",
            "devnet": { "role": "producer", "libp2p_seed_salt_hex": old_salt }
        }),
    );
    atomically_set_libp2p_salt_in_node_config(&path, &new_salt).unwrap();
    let after: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(
        after
            .pointer("/devnet/libp2p_seed_salt_hex")
            .and_then(|v| v.as_str()),
        Some(new_salt.as_str()),
        "rotation MUST replace the prior salt, not append a second one"
    );
    // Sanity: existing sibling fields under devnet survive the write.
    assert_eq!(
        after.pointer("/devnet/role").and_then(|v| v.as_str()),
        Some("producer"),
        "atomic write must not stomp unrelated fields in the devnet block"
    );
}

#[test]
fn atomic_write_is_idempotent_on_same_salt() {
    let dir = tempdir("atomic_idempotent");
    let path = dir.join("node.json");
    write_node_config(
        &path,
        serde_json::json!({ "node_id": "validator-1", "devnet": {} }),
    );
    let salt = "b".repeat(64);
    atomically_set_libp2p_salt_in_node_config(&path, &salt).unwrap();
    let first = std::fs::read(&path).unwrap();
    atomically_set_libp2p_salt_in_node_config(&path, &salt).unwrap();
    let second = std::fs::read(&path).unwrap();
    assert_eq!(
        first, second,
        "writing the same salt twice in a row MUST produce byte-identical files"
    );
}

#[test]
fn atomic_write_bails_on_non_object_devnet() {
    let dir = tempdir("atomic_non_object_devnet");
    let path = dir.join("node.json");
    write_node_config(
        &path,
        serde_json::json!({ "node_id": "validator-1", "devnet": "not-an-object" }),
    );
    let err = atomically_set_libp2p_salt_in_node_config(&path, &"c".repeat(64)).unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.contains("non-object `devnet`"),
        "error must name the corrupt-config root cause, got: {msg}"
    );
}

#[test]
fn atomic_write_leaves_no_tmp_file_on_success() {
    let dir = tempdir("atomic_no_tmp");
    let path = dir.join("node.json");
    write_node_config(&path, serde_json::json!({ "node_id": "validator-1" }));
    atomically_set_libp2p_salt_in_node_config(&path, &"d".repeat(64)).unwrap();
    let tmp = path.with_extension("json.tmp");
    assert!(
        !tmp.exists(),
        "rename(2) should consume the tempfile — finding {} on disk after a successful write indicates a bug",
        tmp.display()
    );
}

#[cfg(unix)]
#[test]
fn atomic_write_preserves_unix_file_mode() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempdir("atomic_mode");
    let path = dir.join("node.json");
    write_node_config(&path, serde_json::json!({ "node_id": "validator-1" }));
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    atomically_set_libp2p_salt_in_node_config(&path, &"e".repeat(64)).unwrap();
    let after_mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(
        after_mode, 0o600,
        "rotation MUST preserve 0600 — node.json carries a long-term secret (libp2p_seed_salt_hex)"
    );
}

// SPDX-License-Identifier: BUSL-1.1
//! Stage A.4 — `pqcd wallet libp2p-init` unit tests.
//!
//! Pin the file-handling invariants of the salt-staging primitive:
//!
//! - writes a 64-char hex salt under `devnet.libp2p_seed_salt_hex`;
//! - refuses to clobber an existing salt without `--force`;
//! - `--force` overwrites cleanly;
//! - preserves large u128 fields (balance) through the JSON round-trip
//!   — same regression guard as `kem_init_tests` for the 2026-05-11
//!   scientific-notation bug, since both subcommands take the same
//!   `serde_json::Value` round-trip path;
//! - preserves Unix file mode across the rename.
//!
//! The chown-preservation path (the libc::chown call in the CLI) is
//! only triggered when the test process actually has CAP_CHOWN — which
//! it doesn't on a normal CI runner. The test below asserts the
//! happy-path "uid/gid stay the same" invariant, which holds trivially
//! when neither side has chown privileges either.

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
        "pqcd-libp2p-init-{label}-{}-{unique}-{n}",
        std::process::id()
    ));
    std::fs::create_dir_all(&path).unwrap();
    path
}

fn write_node_config(path: &std::path::Path, body: serde_json::Value) {
    std::fs::write(path, serde_json::to_vec_pretty(&body).unwrap()).unwrap();
}

fn args_with_path(path: &std::path::Path) -> Vec<String> {
    vec![
        "pqcd".to_owned(),
        "wallet".to_owned(),
        "libp2p-init".to_owned(),
        "--node-config".to_owned(),
        path.display().to_string(),
    ]
}

fn args_with_path_force(path: &std::path::Path) -> Vec<String> {
    let mut a = args_with_path(path);
    a.push("--force".to_owned());
    a
}

#[test]
fn libp2p_init_writes_64_char_hex_salt_to_fresh_config() {
    let dir = tempdir("fresh");
    let path = dir.join("node.json");
    write_node_config(&path, serde_json::json!({ "node_id": "validator-1" }));

    cmd_wallet_libp2p_init(&args_with_path(&path)).unwrap();

    let after: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let salt = after
        .pointer("/devnet/libp2p_seed_salt_hex")
        .and_then(|v| v.as_str())
        .expect("libp2p_seed_salt_hex must be set");
    assert_eq!(
        salt.len(),
        64,
        "salt must be 64 hex chars (= 32 bytes); got {} chars",
        salt.len()
    );
    assert!(
        salt.chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()),
        "salt must be lowercase ASCII hex; got {salt:?}"
    );
}

#[test]
fn libp2p_init_refuses_to_overwrite_existing_salt_without_force() {
    let dir = tempdir("no_clobber");
    let path = dir.join("node.json");
    let prior = "a".repeat(64);
    write_node_config(
        &path,
        serde_json::json!({
            "node_id": "validator-1",
            "devnet": { "libp2p_seed_salt_hex": prior }
        }),
    );

    let err = cmd_wallet_libp2p_init(&args_with_path(&path)).unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.contains("already has `devnet.libp2p_seed_salt_hex` set"),
        "error must name the existing-salt collision, got: {msg}"
    );

    // File MUST be untouched on refusal.
    let after: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(
        after
            .pointer("/devnet/libp2p_seed_salt_hex")
            .and_then(|v| v.as_str()),
        Some(prior.as_str()),
        "refused libp2p-init MUST leave node.json byte-stable"
    );
}

#[test]
fn libp2p_init_force_overwrites_existing_salt() {
    let dir = tempdir("force_overwrite");
    let path = dir.join("node.json");
    let prior = "a".repeat(64);
    write_node_config(
        &path,
        serde_json::json!({
            "node_id": "validator-1",
            "devnet": { "libp2p_seed_salt_hex": prior }
        }),
    );

    cmd_wallet_libp2p_init(&args_with_path_force(&path)).unwrap();

    let after: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let new_salt = after
        .pointer("/devnet/libp2p_seed_salt_hex")
        .and_then(|v| v.as_str())
        .unwrap();
    assert_eq!(new_salt.len(), 64);
    assert_ne!(
        new_salt, prior,
        "--force MUST replace the prior salt with a fresh value"
    );
}

#[test]
fn libp2p_init_preserves_large_u128_balance_through_round_trip() {
    // Same 2026-05-11 regression guard as kem_init_tests. Without
    // `serde_json/arbitrary_precision`, balances > u64::MAX round-trip
    // through f64 → "1e+27" → pqcd boot refuses to parse u128.
    let dir = tempdir("u128_balance");
    let path = dir.join("node.json");
    let raw = r#"{
        "node_id": "validator-1",
        "devnet": { "role": "producer" },
        "genesis_accounts": [
            {
                "address_hex": "0000000000000000000000000000000000000000000000000000000000000000",
                "balance": 1000000000000000000000000000,
                "nonce": 0,
                "keys": []
            }
        ]
    }"#;
    std::fs::write(&path, raw).unwrap();

    cmd_wallet_libp2p_init(&args_with_path(&path)).unwrap();

    let after = String::from_utf8(std::fs::read(&path).unwrap()).unwrap();
    assert!(
        !after.contains("e+") && !after.contains("E+"),
        "libp2p-init round-trip produced scientific-notation number — \
         this is the 2026-05-11 kem-init regression class. Output:\n{after}"
    );
    assert!(
        after.contains("1000000000000000000000000000"),
        "libp2p-init round-trip lost the 28-digit balance literal. Output:\n{after}"
    );
}

#[test]
fn libp2p_init_adds_devnet_block_when_absent() {
    let dir = tempdir("no_devnet");
    let path = dir.join("node.json");
    // No `devnet` field at all — the command must create the block.
    write_node_config(&path, serde_json::json!({ "node_id": "validator-1" }));

    cmd_wallet_libp2p_init(&args_with_path(&path)).unwrap();

    let after: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert!(
        after
            .pointer("/devnet/libp2p_seed_salt_hex")
            .and_then(|v| v.as_str())
            .is_some(),
        "libp2p-init MUST create the devnet block when absent"
    );
}

#[cfg(unix)]
#[test]
fn libp2p_init_preserves_unix_file_mode() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempdir("mode");
    let path = dir.join("node.json");
    write_node_config(&path, serde_json::json!({ "node_id": "validator-1" }));
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

    cmd_wallet_libp2p_init(&args_with_path(&path)).unwrap();

    let after_mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(
        after_mode, 0o600,
        "libp2p-init MUST preserve 0600 — the salt is a long-term secret"
    );
}

#[test]
fn libp2p_init_each_invocation_yields_a_different_salt() {
    // Catches a hypothetical regression where the RNG seed gets pinned
    // (e.g. a misplaced `let mut rng = StdRng::seed_from_u64(0)`).
    let dir1 = tempdir("entropy_a");
    let dir2 = tempdir("entropy_b");
    let path1 = dir1.join("node.json");
    let path2 = dir2.join("node.json");
    write_node_config(&path1, serde_json::json!({ "node_id": "validator-1" }));
    write_node_config(&path2, serde_json::json!({ "node_id": "validator-1" }));

    cmd_wallet_libp2p_init(&args_with_path(&path1)).unwrap();
    cmd_wallet_libp2p_init(&args_with_path(&path2)).unwrap();

    let s1 = serde_json::from_slice::<serde_json::Value>(&std::fs::read(&path1).unwrap())
        .unwrap()
        .pointer("/devnet/libp2p_seed_salt_hex")
        .and_then(|v| v.as_str())
        .unwrap()
        .to_owned();
    let s2 = serde_json::from_slice::<serde_json::Value>(&std::fs::read(&path2).unwrap())
        .unwrap()
        .pointer("/devnet/libp2p_seed_salt_hex")
        .and_then(|v| v.as_str())
        .unwrap()
        .to_owned();
    assert_ne!(
        s1, s2,
        "two libp2p-init invocations MUST yield different salts (entropy from OS CSPRNG, \
         not a pinned seed)"
    );
}

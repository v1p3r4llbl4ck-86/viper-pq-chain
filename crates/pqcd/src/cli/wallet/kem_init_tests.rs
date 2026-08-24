// SPDX-License-Identifier: BUSL-1.1
//! Regression tests for `pqcd wallet kem-init` JSON round-trip.
//!
//! Background — the 2026-05-11 bug
//! ===============================
//!
//! `cmd_wallet_kem_init` round-trips `node.json` through
//! `serde_json::Value` to inject `devnet.kem_seed_salt_hex`. Without
//! the `arbitrary_precision` feature, serde_json stores numbers that
//! don't fit in `u64` (max ~1.8e19) as `f64`. `node.json` contains
//! `genesis_accounts[*].balance` values like
//! `1000000000000000000000000000` (1e27, a 28-digit u128) — these
//! exceeded `u64::MAX` and round-tripped through `f64`, re-emerging
//! from `to_vec_pretty` as the scientific-notation string `1e+27`.
//!
//! Rust's `u128` deserializer at pqcd boot then rejects `1e+27`
//! ("expected `,` or `}` at line N column M"), and pqcd refuses to
//! start. On 2026-05-11 this stalled viper-pq-1 for ~5 minutes after
//! the kem-init pass; the workaround was a Python recovery script
//! that restored node.json from backup and injected the salt
//! manually (a one-off migration script (private)).
//!
//! The fix: enable `serde_json/arbitrary_precision` in `pqcd`'s
//! `Cargo.toml`. With this feature, serde_json preserves the
//! original textual representation of every number — large
//! integers stay as `1000000000000000000000000000`, and the
//! round-trip is information-preserving.
//!
//! These tests pin that behaviour:
//!
//! 1. `kem_init_preserves_large_u128_balance` — a synthetic
//!    node.json with a 28-digit `balance` round-trips through the
//!    same `serde_json::Value`-based serialise path that
//!    `cmd_wallet_kem_init` uses. The output must NOT contain
//!    `e+` (scientific notation). It must contain the original
//!    28-digit literal exactly.
//!
//! 2. `kem_init_output_reparses_as_node_config` — the round-tripped
//!    output must parse back into `NodeConfig` without error. This
//!    is the actual property that broke on 2026-05-11 — pqcd's
//!    deserializer rejected the scientific output.
//!
//! 3. `kem_init_field_actually_inserted` — sanity check that the
//!    salt field IS inserted under `devnet`, not at the top level
//!    (the second bug surfaced in commit a814bd0f).

use serde::Deserialize;

/// Minimal mirror of the load-bearing fields from node.json. We
/// can't easily construct a full `NodeConfig` test fixture
/// (~40 required fields with cross-field validation), so this test
/// fixture parses just the field that actually broke pqcd boot on
/// 2026-05-11: a u128 `balance` inside `genesis_accounts[]`. The
/// scientific-notation regression manifested as a u128 parse error
/// at this exact field.
#[derive(Debug, Deserialize)]
struct TestGenesisAccount {
    #[serde(default)]
    #[allow(dead_code)]
    address_hex: String,
    balance: u128,
}

#[derive(Debug, Deserialize)]
struct TestNodeConfigShape {
    genesis_accounts: Vec<TestGenesisAccount>,
}

/// Build a synthetic node.json string with a 28-digit u128 balance,
/// matching the schema of `genesis-viper-pq-1.json` after the
/// 2026-05-11 migration.
fn synthetic_node_json() -> String {
    r#"{
  "chain_id": "viper-pq-1",
  "data_dir": "/var/lib/pqchain",
  "role": "producer",
  "bind_addr": "127.0.0.1:26657",
  "node_id": "test-node",
  "devnet": {
    "role": "producer",
    "block_time_ms": 500,
    "distributed_signing": true,
    "validators": [
      {
        "node_id": "validator-1",
        "address_hex": "0000000000000000000000000000000000000000000000000000000000000000",
        "sig_alg_id": 2,
        "public_key_hex": ""
      }
    ],
    "proposer_address_hex": "0000000000000000000000000000000000000000000000000000000000000000"
  },
  "genesis_accounts": [
    {
      "address_hex": "0000000000000000000000000000000000000000000000000000000000000000",
      "balance": 1000000000000000000000000000,
      "nonce": 0,
      "keys": []
    }
  ]
}
"#
    .to_string()
}

/// Apply the same `serde_json::Value`-based mutation that
/// `cmd_wallet_kem_init` performs, returning the serialised result.
fn round_trip_with_salt_injection(input: &str, salt_hex: &str) -> String {
    let mut json: serde_json::Value = serde_json::from_str(input).expect("input is valid JSON");
    let devnet_obj = json
        .as_object_mut()
        .unwrap()
        .entry("devnet")
        .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
    let devnet_map = devnet_obj.as_object_mut().unwrap();
    devnet_map.insert(
        "kem_seed_salt_hex".to_owned(),
        serde_json::Value::String(salt_hex.to_owned()),
    );
    let mut serialised = serde_json::to_vec_pretty(&json).expect("serialise");
    serialised.push(b'\n');
    String::from_utf8(serialised).expect("utf-8")
}

#[test]
fn kem_init_preserves_large_u128_balance() {
    // 2026-05-11 regression: without arbitrary_precision, this
    // string-survives the round-trip as `1e+27`. With it enabled,
    // the original 28-digit literal is preserved verbatim.
    let salt = "a".repeat(64);
    let out = round_trip_with_salt_injection(&synthetic_node_json(), &salt);

    // Hard-fail criterion: no scientific-notation numbers in the
    // output. JSON allows `e+`/`E+` only in numbers; if it appears
    // it is unambiguously a numeric token (string fields would have
    // it inside quotes, but our test schema has none).
    assert!(
        !out.contains("e+") && !out.contains("E+"),
        "kem-init round-trip produced scientific-notation number — this is the 2026-05-11 bug. \
         Output:\n{out}"
    );

    // Soft-positive: the original 28-digit literal must appear
    // verbatim. This catches a regression where the value gets
    // round-tripped to a different but still-decimal representation
    // (e.g. some imaginable future fix that emits
    // `1.0e+27` → `10000…` with a different number of digits).
    assert!(
        out.contains("1000000000000000000000000000"),
        "kem-init round-trip lost the original 28-digit balance literal. Output:\n{out}"
    );
}

#[test]
fn kem_init_output_reparses_u128_balance() {
    // The actual property that broke pqcd boot on 2026-05-11: the
    // round-tripped JSON's `balance` field must deserialise as
    // u128. Without arbitrary_precision the field came back as
    // `1e+27` which the Rust u128 deserializer rejects with
    // "expected `,` or `}` at line N column M" — the exact error
    // that stalled the chain.
    let salt = "b".repeat(64);
    let out = round_trip_with_salt_injection(&synthetic_node_json(), &salt);
    let parsed: TestNodeConfigShape = serde_json::from_str(&out).expect(
        "round-tripped node.json must deserialise u128 `balance` — \
         if this fails the kem-init bug has regressed",
    );
    assert_eq!(parsed.genesis_accounts.len(), 1);
    assert_eq!(
        parsed.genesis_accounts[0].balance, 1_000_000_000_000_000_000_000_000_000_u128,
        "balance field must preserve exact u128 value through the round-trip"
    );
}

#[test]
fn kem_init_field_actually_inserted() {
    // a814bd0f sibling pin: the salt must land under `devnet`, NOT
    // at the top level. The Rust loader reads
    // `config.devnet.kem_seed_salt_hex`; a top-level placement is
    // silently ignored.
    let salt = "c".repeat(64);
    let out = round_trip_with_salt_injection(&synthetic_node_json(), &salt);
    let parsed: serde_json::Value = serde_json::from_str(&out).expect("reparses");
    let devnet_salt = parsed
        .get("devnet")
        .and_then(|d| d.get("kem_seed_salt_hex"))
        .and_then(|v| v.as_str());
    assert_eq!(
        devnet_salt,
        Some(salt.as_str()),
        "salt must land at devnet.kem_seed_salt_hex"
    );
    assert!(
        parsed.get("kem_seed_salt_hex").is_none(),
        "salt must NOT be at top level"
    );
}

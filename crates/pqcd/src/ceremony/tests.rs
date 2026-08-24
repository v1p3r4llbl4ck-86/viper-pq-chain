// SPDX-License-Identifier: BUSL-1.1
//! Tests for `ceremony`.
//!
//! Extracted from `ceremony.rs` 2026-05-10. `use super::*;`
//! brings every private item from the parent module into scope.

use super::*;

#[test]
fn chain_id_hex_round_trips_through_hex_decode() {
    let hex = compute_chain_id_hex("viper-pq-1");
    assert_eq!(hex, "76697065722d70712d31");
    assert_eq!(hex::decode(&hex).unwrap(), b"viper-pq-1");
}

#[test]
fn chain_id_hex_kind_test() {
    // Sanity for the kind smoke chain_id used in the 2026-05-05
    // session — pin so a future refactor cannot silently break it.
    assert_eq!(
        compute_chain_id_hex("viper-pq-kind-test"),
        "76697065722d70712d6b696e642d74657374"
    );
}

#[test]
fn derive_validator_entry_is_deterministic_for_same_seed_and_chain() {
    let seed = [0x42u8; 32];
    let chain = b"viper-pq-test";
    let v1 = derive_validator_entry("v1".into(), chain, &seed, AlgId::MlDsa65).unwrap();
    let v2 = derive_validator_entry("v1".into(), chain, &seed, AlgId::MlDsa65).unwrap();
    assert_eq!(v1.address_hex, v2.address_hex);
    assert_eq!(v1.public_key_hex, v2.public_key_hex);
}

#[test]
fn derive_validator_entry_is_chain_id_bound_per_adr_053_t1_3() {
    // §T1.3 — the same seed under different chain_ids MUST produce
    // different addresses (cross-chain replay protection).
    let seed = [0x42u8; 32];
    let v_a = derive_validator_entry("v".into(), b"chain-a", &seed, AlgId::MlDsa65).unwrap();
    let v_b = derive_validator_entry("v".into(), b"chain-b", &seed, AlgId::MlDsa65).unwrap();
    assert_ne!(
        v_a.address_hex, v_b.address_hex,
        "ADR-053 §T1.3 binding violated: same seed → same address across chains"
    );
    // Public-key bytes are derived from the seed alone (no chain_id),
    // so they DO match across chains — that's correct, the chain
    // binding lives in the address tag, not the keypair.
    assert_eq!(v_a.public_key_hex, v_b.public_key_hex);
}

#[test]
fn generate_seeds_emits_n_distinct_seeds() {
    let seeds = generate_seeds(8);
    assert_eq!(seeds.len(), 8);
    // Probability of collision under OS CSPRNG is 2^-256 — the
    // assertion is effectively a tautology, but it pins the call
    // site against accidental "fill all from a constant" regression.
    let mut sorted: Vec<[u8; 32]> = seeds.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(sorted.len(), 8);
}

#[test]
fn ceremony_values_have_expected_top_level_keys() {
    let cfg = CeremonyConfig {
        chain_id: "viper-pq-ceremony-test".into(),
        validators: 3,
        block_time_ms: 500,
        genesis_balance: 1_000_000_000,
        image_repository: "ghcr.io/v1p3r4llbl4ck-86".into(),
        image_tag: "main".into(),
        release_name: "viper-test".into(),
        namespace: "viper".into(),
        deploy_token: None,
    };
    let (values, validators) = generate_ceremony_values(&cfg).unwrap();
    assert_eq!(validators.len(), 3);
    // Top-level Helm keys the chart consumes.
    for key in ["image", "chain", "chainNode", "notary", "kubernetes"] {
        assert!(values.get(key).is_some(), "missing top-level key: {key}");
    }
    // chain.genesis.inline must round-trip via JSON parse — the
    // chart hands it verbatim to a ConfigMap, so a malformed string
    // would only surface at `kubectl apply` time.
    let genesis_inline = values["chain"]["genesis"]["inline"].as_str().unwrap();
    let _: serde_json::Value =
        serde_json::from_str(genesis_inline).expect("genesis.inline must be valid JSON");
    // Per-role node.json is emitted under chainNode.<role>.config.nodeJson.
    for role in ["validator", "sentry", "full", "rpc", "archive", "bootnode"] {
        let node_json = values["chainNode"][role]["config"]["nodeJson"]
            .as_str()
            .unwrap_or_else(|| panic!("role {role} missing nodeJson"));
        let parsed: serde_json::Value = serde_json::from_str(node_json)
            .unwrap_or_else(|e| panic!("role {role} nodeJson invalid JSON: {e}"));
        // Required fields the binary refuses to start without.
        assert!(
            parsed.get("chain_id_hex").is_some(),
            "{role}: chain_id_hex missing"
        );
        assert!(
            parsed.get("fee_params").is_some(),
            "{role}: fee_params missing"
        );
        assert!(parsed.get("devnet").is_some(), "{role}: devnet missing");
        assert!(
            parsed["devnet"]["validators"].as_array().is_some(),
            "{role}: devnet.validators[] missing"
        );
        assert!(
            parsed["devnet"]["proposer_address_hex"].is_string(),
            "{role}: devnet.proposer_address_hex missing"
        );
    }
}

#[test]
fn build_secrets_manifest_emits_validator_consensus_secret() {
    let cfg = CeremonyConfig {
        chain_id: "viper-pq-test".into(),
        validators: 1,
        block_time_ms: 500,
        genesis_balance: 1_000_000_000,
        image_repository: "ghcr.io/v1p3r4llbl4ck-86".into(),
        image_tag: "main".into(),
        release_name: "viper-test".into(),
        namespace: "viper".into(),
        deploy_token: None,
    };
    let (_values, validators) = generate_ceremony_values(&cfg).unwrap();
    let yaml = build_secrets_manifest(&cfg, "viper", &validators).unwrap();
    assert!(yaml.contains("kind: Secret"));
    assert!(yaml.contains("name: viper-validator-1-consensus"));
    assert!(yaml.contains("consensus_seed:"));
    assert!(yaml.contains(&validators[0].commit_seed_hex));
    // No deploy token → no dockerconfigjson Secret.
    assert!(!yaml.contains("dockerconfigjson"));
}

#[test]
fn build_secrets_manifest_appends_dockerconfigjson_for_deploy_token() {
    let cfg = CeremonyConfig {
        chain_id: "viper-pq-test".into(),
        validators: 1,
        block_time_ms: 500,
        genesis_balance: 1_000_000_000,
        image_repository: "ghcr.io/v1p3r4llbl4ck-86".into(),
        image_tag: "main".into(),
        release_name: "viper-test".into(),
        namespace: "viper".into(),
        deploy_token: Some(DeployToken {
            registry: "registry.example.com".into(),
            username: "gitlab+deploy-token-k8s".into(),
            password: "abc123token".into(),
        }),
    };
    let (_values, validators) = generate_ceremony_values(&cfg).unwrap();
    let yaml = build_secrets_manifest(&cfg, "viper", &validators).unwrap();
    assert!(yaml.contains("kubernetes.io/dockerconfigjson"));
    assert!(yaml.contains("name: viper-registry-pull"));
    // The decoded `.dockerconfigjson` should round-trip back to the
    // original creds — pin so a refactor to base64-encoding can't
    // silently corrupt the auth blob.
    let line = yaml
        .lines()
        .find(|l| l.contains(".dockerconfigjson:"))
        .expect(".dockerconfigjson line missing");
    let b64 = line
        .split_once(": ")
        .map(|(_, v)| v.trim())
        .expect("malformed yaml line");
    let decoded = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, b64).unwrap();
    let parsed: serde_json::Value = serde_json::from_slice(&decoded).unwrap();
    assert_eq!(
        parsed["auths"]["registry.example.com"]["username"],
        "gitlab+deploy-token-k8s"
    );
}

#[test]
fn libp2p_wires_validator_multiaddr_into_sentry_and_full_bootstrap_peers() {
    let cfg = CeremonyConfig {
        chain_id: "viper-pq-libp2p-test".into(),
        validators: 3,
        block_time_ms: 500,
        genesis_balance: 1_000_000_000,
        image_repository: "ghcr.io/v1p3r4llbl4ck-86".into(),
        image_tag: "main".into(),
        release_name: "alfa".into(),
        namespace: "beta".into(),
        deploy_token: None,
    };
    let (values, _) = generate_ceremony_values(&cfg).unwrap();
    // G-01: every role's node.json carries its own libp2p / KEM salts and the
    // PeerIds the ceremony bakes into bootstrap lists are derived WITH them.
    let salt_of = |role: &str| -> [u8; 32] {
        let node_json = values["chainNode"][role]["config"]["nodeJson"]
            .as_str()
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_str(node_json).unwrap();
        let hex_salt = parsed["devnet"]["libp2p_seed_salt_hex"]
            .as_str()
            .unwrap_or_else(|| panic!("{role}: libp2p_seed_salt_hex"));
        let kem = parsed["devnet"]["kem_seed_salt_hex"].as_str().unwrap();
        assert_eq!(hex_salt.len(), 64, "{role}: 32-byte libp2p salt");
        assert_eq!(kem.len(), 64, "{role}: 32-byte KEM salt");
        assert_ne!(hex_salt, kem, "{role}: the two salts differ");
        hex::decode(hex_salt).unwrap().try_into().unwrap()
    };
    assert_ne!(
        salt_of("validator"),
        salt_of("sentry"),
        "salts differ per role"
    );
    // ADR-069 §3: the validator pod's node_id is its pod name.
    let expected_validator_peer_id = crate::p2p::deterministic_peer_id(
        "alfa-viper-pq-chain-pqcd-validator-0",
        Some(&salt_of("validator")),
    )
    .to_string();
    let expected_multiaddr = format!(
        "/dns4/alfa-viper-pq-chain-pqcd-validator-headless.beta.svc.cluster.local/tcp/26656/p2p/{expected_validator_peer_id}"
    );

    // ADR-069 §4: sentries dial the validator; full / rpc / archive /
    // bootnode dial the sentries (one multiaddr per sentry replica).
    let expected_sentry_multiaddrs: Vec<String> = (0..2)
        .map(|i| {
            let pod = format!("alfa-viper-pq-chain-pqcd-sentry-{i}");
            let pid = crate::p2p::deterministic_peer_id(&pod, Some(&salt_of("sentry")));
            format!("/dns4/{pod}.alfa-viper-pq-chain-pqcd-sentry-headless.beta.svc.cluster.local/tcp/26656/p2p/{pid}")
        })
        .collect();
    for role in ["full", "rpc", "archive", "bootnode"] {
        let node_json = values["chainNode"][role]["config"]["nodeJson"]
            .as_str()
            .unwrap_or_else(|| panic!("{role}: nodeJson"));
        let parsed: serde_json::Value = serde_json::from_str(node_json).unwrap();
        let bootstrap: Vec<&str> = parsed["libp2p"]["bootstrap_peers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert_eq!(
            bootstrap, expected_sentry_multiaddrs,
            "{role}: dials the sentries"
        );
        assert!(
            parsed["libp2p"]["public_listen"].is_string(),
            "{role}: public_listen"
        );
        assert_eq!(parsed["devnet"]["role"].as_str(), Some(role));
    }
    let role = "sentry";
    {
        let node_json = values["chainNode"][role]["config"]["nodeJson"]
            .as_str()
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_str(node_json).unwrap();
        assert_eq!(
            parsed["libp2p"]["enable"].as_bool(),
            Some(true),
            "{role}: libp2p.enable must be true"
        );
        let bootstrap = parsed["libp2p"]["bootstrap_peers"]
            .as_array()
            .unwrap_or_else(|| panic!("{role}: bootstrap_peers must be array"));
        assert_eq!(
            bootstrap.len(),
            1,
            "{role}: exactly one bootstrap peer (the validator)"
        );
        assert_eq!(
            bootstrap[0].as_str(),
            Some(expected_multiaddr.as_str()),
            "{role}: bootstrap multiaddr binds release-name + namespace + PeerId"
        );
    }
    // sentry uses vfn_listen, full uses public_listen, validator uses
    // validator_listen — three distinct ADR-041 §3 binding fields.
    let validator_node = values["chainNode"]["validator"]["config"]["nodeJson"]
        .as_str()
        .unwrap();
    let v: serde_json::Value = serde_json::from_str(validator_node).unwrap();
    assert!(
        v["libp2p"]["validator_listen"].is_string(),
        "validator: validator_listen field present"
    );
    assert!(
        v["libp2p"]["bootstrap_peers"]
            .as_array()
            .unwrap()
            .is_empty(),
        "validator: empty bootstrap_peers (sentries dial *to* it)"
    );
}

#[test]
fn deploy_token_emits_pull_secret_block() {
    let cfg = CeremonyConfig {
        chain_id: "viper-pq-test".into(),
        validators: 1,
        block_time_ms: 500,
        genesis_balance: 1_000_000_000,
        image_repository: "ghcr.io/v1p3r4llbl4ck-86".into(),
        image_tag: "main".into(),
        release_name: "viper-test".into(),
        namespace: "viper".into(),
        deploy_token: Some(DeployToken {
            registry: "registry.example.com".into(),
            username: "gitlab+deploy-token-k8s".into(),
            password: "abc123token".into(),
        }),
    };
    let (values, _) = generate_ceremony_values(&cfg).unwrap();
    let pull_secrets = values["image"]["pullSecrets"].as_array().unwrap();
    assert_eq!(pull_secrets.len(), 1);
    assert_eq!(pull_secrets[0]["name"], "viper-registry-pull");
    let secrets = values["kubernetes"]["secrets"].as_array().unwrap();
    // Validator consensus secret + registry pull secret = 2 entries.
    assert_eq!(secrets.len(), 2);
    let registry_secret = secrets
        .iter()
        .find(|s| s["name"] == "viper-registry-pull")
        .expect("registry pull secret missing");
    assert_eq!(registry_secret["type"], "kubernetes.io/dockerconfigjson");
}

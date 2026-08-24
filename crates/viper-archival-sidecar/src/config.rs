// SPDX-License-Identifier: BUSL-1.1
//! Sidecar configuration — TOML-backed.
//!
//! The sidecar runs with a single declarative config file. Every deployment
//! variable (node URL, TSA endpoints, keystore, retry policy) lives here.
//! There are no CLI overrides in M4.5 — operators edit the file and restart
//! the daemon; the surface stays narrow and auditable.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// One RFC 3161 TSA endpoint definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TsaEndpoint {
    /// Human-readable label — used in logs + metrics labels.
    pub name: String,
    /// Full URL (including scheme) to the TSA's RFC 3161 `TimeStampReq`
    /// endpoint. Production endpoints typically speak
    /// `application/timestamp-query`; URLs must be https:// in production.
    pub url: String,
    /// Optional basic-auth credentials for TSAs that require them (e.g.
    /// the InfoCert sandbox). Format: `user:password`. Omit in the file
    /// for anonymous TSAs; pass via the `VIPER_TSA_<NAME>_AUTH` env var
    /// so the file never carries secrets.
    #[serde(default)]
    pub basic_auth_env: Option<String>,
}

/// Top-level sidecar configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SidecarConfig {
    /// pqcd HTTP API URL (e.g. `http://127.0.0.1:3000`).
    pub node_url: String,
    /// Seconds between archival-records polls (default 60 s).
    #[serde(default = "default_poll_interval")]
    pub poll_interval_secs: u64,
    /// First epoch to consider — useful for restarting a sidecar without
    /// re-anchoring old epochs (the chain already has their anchors).
    /// Default 0 = start from the earliest record.
    #[serde(default)]
    pub starting_epoch: u64,
    /// Maximum records to pull per poll tick (caps mempool-flood risk
    /// during catch-up). Default 32.
    #[serde(default = "default_batch_limit")]
    pub batch_limit: usize,
    /// Sidecar's ML-DSA keystore (encrypted JSON per SPEC-WALLET-001 §4).
    pub keystore_path: String,
    /// Passphrase for the keystore. Empty → fall back to the
    /// `VIPER_PASSPHRASE` env var, then interactive prompt.
    #[serde(default)]
    pub keystore_passphrase: String,
    /// List of TSA endpoints. The sidecar fans out to all of them for each
    /// record per SPEC §6.3 "≥ 2 EU-qualified TSAs" requirement.
    pub tsa_endpoints: Vec<TsaEndpoint>,
    /// Optional Prometheus metrics bind address (`127.0.0.1:9635` default).
    /// Set to `null` / empty string to disable.
    #[serde(default)]
    pub metrics_addr: Option<String>,
    /// Minimum anchors required per record before the sidecar considers it
    /// "anchored enough". Default 1 — any AddAnchor satisfies. Operators
    /// running a multi-TSA redundancy policy set this to 2 or more.
    #[serde(default = "default_required_anchors")]
    pub required_anchors: usize,
}

fn default_poll_interval() -> u64 {
    60
}
fn default_batch_limit() -> usize {
    32
}
fn default_required_anchors() -> usize {
    1
}

impl SidecarConfig {
    /// Resolve basic-auth credentials for a TSA endpoint, reading from the
    /// environment variable named in `basic_auth_env`.
    pub fn resolve_basic_auth(&self, endpoint: &TsaEndpoint) -> Option<(String, String)> {
        let var = endpoint.basic_auth_env.as_ref()?;
        let value = std::env::var(var).ok()?;
        let (user, pw) = value.split_once(':')?;
        Some((user.to_string(), pw.to_string()))
    }

    /// Resolve the keystore passphrase from config, env, or stdin prompt.
    pub fn resolve_passphrase(&self) -> Result<String> {
        if !self.keystore_passphrase.is_empty() {
            return Ok(self.keystore_passphrase.clone());
        }
        if let Ok(env) = std::env::var("VIPER_PASSPHRASE") {
            if !env.is_empty() {
                return Ok(env);
            }
        }
        // Final fallback: stdin prompt. Fails early in headless mode —
        // operators are expected to use the env var.
        anyhow::bail!(
            "no keystore passphrase: set SidecarConfig.keystore_passphrase, \
             VIPER_PASSPHRASE env var, or supply interactively"
        );
    }
}

/// Parse a `sidecar.toml` file from disk.
pub fn load_config(path: &Path) -> Result<SidecarConfig> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read sidecar config from {}", path.display()))?;
    let parsed: SidecarConfig = toml::from_str(&raw)
        .with_context(|| format!("failed to parse sidecar TOML at {}", path.display()))?;
    if parsed.tsa_endpoints.is_empty() {
        anyhow::bail!("sidecar config has no TSA endpoints — at least one is required");
    }
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_config() {
        let toml_src = r#"
            node_url = "http://127.0.0.1:3000"
            keystore_path = "/etc/pqchain/sidecar.keystore.json"

            [[tsa_endpoints]]
            name = "aruba"
            url  = "https://tsa.arubapec.it/tsa"

            [[tsa_endpoints]]
            name = "infocert"
            url  = "https://tsa.infocert.it/rfc3161"
            basic_auth_env = "VIPER_TSA_INFOCERT_AUTH"
        "#;
        let cfg: SidecarConfig = toml::from_str(toml_src).unwrap();
        assert_eq!(cfg.node_url, "http://127.0.0.1:3000");
        assert_eq!(cfg.tsa_endpoints.len(), 2);
        assert_eq!(cfg.poll_interval_secs, 60);
        assert_eq!(cfg.batch_limit, 32);
        assert_eq!(cfg.required_anchors, 1);
        assert_eq!(cfg.starting_epoch, 0);
        assert!(cfg.metrics_addr.is_none());
        assert_eq!(cfg.tsa_endpoints[0].basic_auth_env, None);
        assert_eq!(
            cfg.tsa_endpoints[1].basic_auth_env,
            Some("VIPER_TSA_INFOCERT_AUTH".to_string())
        );
    }

    #[test]
    fn rejects_empty_tsa_list() {
        let toml_src = r#"
            node_url = "http://127.0.0.1:3000"
            keystore_path = "/etc/pqchain/sidecar.keystore.json"
            tsa_endpoints = []
        "#;
        let tmp = std::env::temp_dir().join(format!("sidecar-empty-{}.toml", std::process::id()));
        std::fs::write(&tmp, toml_src).unwrap();
        let err = load_config(&tmp).unwrap_err();
        assert!(format!("{err}").contains("no TSA endpoints"));
        let _ = std::fs::remove_file(&tmp);
    }
}

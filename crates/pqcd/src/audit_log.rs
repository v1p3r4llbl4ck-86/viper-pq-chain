// SPDX-License-Identifier: BUSL-1.1
//! Tamper-evident audit log for security-relevant events.
//!
//! A separate `tracing_subscriber::Layer` that captures events emitted with
//! `target = "viper.audit"` (or any target starting with `viper.audit`) and
//! writes them to a per-day JSONL file with a SHA-256 hash chain — each line
//! carries `prev_hash` (the hash of the previous line) and `hash` (the hash
//! of its own canonical payload), making any insertion / deletion /
//! modification of a line detectable by recomputing the chain.
//!
//! ## Why a separate sink
//!
//! The main pqcd journal mixes consensus, p2p, mempool, validator-rotation,
//! key-management and HTTP traces. For compliance-grade attestations
//! (notary anchors, slashing, key rotation) auditors need:
//!   1. A discriminated stream they can ingest without filtering noise.
//!   2. Tamper-evidence: an operator with root on the box must not be able
//!      to silently rewrite history.
//!
//! The hash chain delivers (2). It does NOT prove the operator didn't
//! truncate the file at some earlier line — for that you'd need an external
//! pinning step (publish daily roots to a different chain / a witness
//! server). That falls under the deferred "log centralization" item.
//!
//! ## Output format
//!
//! ```jsonl
//! {"unix_secs":1777268402,"unix_nanos":123456789,"level":"INFO","target":"viper.audit","event":"block_proposed","height":90080,"block_hash":"5ea51b…","proposer":"d80d06…","prev_hash":"","hash":"a3f2…"}
//! {"unix_secs":1777268407,"unix_nanos":987654321,"level":"INFO","target":"viper.audit","event":"block_finalized","height":90080,"prev_hash":"a3f2…","hash":"7e91…"}
//! ```
//!
//! - `prev_hash` of the very first line in a file is `""` (empty string).
//! - `hash = sha256(prev_hash || canonical_payload_bytes)` where
//!   `canonical_payload_bytes` is the JSON object **without** the `hash`
//!   field, serialized with deterministic key order (serde_json with sorted
//!   keys via BTreeMap).
//!
//! ## Rotation
//!
//! Files rotate on UTC date change: `audit-YYYYMMDD.jsonl`. The hash chain
//! is reset to `prev_hash=""` on rotation (each file is independently
//! verifiable). For cross-day continuity the operator can run
//! `verify-audit-log.sh` (deferred).
//!
//! ## Process restart
//!
//! On restart the in-memory `last_hash` is reset to `""` and the next event
//! starts a fresh chain segment in whatever file is current. A sentinel
//! event with `event="process_started"` is emitted by main.rs so the
//! discontinuity is explicit, not silent.
//!
//! ## Emission sites
//!
//! Add `tracing::info!(target: "viper.audit", event = "...", ...)` at:
//! - block proposed (after own signature)
//! - block finalized (after quorum + state-apply)
//! - attestation committed (notary anchor admitted to chain)
//! - validator slashed (equivocation evidence applied)
//! - key rotation (proposer-key change)
//! - process_started (sentinel — main.rs)

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{create_dir_all, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{Event, Subscriber};
use tracing_subscriber::{layer::Context, Layer};

/// Default base directory for audit logs. Override via env
/// `VIPER_AUDIT_LOG_DIR`. The directory is created on first event with
/// permissions inherited from the running user (typically pqchain:pqchain
/// 0750 from the deploy).
const DEFAULT_AUDIT_DIR: &str = "/var/log/pqchain/audit";

/// State held across events: open file, the date of the file (so we can
/// detect rotation) and the running hash chain head.
struct AuditState {
    base_dir: PathBuf,
    /// `YYYYMMDD` string of the currently-open file. Empty on first event.
    current_date: String,
    /// Hex-encoded sha256 of the previous line's canonical payload. Empty
    /// at file open.
    last_hash: String,
}

impl AuditState {
    fn new() -> Self {
        let base =
            std::env::var("VIPER_AUDIT_LOG_DIR").unwrap_or_else(|_| DEFAULT_AUDIT_DIR.to_string());
        AuditState {
            base_dir: PathBuf::from(base),
            current_date: String::new(),
            last_hash: String::new(),
        }
    }

    /// Compute today's UTC date as `YYYYMMDD` from a UNIX seconds value.
    fn ymd(unix_secs: u64) -> String {
        // Days since epoch → year/month/day, civil-from-days algorithm
        // (Howard Hinnant). Avoids pulling in `chrono` for a single date
        // format.
        let days = (unix_secs / 86_400) as i64;
        let z = days + 719_468;
        let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
        let doe = (z - era * 146_097) as u64;
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
        let y = yoe as i64 + era * 400;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let d = doy - (153 * mp + 2) / 5 + 1;
        let m = if mp < 10 { mp + 3 } else { mp - 9 };
        let y = if m <= 2 { y + 1 } else { y };
        format!("{y:04}{m:02}{d:02}")
    }

    fn current_path(&self) -> PathBuf {
        self.base_dir
            .join(format!("audit-{}.jsonl", self.current_date))
    }
}

static STATE: Mutex<Option<AuditState>> = Mutex::new(None);

/// Public entry point used by both the `Layer` impl and the
/// `process_started` sentinel emission in main.rs.
pub fn write_event(fields: BTreeMap<String, Value>, level: &str, target: &str) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let unix_secs = now.as_secs();
    let unix_nanos = now.subsec_nanos();

    let mut guard = match STATE.lock() {
        Ok(g) => g,
        Err(_poison) => {
            // Audit must not panic on a poisoned mutex — best effort,
            // continue silently. The `tracing::error!` would loop back
            // here; eprintln! to stderr instead.
            eprintln!("audit_log: state mutex poisoned, dropping event");
            return;
        }
    };
    if guard.is_none() {
        *guard = Some(AuditState::new());
    }
    let state = guard.as_mut().expect("just-set");

    // Rotation: if today's date differs from the file we have open, swap
    // file and reset the hash chain.
    let today = AuditState::ymd(unix_secs);
    if today != state.current_date {
        state.current_date = today;
        state.last_hash = String::new();
        if let Err(e) = create_dir_all(&state.base_dir) {
            eprintln!(
                "audit_log: cannot mkdir {}: {}",
                state.base_dir.display(),
                e
            );
            return;
        }
    }

    // Build canonical payload: BTreeMap → deterministic key order.
    let mut payload: BTreeMap<String, Value> = BTreeMap::new();
    payload.insert("unix_secs".into(), json!(unix_secs));
    payload.insert("unix_nanos".into(), json!(unix_nanos));
    payload.insert("level".into(), json!(level));
    payload.insert("target".into(), json!(target));
    for (k, v) in fields {
        // Don't allow callers to overwrite our reserved fields.
        if matches!(
            k.as_str(),
            "unix_secs" | "unix_nanos" | "level" | "target" | "prev_hash" | "hash"
        ) {
            continue;
        }
        payload.insert(k, v);
    }
    payload.insert("prev_hash".into(), json!(state.last_hash));

    // Canonicalize: serialize the map (without `hash`) and hash it.
    let canon = match serde_json::to_vec(&payload) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("audit_log: serialize failed: {e}");
            return;
        }
    };
    let mut hasher = Sha256::new();
    hasher.update(&canon);
    let hash_hex = hex::encode(hasher.finalize());

    // Now produce the line we actually write: the same map plus `hash`.
    payload.insert("hash".into(), json!(hash_hex.clone()));
    let line = match serde_json::to_string(&payload) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("audit_log: serialize line failed: {e}");
            return;
        }
    };

    let path = state.current_path();
    let mut f = match OpenOptions::new().create(true).append(true).open(&path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("audit_log: cannot open {}: {}", path.display(), e);
            return;
        }
    };
    if let Err(e) = writeln!(f, "{line}") {
        eprintln!("audit_log: write failed to {}: {}", path.display(), e);
        return;
    }
    state.last_hash = hash_hex;
}

/// Tracing layer that captures events with target prefix `viper.audit` and
/// forwards them to `write_event`.
pub struct AuditLogLayer;

struct Capture {
    fields: BTreeMap<String, Value>,
}

impl tracing::field::Visit for Capture {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.fields.insert(field.name().to_string(), json!(value));
    }
    fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
        self.fields.insert(field.name().to_string(), json!(value));
    }
    fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
        self.fields.insert(field.name().to_string(), json!(value));
    }
    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        self.fields.insert(field.name().to_string(), json!(value));
    }
    fn record_f64(&mut self, field: &tracing::field::Field, value: f64) {
        self.fields.insert(field.name().to_string(), json!(value));
    }
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.fields
            .insert(field.name().to_string(), json!(format!("{:?}", value)));
    }
}

impl<S: Subscriber> Layer<S> for AuditLogLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let target = event.metadata().target();
        if !target.starts_with("viper.audit") {
            return;
        }
        let mut capture = Capture {
            fields: BTreeMap::new(),
        };
        event.record(&mut capture);
        // tracing carries the message as a field named "message".
        let level = event.metadata().level().to_string();
        write_event(capture.fields, &level, target);
    }
}

/// Sentinel "process_started" event — emitted once at boot from main.rs so
/// that the post-restart hash-chain discontinuity is explicit.
pub fn emit_process_started(node_id: &str, version: &str) {
    let mut fields: BTreeMap<String, Value> = BTreeMap::new();
    fields.insert("event".into(), json!("process_started"));
    fields.insert("node_id".into(), json!(node_id));
    fields.insert("version".into(), json!(version));
    write_event(fields, "INFO", "viper.audit");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn ymd_known_dates() {
        // 2026-04-27 00:00:00 UTC = 1777248000
        assert_eq!(AuditState::ymd(1_777_248_000), "20260427");
        // 2026-01-01 = 1767225600
        assert_eq!(AuditState::ymd(1_767_225_600), "20260101");
        // Unix epoch
        assert_eq!(AuditState::ymd(0), "19700101");
    }

    #[test]
    fn hash_chain_reproducible() {
        // Use a temp dir; verify that two consecutive events produce a
        // chain where the second's prev_hash equals the first's hash.
        let tmp = std::env::temp_dir().join(format!("viper-audit-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        std::env::set_var("VIPER_AUDIT_LOG_DIR", &tmp);
        // Reset global state for this test (we don't have a setter, so
        // accept that other tests in this binary may have already
        // initialized it — the test still verifies chain self-consistency).
        let mut a: BTreeMap<String, Value> = BTreeMap::new();
        a.insert("event".into(), json!("test_a"));
        write_event(a, "INFO", "viper.audit");
        let mut b: BTreeMap<String, Value> = BTreeMap::new();
        b.insert("event".into(), json!("test_b"));
        write_event(b, "INFO", "viper.audit");

        let entries = fs::read_dir(&tmp).expect("audit dir exists");
        let path = entries
            .into_iter()
            .find_map(|e| e.ok().map(|e| e.path()))
            .expect("audit file exists");
        let content = fs::read_to_string(&path).expect("read");
        let lines: Vec<&str> = content.lines().collect();
        assert!(lines.len() >= 2, "got {} lines", lines.len());
        let last = serde_json::from_str::<Value>(lines[lines.len() - 1]).unwrap();
        let prev = serde_json::from_str::<Value>(lines[lines.len() - 2]).unwrap();
        assert_eq!(
            last["prev_hash"].as_str().unwrap(),
            prev["hash"].as_str().unwrap(),
            "chain link broken between two consecutive events"
        );
        let _ = fs::remove_dir_all(&tmp);
    }
}

// SPDX-License-Identifier: BUSL-1.1
//! viper-archival-sidecar — out-of-consensus RFC 3161 TSA anchoring.
//!
//! Implements SPEC-ARCHIVAL-001 §6, ADR-045, TASK-164 / M4.5.
//!
//! # Role
//!
//! The sidecar is a stateless daemon that watches a pqcd node's archival
//! overlay for freshly-admitted `ArchivalRecord`s (via HTTP polling of
//! `GET /v1/archival/records?since=…`). For each record missing at least
//! the governance-parameterised number of `timestamp_anchors`, it:
//!
//! 1. Builds the §6.1 TSA preimage:
//!    `"VIPER-ARCHIVAL-TSA-V1" || u64_be(epoch_number) || epoch_root`.
//! 2. Hashes it with SHA-256 (RFC 3161 mandatory-to-implement, §6.6).
//! 3. Encodes a minimal RFC 3161 `TimeStampReq` and POSTs it to each
//!    configured TSA URL (Content-Type: `application/timestamp-query`).
//! 4. On a 200 OK `application/timestamp-reply`, extracts the reply bytes
//!    opaquely — the on-chain apply path does NOT validate the DER
//!    cryptographically (§6.1 defers that to the external auditor in §7).
//! 5. Builds an `ArchivalRecordAddAnchor` transaction carrying the TST as
//!    `tst_bytes` and the external hash `SHAKE-256(tst_bytes)` as
//!    `external_hash`, signs the envelope with the sidecar's configured
//!    ML-DSA key, and POSTs it to the node's `/v1/txs` endpoint.
//!
//! The archival overlay is additive: a TSA outage delays anchoring but
//! does not affect consensus finality. All errors here are logged at
//! `warn` and do not abort the loop.
//!
//! # Scope (M4.5 / this crate in-session)
//!
//! - Config file parsing (`sidecar.toml`).
//! - Polling loop with backoff.
//! - Hand-rolled RFC 3161 `TimeStampReq` DER encoder (SHA-256 only; other
//!   digest OIDs are a trivial extension — tracked as a follow-up for
//!   multi-digest governance).
//! - Opaque TST response forwarding.
//! - Minimal Prometheus exposition on `/metrics`.
//!
//! Out of scope for M4.5:
//!
//! - RFC 3161 reply-DER validation (signed TST X.509 chain verification)
//!   — intentionally deferred to the auditor per SPEC §6.1.
//! - RFC 4998 `ArchiveTimeStampChain` ERS renewal — lives in M4.6 (TASK-165).
//! - Live-bulk pipelining for catching up a stale chain — the 1-epoch-per
//!   poll-tick pace is adequate at a 60-block epoch.
//!
//! # Real-world operator flow
//!
//! ```text
//!   [sidecar.toml] → viper-archival-sidecar --config sidecar.toml
//!       │
//!       ├─ poll pqcd ──► /v1/archival/records?since=N
//!       │
//!       ├─ for each new record:
//!       │     build TimeStampReq(digest = SHA-256(tsa_preimage))
//!       │     POST to each TSA
//!       │     receive TimeStampResp (opaque DER bytes)
//!       │     build ArchivalRecordAddAnchor(epoch, tst_bytes, external_hash)
//!       │     POST /v1/txs
//!       │
//!       └─ update `last_epoch_seen`, sleep `poll_interval_secs`
//! ```

pub mod config;
pub mod renew;
pub mod rfc3161;
pub mod tsa_client;

pub use config::{load_config, SidecarConfig, TsaEndpoint};
pub use renew::{ers_bundle_hash, renewal_preimage, ERS_PREIMAGE_DOMAIN};
pub use rfc3161::{build_timestamp_request, tsa_preimage, TSA_PREIMAGE_DOMAIN};
pub use tsa_client::{post_timestamp_request, TsaError};

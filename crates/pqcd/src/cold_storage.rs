// SPDX-License-Identifier: BUSL-1.1
//! TASK-188 / TASK-188b — cold-storage rotation (export, sign, anchor, restore).
//!
//! Reads chain blocks `[1..=cutoff]` from the on-disk RocksDB store,
//! batches them in groups of `batch_size` blocks, zstd-compresses each
//! batch, and writes the result to a local output directory along with
//! a per-run manifest JSON. Optionally signs the manifest with the
//! operator's SLH-DSA-SHAKE-256s archival key (TASK-188b §1) and
//! anchors `sha256(canonical_manifest_json)` in an RFC 3161 TSA token
//! (TASK-188b §2). The signed manifest can later be restored on a
//! follower via `pqcd cold-storage-import` (TASK-188b §3).
//!
//! Operator workflow (signed-rotation, with optional S3 push):
//!
//! ```text
//! pqcd cold-storage-export node-config.json \
//!     --cutoff-height $CUTOFF \
//!     --output-dir /var/cache/pqchain/cold/$DATE \
//!     --sign-with-operator $OP_ADDR_HEX \
//!     --anchor-tsa http://timestamp.digicert.com \
//!     --upload-to s3://viper-pq-cold/$DATE/   (s3-upload feature)
//! ```
//!
//! Operator workflow (restore on a fresh follower):
//!
//! ```text
//! aws s3 sync s3://viper-pq-cold/2026-04/ /var/cache/pqchain/cold/2026-04/
//! pqcd cold-storage-import node-config.json /var/cache/pqchain/cold/2026-04/
//! ```
//!
//! # Manifest schema versions
//!
//! - `viper-cold-storage-v1` — TASK-188 export-only landing. Bare batch list,
//!   anchor hash per batch, sha256 per file, no operator signature, no TSA
//!   token. Restore path treats it as untrusted (must pass
//!   `--insecure-no-verify`).
//!
//! - `viper-cold-storage-v2` — TASK-188b. Adds two optional fields:
//!     - `signature`: SLH-DSA-SHAKE-256s over the canonical manifest bytes
//!       (manifest with `signature: None, tsa_token: None`, rendered via
//!       `serde_json::to_vec_pretty` — see `canonical_manifest_bytes`). The
//!       signing preimage prepends `b"VIPER-COLD-STORAGE-MANIFEST-V1"`.
//!     - `tsa_token`: opaque RFC 3161 TimeStampResp DER, base64-encoded.
//!       The TSA imprint is `sha256(b"VIPER-COLD-STORAGE-TSA-V1" ||
//!       canonical_manifest_bytes)`. The token is forwarded to disk
//!       verbatim and the chain does not parse the DER (matches
//!       SPEC-ARCHIVAL-001 §6.1 — TST verification is the auditor's job).
//!
//! Both v2 fields are `Option`. A v2 manifest with neither sig nor token is
//! schema-equivalent to v1 plus a different `schema_version` string.
//!
//! # Why split sign + restore into v2
//!
//! TASK-188's export-only landing closed the operator's "I need to ship
//! cold blocks to S3" gap with no new dependencies. The v2 path adds:
//!
//!   - SLH-DSA-SHAKE-256s manifest signing — re-uses
//!     `pqc_crypto::slh_dsa_shake_256s_sign` and the keystore's
//!     `archival_sk` slot already wired for the in-band archival overlay.
//!     A signed manifest is auditable independently of the operator's S3
//!     bucket policy + IAM.
//!
//!   - RFC 3161 TSA token — re-uses the DER encoder pattern from
//!     `viper-archival-sidecar/src/rfc3161.rs`. (sidecar depends on
//!     pqcd, so we cannot import that crate; the encoder is small enough
//!     to inline. Future cleanup: extract a shared `pqc-tsa` crate when
//!     a third consumer appears.)
//!
//!   - `cold-storage-import` restore path — verifies signature, batch
//!     SHA-256, anchor-hash chain, then replays via
//!     `RocksDbChainStore::append_stored_block`.

use std::{fs, path::Path, time::SystemTime};

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use pqc_consensus::{RocksDbChainStore, StoredBlock};
use pqc_crypto::{
    slh_dsa_shake_256s_sign, AlgId, PqVerifier, PublicKey, Signature, SignatureVerifier,
};
use pqc_types::block::BlockHash;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::keystore::Keystore;

// ── Manifest schema ──────────────────────────────────────────────────────────

/// Manifest schema label written by `export_cold_storage`. Bumped from
/// `viper-cold-storage-v1` (TASK-188) when the optional `signature` and
/// `tsa_token` fields landed (TASK-188b).
pub const MANIFEST_SCHEMA_VERSION_V2: &str = "viper-cold-storage-v2";

/// Schema label written by the TASK-188 export-only path. Restore code
/// still accepts v1 manifests but refuses to verify them — the operator
/// must explicitly pass `--insecure-no-verify` to import a v1 archive.
pub const MANIFEST_SCHEMA_VERSION_V1: &str = "viper-cold-storage-v1";

/// Domain prefix for the SLH-DSA-SHAKE-256s manifest signature preimage.
/// The signed bytes are `MANIFEST_SIGNING_DOMAIN || canonical_manifest_json`.
pub const MANIFEST_SIGNING_DOMAIN: &[u8] = b"VIPER-COLD-STORAGE-MANIFEST-V1";

/// Domain prefix for the RFC 3161 TSA imprint preimage. The SHA-256 input
/// is `MANIFEST_TSA_DOMAIN || canonical_manifest_json`.
pub const MANIFEST_TSA_DOMAIN: &[u8] = b"VIPER-COLD-STORAGE-TSA-V1";

/// One batch entry inside the cold-storage manifest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BatchEntry {
    pub file_name: String,
    pub low_height: u64,
    pub high_height: u64,
    pub anchor_block_hash: String,
    pub sha256: String,
    pub uncompressed_bytes: u64,
    pub compressed_bytes: u64,
}

/// Operator-side signature over the manifest. SLH-DSA-SHAKE-256s only
/// at v2; future algs would bump `schema_version` to v3 + relax `alg`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManifestSignature {
    pub alg: String,
    pub signer_address_hex: String,
    pub signer_pk_hex: String,
    pub value_hex: String,
}

/// Cold-storage manifest — one per export run. v2 schema: optional
/// signature + tsa_token are stripped before computing the canonical
/// signing preimage.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ColdStorageManifest {
    pub schema_version: String,
    pub chain_id_hex: String,
    pub exported_at_unix: u64,
    pub low_height: u64,
    pub high_height: u64,
    pub batch_count: u32,
    pub batches: Vec<BatchEntry>,
    /// SLH-DSA-SHAKE-256s signature over the canonical manifest bytes
    /// (manifest with `signature: None, tsa_token: None`). v2-only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<ManifestSignature>,
    /// Base64-encoded RFC 3161 `TimeStampResp` DER. v2-only. The chain
    /// does not parse the DER; it is forwarded opaquely for the auditor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tsa_token: Option<String>,
}

/// Compute the canonical signing/anchoring preimage for a manifest:
/// `serde_json::to_vec_pretty` of the manifest with `signature: None`
/// AND `tsa_token: None`. Field order is fixed by the struct
/// declaration; `to_vec_pretty` is byte-deterministic across runs of
/// the same crate version.
pub fn canonical_manifest_bytes(m: &ColdStorageManifest) -> Result<Vec<u8>> {
    let stripped = ColdStorageManifest {
        schema_version: m.schema_version.clone(),
        chain_id_hex: m.chain_id_hex.clone(),
        exported_at_unix: m.exported_at_unix,
        low_height: m.low_height,
        high_height: m.high_height,
        batch_count: m.batch_count,
        batches: m.batches.clone(),
        signature: None,
        tsa_token: None,
    };
    serde_json::to_vec_pretty(&stripped).context("canonical manifest serialisation failed")
}

// ── Export pipeline (TASK-188 + TASK-188b additions) ─────────────────────────

/// Read block CBOR bytes for the heights `[low..=high]` from the
/// chain store, returning the raw concatenation suitable for
/// CBOR-sequence decoding by the restorer. Errors out on the first
/// missing height — a caller already checked `cutoff <= store.height()`.
fn collect_batch_bytes(store: &RocksDbChainStore, low: u64, high: u64) -> Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(((high - low + 1) * 1024) as usize);
    for h in low..=high {
        let bytes = store
            .export_block_bytes(h)
            .with_context(|| format!("export_block_bytes failed at height {h}"))?
            .ok_or_else(|| anyhow::anyhow!("missing block at height {h}"))?;
        buf.extend_from_slice(&bytes);
    }
    Ok(buf)
}

/// Read the high-block hash for a given height — used as the manifest
/// anchor so the operator (or the restore path) can verify the batch's
/// last block matches the expected canonical chain.
fn read_anchor_block_hash(store: &RocksDbChainStore, height: u64) -> Result<BlockHash> {
    let stored: StoredBlock = store
        .read_stored_block_at_height(height)
        .with_context(|| format!("read_stored_block_at_height({height}) failed"))?
        .ok_or_else(|| anyhow::anyhow!("anchor block missing at height {height}"))?;
    Ok(stored.metadata.block_hash)
}

/// Write one zstd-compressed batch file to `output_dir`. Returns the
/// per-batch manifest entry (file name, height range, sha256, sizes,
/// anchor hash). Compression level 19 is the SDK default for "high
/// compression"; Zstandard's level 19 typically achieves a 50–60 %
/// reduction on Viper block CBOR.
fn write_batch(
    store: &RocksDbChainStore,
    output_dir: &Path,
    low: u64,
    high: u64,
) -> Result<BatchEntry> {
    let raw = collect_batch_bytes(store, low, high)?;
    let compressed = zstd::encode_all(raw.as_slice(), 19).context("zstd compression failed")?;

    let mut hasher = Sha256::new();
    hasher.update(&compressed);
    let sha256 = hex::encode(hasher.finalize());

    let anchor = read_anchor_block_hash(store, high)?;

    let file_name = format!("blocks-{low:08}-{high:08}.zst");
    let path = output_dir.join(&file_name);
    fs::write(&path, &compressed)
        .with_context(|| format!("failed to write batch file {}", path.display()))?;

    Ok(BatchEntry {
        file_name,
        low_height: low,
        high_height: high,
        anchor_block_hash: hex::encode(anchor.0),
        sha256,
        uncompressed_bytes: raw.len() as u64,
        compressed_bytes: compressed.len() as u64,
    })
}

/// Optional v2 features added on top of the v1 export. All fields are
/// independent — sign without anchoring, anchor without signing, both,
/// or neither (the latter still bumps the schema_version label to v2
/// to mark "produced by a v2-aware exporter").
#[derive(Debug, Default, Clone)]
pub struct ExportOptions {
    /// Operator address (hex, 32 bytes) to look up an `archival_sk` in
    /// the supplied keystore and SLH-DSA-SHAKE-256s sign the canonical
    /// manifest bytes. `None` skips signing entirely.
    pub sign_with_operator_hex: Option<String>,
    /// HTTP TSA endpoint (e.g. `http://timestamp.digicert.com`). When
    /// set, the exporter POSTs an RFC 3161 `TimeStampReq` whose imprint
    /// is `sha256(MANIFEST_TSA_DOMAIN || canonical_manifest_bytes)` and
    /// embeds the reply DER as `manifest.tsa_token` (base64).
    pub anchor_tsa_url: Option<String>,
    /// Best-effort flag: when true, a TSA failure is logged at WARN and
    /// the export still completes. When false (default), a TSA failure
    /// aborts the export. Operators rotating with a flaky TSA flip this
    /// to keep the schedule moving.
    pub tsa_best_effort: bool,
}

/// End-to-end cold-storage export. Iterates heights `1..=cutoff` in
/// batches of `batch_size`, writes each batch + a single `manifest.json`
/// to `output_dir`. When `opts.sign_with_operator_hex` is set, the
/// manifest is signed in-place. When `opts.anchor_tsa_url` is set, the
/// manifest is anchored in-place. Returns the (post-sign-and-anchor)
/// manifest so callers can log it without re-reading the file.
pub fn export_cold_storage(
    store: &RocksDbChainStore,
    chain_id_hex: String,
    cutoff: u64,
    batch_size: u64,
    output_dir: &Path,
    keystore: Option<&Keystore>,
    opts: &ExportOptions,
) -> Result<ColdStorageManifest> {
    if cutoff == 0 {
        bail!("cold-storage-export requires cutoff > 0 (genesis stays in the live store)");
    }
    let tip = store.height();
    if cutoff > tip {
        bail!(
            "cold-storage-export refused: cutoff {cutoff} exceeds current tip {tip}; \
             pruning what doesn't exist is a config error, not a feature"
        );
    }
    if batch_size == 0 {
        bail!("--batch-size must be > 0 (no zero-block batches)");
    }
    fs::create_dir_all(output_dir).with_context(|| {
        format!(
            "failed to create cold-storage output dir {}",
            output_dir.display()
        )
    })?;

    let mut batches: Vec<BatchEntry> = Vec::new();
    let mut h: u64 = 1;
    while h <= cutoff {
        let high = (h + batch_size - 1).min(cutoff);
        let entry = write_batch(store, output_dir, h, high)?;
        tracing::info!(
            low_height = entry.low_height,
            high_height = entry.high_height,
            sha256 = %entry.sha256,
            uncompressed_bytes = entry.uncompressed_bytes,
            compressed_bytes = entry.compressed_bytes,
            "cold-storage batch written",
        );
        batches.push(entry);
        h = high + 1;
    }

    let mut manifest = ColdStorageManifest {
        schema_version: MANIFEST_SCHEMA_VERSION_V2.to_string(),
        chain_id_hex,
        exported_at_unix: SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        low_height: 1,
        high_height: cutoff,
        batch_count: batches.len() as u32,
        batches,
        signature: None,
        tsa_token: None,
    };

    if let Some(operator_hex) = opts.sign_with_operator_hex.as_deref() {
        let ks = keystore.context(
            "cold-storage-export refused: --sign-with-operator requires a keystore \
             (set node_config.devnet.validators[].archival_sk_hex or keystore_path)",
        )?;
        sign_manifest_in_place(&mut manifest, ks, operator_hex)
            .context("manifest signing failed")?;
    }

    if let Some(tsa_url) = opts.anchor_tsa_url.as_deref() {
        match anchor_manifest_with_tsa(&manifest, tsa_url) {
            Ok(token_b64) => manifest.tsa_token = Some(token_b64),
            Err(e) if opts.tsa_best_effort => {
                tracing::warn!(
                    error = %e,
                    tsa_url = tsa_url,
                    "cold-storage TSA anchor failed (best-effort): proceeding unanchored",
                );
            }
            Err(e) => {
                return Err(e).context(
                    "cold-storage-export refused: TSA anchor failed and \
                     --tsa-best-effort was not set",
                );
            }
        }
    }

    let manifest_path = output_dir.join("manifest.json");
    let manifest_bytes =
        serde_json::to_vec_pretty(&manifest).context("manifest serialisation failed")?;
    fs::write(&manifest_path, &manifest_bytes)
        .with_context(|| format!("failed to write manifest at {}", manifest_path.display()))?;

    tracing::info!(
        manifest_path = %manifest_path.display(),
        batch_count = manifest.batch_count,
        low_height = manifest.low_height,
        high_height = manifest.high_height,
        signed = manifest.signature.is_some(),
        anchored = manifest.tsa_token.is_some(),
        "cold-storage export completed",
    );
    Ok(manifest)
}

// ── Manifest signing (TASK-188b §1) ──────────────────────────────────────────

/// SLH-DSA-SHAKE-256s sign the canonical manifest bytes using the
/// operator's `archival_sk` from the keystore. `operator_hex` is the
/// 32-byte operator address (hex, no `0x` prefix).
fn sign_manifest_in_place(
    manifest: &mut ColdStorageManifest,
    keystore: &Keystore,
    operator_hex: &str,
) -> Result<()> {
    let addr_bytes_vec =
        hex::decode(operator_hex.trim_start_matches("0x")).context("operator hex decode")?;
    if addr_bytes_vec.len() != 32 {
        bail!(
            "--sign-with-operator address must be 32 bytes (64 hex chars), got {}",
            addr_bytes_vec.len()
        );
    }
    let mut addr_bytes = [0u8; 32];
    addr_bytes.copy_from_slice(&addr_bytes_vec);

    let entry = keystore.get(&addr_bytes).with_context(|| {
        format!(
            "keystore has no entry for operator {operator_hex} \
             (cold-storage-export needs a validator's archival_sk)"
        )
    })?;
    let sk = entry.archival_sk.as_ref().with_context(|| {
        format!(
            "keystore entry for operator {operator_hex} is present but has no archival_sk_hex; \
             cold-storage signing requires an SLH-DSA-SHAKE-256s key"
        )
    })?;

    let canonical = canonical_manifest_bytes(manifest)?;
    let mut preimage = Vec::with_capacity(MANIFEST_SIGNING_DOMAIN.len() + canonical.len());
    preimage.extend_from_slice(MANIFEST_SIGNING_DOMAIN);
    preimage.extend_from_slice(&canonical);

    let sig = slh_dsa_shake_256s_sign(sk, &preimage)
        .map_err(|e| anyhow::anyhow!("slh_dsa_shake_256s_sign failed: {e}"))?;

    // Derive the matching public key from the secret key — pqc_crypto
    // does not expose a one-shot "sk → pk" helper, but the SLH-DSA-SHAKE-256s
    // secret key encoding (FIPS 205 §10.3) places the seed + pk-seed +
    // pk-root contiguously: pk = sk_bytes[64..128] (the last 64 bytes
    // are the public key by construction). Pinned by
    // `signed_manifest_round_trip_recovers_pk` test.
    if sk.len() != pqc_types::archival::SLH_DSA_SHAKE_256S_SK_LEN {
        bail!(
            "archival_sk is {} bytes; expected {} (FIPS 205 §10.3)",
            sk.len(),
            pqc_types::archival::SLH_DSA_SHAKE_256S_SK_LEN
        );
    }
    let pk_bytes = sk[64..128].to_vec();

    manifest.signature = Some(ManifestSignature {
        alg: "slh-dsa-shake-256s".to_string(),
        signer_address_hex: operator_hex.trim_start_matches("0x").to_lowercase(),
        signer_pk_hex: hex::encode(&pk_bytes),
        value_hex: hex::encode(&sig),
    });
    Ok(())
}

/// Verify a manifest's `signature` field. Returns the verified signer
/// public key bytes on success. Errors out with a clear message when:
///   - signature is absent (caller should reject unless --insecure)
///   - alg is not slh-dsa-shake-256s
///   - signer address / pk hex malformed
///   - SLH-DSA verification fails
pub fn verify_manifest_signature(manifest: &ColdStorageManifest) -> Result<Vec<u8>> {
    let sig = manifest
        .signature
        .as_ref()
        .context("manifest has no signature field; pass --insecure-no-verify to import anyway")?;

    if sig.alg != "slh-dsa-shake-256s" {
        bail!(
            "unsupported signature alg '{}' (only slh-dsa-shake-256s at v2)",
            sig.alg
        );
    }

    let pk_bytes =
        hex::decode(sig.signer_pk_hex.trim_start_matches("0x")).context("signer_pk_hex decode")?;
    let sig_bytes = hex::decode(sig.value_hex.trim_start_matches("0x"))
        .context("signature value_hex decode")?;

    let canonical = canonical_manifest_bytes(manifest)?;
    let mut preimage = Vec::with_capacity(MANIFEST_SIGNING_DOMAIN.len() + canonical.len());
    preimage.extend_from_slice(MANIFEST_SIGNING_DOMAIN);
    preimage.extend_from_slice(&canonical);

    let pk = PublicKey {
        alg_id: AlgId::SlhDsaShake256s,
        bytes: pk_bytes.clone(),
    };
    let sigobj = Signature {
        alg_id: AlgId::SlhDsaShake256s,
        bytes: sig_bytes,
    };
    PqVerifier
        .verify(&pk, &preimage, &sigobj)
        .map_err(|e| anyhow::anyhow!("manifest signature verification failed: {e}"))?;
    Ok(pk_bytes)
}

// ── RFC 3161 TSA anchor (TASK-188b §2) ───────────────────────────────────────

/// Build an RFC 3161 `TimeStampReq` DER for a SHA-256 imprint, POST it
/// to `tsa_url`, and return the reply DER bytes (base64). Synchronous
/// blocking-runtime helper because the export pipeline is itself a
/// blocking CLI driver.
fn anchor_manifest_with_tsa(manifest: &ColdStorageManifest, tsa_url: &str) -> Result<String> {
    let canonical = canonical_manifest_bytes(manifest)?;

    let mut digest_input = Vec::with_capacity(MANIFEST_TSA_DOMAIN.len() + canonical.len());
    digest_input.extend_from_slice(MANIFEST_TSA_DOMAIN);
    digest_input.extend_from_slice(&canonical);

    let mut hasher = Sha256::new();
    hasher.update(&digest_input);
    let digest_arr: [u8; 32] = hasher.finalize().into();

    let req_der = pqc_tsa::build_timestamp_request(&digest_arr);

    // Block on a fresh tokio current-thread runtime — pqcd's CLI
    // dispatcher is synchronous up to subcommand entry; spinning up
    // a runtime for one HTTP POST is cheaper than refactoring the
    // dispatch path.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("failed to spin up tokio runtime for TSA POST")?;

    let body = rt.block_on(async {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .context("reqwest client build failed")?;
        let resp = client
            .post(tsa_url)
            .header("content-type", "application/timestamp-query")
            .body(req_der)
            .send()
            .await
            .with_context(|| format!("POST {tsa_url} failed"))?;
        let status = resp.status();
        if !status.is_success() {
            bail!("TSA returned HTTP {}", status.as_u16());
        }
        let body = resp.bytes().await.context("read TSA response body")?;
        if body.len() > 64 * 1024 {
            bail!("TSA response too large ({} bytes; max 64 KiB)", body.len());
        }
        Ok::<Vec<u8>, anyhow::Error>(body.to_vec())
    })?;

    Ok(B64.encode(&body))
}

// The RFC 3161 `TimeStampReq` DER encoder lives in the shared `pqc-tsa`
// crate (extracted 2026-05-06 to close the ADR-060 D7 loose end).
// `viper-archival-sidecar` imports the same encoder there; this comment
// is the only remnant of the previous inline copy.

// ── Restore path (TASK-188b §3) ──────────────────────────────────────────────

/// Outcome of a successful import.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportSummary {
    pub schema_version: String,
    pub chain_id_hex: String,
    pub low_height: u64,
    pub high_height: u64,
    pub batches_replayed: u32,
    pub blocks_replayed: u64,
    pub signature_verified: bool,
    pub tsa_token_present: bool,
    pub final_tip_hash_hex: String,
}

/// Options for `import_cold_storage`. `insecure_no_verify` skips
/// signature verification (required for v1 manifests; refused for v2
/// manifests carrying a signature unless explicit). `require_tsa`
/// makes the import fail when the manifest carries no `tsa_token`.
#[derive(Debug, Default, Clone)]
pub struct ImportOptions {
    pub insecure_no_verify: bool,
    pub require_tsa: bool,
}

/// Read a cold-storage manifest from `<input_dir>/manifest.json`,
/// verify it (optionally), then for each batch in order:
///   1. Read `<input_dir>/<batch.file_name>`.
///   2. SHA-256 the bytes; reject if mismatched against `batch.sha256`.
///   3. zstd-decompress.
///   4. Decode as a CBOR sequence of `StoredBlock`s; reject if the
///      decoded count is not `(batch.high_height - batch.low_height + 1)`.
///   5. Verify the decoded heights are contiguous and start at
///      `batch.low_height`.
///   6. Verify the LAST decoded block's `block_hash` equals
///      `batch.anchor_block_hash`.
///   7. For every block, call `RocksDbChainStore::append_stored_block`
///      with `policy = None` (the manifest signature already attested
///      to the bundle authenticity; we trust the operator who signed).
///
/// Returns an `ImportSummary` describing what was replayed.
pub fn import_cold_storage(
    store: &mut RocksDbChainStore,
    input_dir: &Path,
    opts: &ImportOptions,
) -> Result<ImportSummary> {
    let manifest_path = input_dir.join("manifest.json");
    let manifest_bytes = fs::read(&manifest_path)
        .with_context(|| format!("failed to read manifest at {}", manifest_path.display()))?;
    let manifest: ColdStorageManifest = serde_json::from_slice(&manifest_bytes)
        .with_context(|| format!("failed to parse manifest at {}", manifest_path.display()))?;

    // Schema gate.
    let known_schema = matches!(
        manifest.schema_version.as_str(),
        MANIFEST_SCHEMA_VERSION_V1 | MANIFEST_SCHEMA_VERSION_V2
    );
    if !known_schema {
        bail!(
            "manifest schema_version '{}' not recognised (known: {} | {})",
            manifest.schema_version,
            MANIFEST_SCHEMA_VERSION_V1,
            MANIFEST_SCHEMA_VERSION_V2
        );
    }
    if manifest.batches.len() as u32 != manifest.batch_count {
        bail!(
            "manifest is internally inconsistent: batch_count={} but batches.len()={}",
            manifest.batch_count,
            manifest.batches.len()
        );
    }

    // Signature gate.
    let signature_verified = if manifest.signature.is_some() {
        if opts.insecure_no_verify {
            tracing::warn!(
                "cold-storage import: --insecure-no-verify set; SKIPPING manifest signature \
                 verification despite the manifest carrying a signature",
            );
            false
        } else {
            verify_manifest_signature(&manifest).context("manifest signature verification")?;
            true
        }
    } else if opts.insecure_no_verify {
        tracing::warn!(
            "cold-storage import: manifest has no signature; --insecure-no-verify set, \
             proceeding without authenticity",
        );
        false
    } else {
        bail!(
            "cold-storage import refused: manifest has no signature field. \
             Pass --insecure-no-verify to override (operator-trusted-source rotation)."
        );
    };

    // TSA gate.
    let tsa_present = manifest.tsa_token.is_some();
    if opts.require_tsa && !tsa_present {
        bail!(
            "cold-storage import refused: --require-tsa set but manifest has no tsa_token. \
             Either re-export with --anchor-tsa or drop --require-tsa."
        );
    }

    // Refuse imports whose live tip is past the cold-storage low_height
    // — restoring backward into a populated store would corrupt the
    // canonical chain. The expected operator workflow is "fresh node
    // bootstrapped from genesis OR a zeroed RocksDB".
    let live_tip = store.height();
    if live_tip >= manifest.low_height {
        bail!(
            "cold-storage import refused: live store tip is at height {}, \
             cold-storage manifest starts at height {}. Import target must \
             be empty (height < {}). Run on a freshly-bootstrapped follower.",
            live_tip,
            manifest.low_height,
            manifest.low_height,
        );
    }

    // Replay each batch.
    let mut blocks_replayed: u64 = 0;
    let mut last_anchor_hash = BlockHash([0u8; 32]);
    for batch in &manifest.batches {
        let batch_path = input_dir.join(&batch.file_name);
        let zst_bytes = fs::read(&batch_path)
            .with_context(|| format!("failed to read batch {}", batch_path.display()))?;

        let mut hasher = Sha256::new();
        hasher.update(&zst_bytes);
        let actual_sha = hex::encode(hasher.finalize());
        if actual_sha != batch.sha256 {
            bail!(
                "cold-storage import refused: SHA-256 mismatch on {} (manifest={}, file={})",
                batch.file_name,
                batch.sha256,
                actual_sha
            );
        }

        let raw = zstd::decode_all(zst_bytes.as_slice())
            .with_context(|| format!("zstd decompress failed on {}", batch.file_name))?;

        let total_len = raw.len() as u64;
        let mut cursor = std::io::Cursor::new(raw);
        let expected_count = batch.high_height - batch.low_height + 1;
        let mut decoded_in_batch: u64 = 0;
        let mut last_block_hash = BlockHash([0u8; 32]);
        while cursor.position() < total_len {
            let stored = RocksDbChainStore::decode_block_bytes_from_reader(&mut cursor)
                .with_context(|| {
                    format!(
                        "CBOR decode failed at offset {} of batch {}",
                        cursor.position(),
                        batch.file_name
                    )
                })?;

            let expected_height = batch.low_height + decoded_in_batch;
            if stored.metadata.height != expected_height {
                bail!(
                    "cold-storage import refused: height drift in batch {} — got {}, expected {}",
                    batch.file_name,
                    stored.metadata.height,
                    expected_height
                );
            }

            // Replay via append_stored_block. policy=None is intentional:
            // the manifest signer attests authenticity at bundle level;
            // the chain store still re-checks tip continuity (prev_hash)
            // and rejects out-of-order or duplicate inserts.
            last_block_hash = stored.metadata.block_hash.clone();
            store.append_stored_block(stored, None).with_context(|| {
                format!("append_stored_block failed at height {expected_height}")
            })?;

            decoded_in_batch += 1;
            blocks_replayed += 1;
        }

        if decoded_in_batch != expected_count {
            bail!(
                "cold-storage import refused: batch {} contained {} blocks (expected {})",
                batch.file_name,
                decoded_in_batch,
                expected_count
            );
        }

        let expected_anchor = decode_block_hash_hex(&batch.anchor_block_hash, &batch.file_name)?;
        if last_block_hash != expected_anchor {
            bail!(
                "cold-storage import refused: batch {} anchor mismatch \
                 (manifest={}, replayed-tip={})",
                batch.file_name,
                batch.anchor_block_hash,
                hex::encode(last_block_hash.0)
            );
        }
        last_anchor_hash = last_block_hash;

        tracing::info!(
            file = %batch.file_name,
            blocks = decoded_in_batch,
            "cold-storage batch replayed",
        );
    }

    Ok(ImportSummary {
        schema_version: manifest.schema_version,
        chain_id_hex: manifest.chain_id_hex,
        low_height: manifest.low_height,
        high_height: manifest.high_height,
        batches_replayed: manifest.batch_count,
        blocks_replayed,
        signature_verified,
        tsa_token_present: tsa_present,
        final_tip_hash_hex: hex::encode(last_anchor_hash.0),
    })
}

fn decode_block_hash_hex(s: &str, ctx: &str) -> Result<BlockHash> {
    let v = hex::decode(s.trim_start_matches("0x"))
        .with_context(|| format!("anchor_block_hash decode in {ctx}"))?;
    if v.len() != 32 {
        bail!(
            "anchor_block_hash in {ctx} must be 32 bytes, got {}",
            v.len()
        );
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    Ok(BlockHash(out))
}

// ── S3 push (TASK-188b §4, feature-gated) ────────────────────────────────────

/// Upload every file in `dir` (manifest.json + every blocks-*.zst) to
/// `s3://<bucket>/<prefix>/<file_name>` using the AWS SDK. IRSA-friendly:
/// the SDK reads `AWS_ROLE_ARN` + `AWS_WEB_IDENTITY_TOKEN_FILE` env
/// vars when running on EKS, otherwise falls back to ambient creds.
///
/// Off by default — feature-gated behind `s3-upload` so the standard
/// build does not pay the AWS SDK compile cost (~30 transitive crates).
/// Builds that need uploads opt in:
///
/// ```text
/// cargo build -p pqcd --features s3-upload
/// ```
#[cfg(feature = "s3-upload")]
pub fn upload_to_s3(dir: &Path, s3_uri: &str) -> Result<()> {
    let (bucket, prefix) = parse_s3_uri(s3_uri)?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("failed to spin up tokio runtime for S3 upload")?;
    rt.block_on(async {
        let cfg = aws_config::load_from_env().await;
        let client = aws_sdk_s3::Client::new(&cfg);
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            if !entry.file_type()?.is_file() {
                continue;
            }
            let name = entry.file_name();
            let name_str = name.to_string_lossy().into_owned();
            let key = if prefix.is_empty() {
                name_str.clone()
            } else if prefix.ends_with('/') {
                format!("{prefix}{name_str}")
            } else {
                format!("{prefix}/{name_str}")
            };
            let body = aws_sdk_s3::primitives::ByteStream::from_path(entry.path())
                .await
                .with_context(|| format!("read file for upload: {}", entry.path().display()))?;
            client
                .put_object()
                .bucket(&bucket)
                .key(&key)
                .body(body)
                .send()
                .await
                .with_context(|| format!("PutObject s3://{bucket}/{key}"))?;
            tracing::info!(bucket = %bucket, key = %key, "cold-storage uploaded");
        }
        Ok::<(), anyhow::Error>(())
    })
}

#[cfg(not(feature = "s3-upload"))]
pub fn upload_to_s3(_dir: &Path, _s3_uri: &str) -> Result<()> {
    bail!(
        "--upload-to is unavailable in this build: pqcd was compiled without the \
         's3-upload' feature. Re-build with `cargo build -p pqcd --features s3-upload` \
         or upload externally with `aws s3 sync`."
    )
}

#[cfg(feature = "s3-upload")]
fn parse_s3_uri(uri: &str) -> Result<(String, String)> {
    let rest = uri
        .strip_prefix("s3://")
        .with_context(|| format!("--upload-to must be an s3:// URI, got '{uri}'"))?;
    let mut parts = rest.splitn(2, '/');
    let bucket = parts
        .next()
        .filter(|s| !s.is_empty())
        .context("S3 URI missing bucket component")?
        .to_string();
    let prefix = parts.next().unwrap_or("").to_string();
    Ok((bucket, prefix))
}

#[cfg(test)]
mod tests;

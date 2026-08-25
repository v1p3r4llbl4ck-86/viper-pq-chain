# Cold-Storage Manifest Specification

**Spec ID**: SPEC-COLD-STORAGE-001
**Version**: 0.2
**Status**: Draft
**Date**: 2026-05-06
**Implements**: TASK-188 (`pqcd cold-storage-export` rotation; commit `b6d6e80`) + TASK-188b (manifest signing + TSA anchor + restore + S3 push + Ansible timer; commit appended on land)
**Decision authority**: ADR-045 (Archival Overlay), ADR-058 (cold-storage export-only), ADR-060 (cold-storage v2 closure), Policy P-COMPAT-001
**Depends on**: SPEC-ARCHIVAL-001 §6 (RFC 3161 anchor pattern), SPEC-CONSENSUS-001 §7.4 (canonical block hash), SPEC-GENESIS-001 §0 (`chain_id_hex` contract)
**References**: ADR-045, ADR-058, ADR-060, KNOWN-ISSUES R-10, Zstandard RFC 8478, FIPS 180-4 (SHA-256), FIPS 205 (SLH-DSA), RFC 3161 (TSA), `crates/pqcd/src/cold_storage.rs`

---

## Revision history

| Version | Date       | Notes |
|---------|-----------|-------|
| 0.1     | 2026-05-06 | Initial draft. Pins the on-disk manifest schema produced by TASK-188 commit `b6d6e80`. Manifest signing (SLH-DSA-SHAKE-256s) and TSA anchor are reserved for TASK-188b under v2 of the schema. |
| 0.2     | 2026-05-06 | TASK-188b closure. Pins the v2 schema (`viper-cold-storage-v2`) with `signature` + `tsa_token` optional fields, the canonical signing preimage rule, the SLH-DSA domain `MANIFEST_SIGNING_DOMAIN`, the TSA-imprint domain `MANIFEST_TSA_DOMAIN`, and the restore-path semantic gates (signature → required by default; TSA → required only with `--require-tsa`). v1 → v2 is additive (`Option`-typed fields with `skip_serializing_if = "Option::is_none"`). |

---

## 0. Status banner

This spec governs both versions of the cold-storage rotation pipeline:

- **v1** (`viper-cold-storage-v1`, TASK-188 / commit `b6d6e80`): export-only path. Manifest is unsigned; integrity inherits from the chain (anchor block hash) and from the operator's S3 bucket access policy. Restore is manual.
- **v2** (`viper-cold-storage-v2`, TASK-188b): adds optional SLH-DSA-SHAKE-256s manifest signature, optional RFC 3161 TSA token, and an automated `pqcd cold-storage-import` restore subcommand. v2 is a strict additive superset of v1 — both fields are `Option`-typed with `skip_serializing_if = "Option::is_none"`, so a v2 manifest with neither field set serialises to bytes that differ from v1 only in the `schema_version` string. v1 readers parse v2 manifests successfully (unknown-field tolerance); v2 readers parse both formats.

The transition rule under P-COMPAT-001: producers SHOULD emit v2 starting at TASK-188b's land commit. Existing v1 archives stay valid forever and remain restorable via `pqcd cold-storage-import --insecure-no-verify` (the operator explicitly opts into accepting an unauthenticated bundle).

---

## 1. Scope

This specification defines:

- the on-disk JSON manifest schema produced by `pqcd cold-storage-export`,
- the per-batch zstd-compressed file naming convention,
- the SHA-256 integrity binding between manifest entries and on-disk batch files,
- the pre-flight constraints enforced before a single byte is written,
- the operator workflow that pairs `pqcd cold-storage-export` with an out-of-band cold-storage backend (S3 / equivalent).

Out of scope:
- Manifest signing — deferred to TASK-188b (§9).
- RFC 3161 TSA anchoring of the manifest hash — deferred to TASK-188b (§9). The in-band archival overlay (SPEC-ARCHIVAL-001 §6) already implements the TSA pattern; cold storage will reuse the same sidecar in v2.
- The restore path (`pqcd snapshot-import --from-cold <manifest>`) — deferred to TASK-188b (§9).
- Cold-storage backend selection (S3 / R2 / on-prem) — operational concern, not a chain commitment.

---

## 2. Normative Language

RFC 2119. MUST / SHOULD / MAY carry their usual meaning.

---

## 3. Schema Version

The manifest carries a single immutable schema-version string:

```
schema_version ∈ { "viper-cold-storage-v1", "viper-cold-storage-v2" }
```

- **v1** (TASK-188 — commit `b6d6e80`): no `signature` field, no `tsa_token` field.
- **v2** (TASK-188b): both `signature` and `tsa_token` are present as `Option`-typed fields. A v2 manifest MAY have either, both, or neither set (e.g. a rotation run with `--anchor-tsa` but no `--sign-with-operator`).

The constants are exported as `MANIFEST_SCHEMA_VERSION_V1` and `MANIFEST_SCHEMA_VERSION_V2` in `crates/pqcd/src/cold_storage.rs`.

Restore code dispatches on the version string:

- v1 → require `--insecure-no-verify` (no signature to verify; explicit operator opt-in).
- v2 with `signature == None` → require `--insecure-no-verify`.
- v2 with `signature != None` → verify against the canonical preimage; bail on mismatch.
- v1 or v2 with `tsa_token == None` AND `--require-tsa` set → bail.

A v1 reader that encounters `viper-cold-storage-v2` MAY parse it (unknown-field tolerance) but MUST treat the resulting bundle as unsigned (it has no SLH-DSA verifier). For that reason the `cold-storage-import` subcommand is the only sanctioned restorer; ad-hoc parsers SHOULD bail on unknown schema versions.

---

## 4. Manifest JSON Shape

### 4.1 Top-level manifest

The manifest is written as `manifest.json` in the export output directory and serialised as pretty-printed JSON via `serde_json::to_vec_pretty`. The Rust source of record is `pqcd::cold_storage::ColdStorageManifest`.

| Field | Type | Notes |
|-------|------|-------|
| `schema_version` | string | MUST equal `"viper-cold-storage-v1"` (§3). |
| `chain_id_hex` | string | UTF-8 byte hex of the chain id (per SPEC-GENESIS-001 §0). For the retired `viper-pq-1` chain this was `76697065722d70712d31`; the `viper-testnet-2` value is assigned at genesis. Operator-supplied at export time; the binary does not re-derive it. |
| `exported_at_unix` | uint64 | Wall-clock seconds since the Unix epoch at export start. Derived from `SystemTime::now()`; falls back to `0` on clock-error (the operator MUST notice a `0` value). Authoritative time is the §9 TSA anchor when v2 lands; v1 carries the host-clock value as informational only. |
| `low_height` | uint64 | Smallest height included in the export. v1 emits `1` (genesis at height 0 stays in the live store; the v1 path never archives genesis). |
| `high_height` | uint64 | Largest height included in the export. Equals the operator-supplied `cutoff` (§6). |
| `batch_count` | uint32 | Number of `batches[]` entries; equals `batches.len()`. Derived field, MUST be consistent with `batches.len()` on read. |
| `batches` | array | Per-batch entries (§4.2), in ascending height order. |

### 4.2 Per-batch entry

Each entry in `batches[]` corresponds to exactly one `.zst` file in the same directory.

| Field | Type | Notes |
|-------|------|-------|
| `file_name` | string | Per §5 (`blocks-<low:08>-<high:08>.zst`). Sibling-relative; no path separators. |
| `low_height` | uint64 | First height in the batch (inclusive). |
| `high_height` | uint64 | Last height in the batch (inclusive). |
| `anchor_block_hash` | string | Hex of the canonical consensus block hash at `high_height` (SPEC-CONSENSUS-001 §7.4). 64 hex chars (32 bytes). The "anchor" name reflects that this is the hash a future restorer will check against the chain to confirm the batch's last block is on the canonical branch the operator intended to archive. |
| `sha256` | string | Hex of `SHA-256(compressed_bytes_on_disk)` (§6.4). 64 hex chars. |
| `uncompressed_bytes` | uint64 | Number of pre-compression bytes in the batch (cumulative `export_block_bytes` output across the height range). Reported for operator capacity-planning and cold-vs-hot ratio observability; not security-load-bearing. |
| `compressed_bytes` | uint64 | Size of the on-disk `.zst` file in bytes. MUST equal `len(file_name's bytes on disk)` after a successful export. |

Batches MUST be sorted by `low_height` ascending. Batch ranges MUST be contiguous (`batches[i].high_height + 1 == batches[i+1].low_height`) and non-overlapping. The first batch's `low_height` MUST equal the manifest's `low_height`; the last batch's `high_height` MUST equal the manifest's `high_height`.

---

## 5. Batch File Naming

```
file_name = format!("blocks-{:08}-{:08}.zst", low_height, high_height)
```

- `{:08}` zero-pads to 8 decimal digits, so `blocks-00000001-00010000.zst` lexicographically sorts before `blocks-00010001-00020000.zst`. 8 digits accommodate heights up to 99,999,999 (≈ 1.5 years at 500 ms cadence); when the chain crosses 10⁸ blocks the field widens under v2 (additive backward-compatible change — old restorers parse the wider form by recognising the contiguous digit run rather than fixed width).
- The `.zst` extension is the standard Zstandard suffix per RFC 8478 §6.
- File names contain no path separators; all batch files live as siblings of `manifest.json` in the export directory. The cold-storage backend's prefix (e.g. `s3://viper-pq-cold/2026-05/`) is added at upload time by the operator, not by the binary.

---

## 6. Compression and Integrity

### 6.1 Codec

Each batch is compressed with **Zstandard at level 19** (`zstd::encode_all(raw, 19)` in `crates/pqcd/src/cold_storage.rs`). Level 19 is the SDK's "high compression" tier and typically achieves a 50–60% size reduction on Viper block CBOR — heavy ML-DSA-65 signature blocks compress less than text but more than already-compressed data, so the 50–60% figure is a measured central tendency, not a guarantee.

Level 19 was chosen over levels 22 (max) and 3 (default) on the following tradeoffs:

- **Level 22** doubles encode time for ≤ 2 percentage points additional reduction on the measured Viper corpus — not worth the operator-side wall time.
- **Level 3** roughly halves encode time but loses ~10 percentage points of reduction — for an archival tier whose dominant cost is bytes-stored × years, the trade is wrong-directional.
- **Level 19** is the documented Zstandard "long-term archival" sweet spot and is the level used by other archival pipelines this spec aligns with (Debian snapshot, ZFS archival datasets).

The level is hardcoded; future changes ride P-COMPAT-001 (a v2 manifest may declare a different level via an additive field, but v1 readers always see level 19 because v1 writers always wrote level 19).

### 6.2 Block-byte source

Per-block bytes are obtained from `RocksDbChainStore::export_block_bytes(h)`, which returns the canonical CBOR encoding the chain stored at finalisation. Concatenation order is ascending by height, byte-stable across exports:

```
raw_batch_bytes = export_block_bytes(low) || export_block_bytes(low+1) || … || export_block_bytes(high)
```

A missing height inside `[low, high]` aborts the export with an error; the manifest is NOT written if any batch fails to write.

### 6.3 Anchor block hash

The per-batch `anchor_block_hash` is the canonical consensus block hash (SPEC-CONSENSUS-001 §7.4) at `high_height`, NOT the `state_root` and NOT the `commit_hash`. Hashing matches `crates/pqc-consensus/src/store.rs::StoredBlock::metadata.block_hash`. A restorer that verifies cold-storage data against a peer's live chain checks `chain.block_at(high_height).hash == manifest.batches[k].anchor_block_hash` and rejects a mismatch.

The choice of `high_height` (not `low_height`) for the anchor is deliberate: it pins the most-recently-finalised block in the batch, which is the strongest claim about canonical-chain inclusion (deeper finality = more BFT-commit material in the open record).

### 6.4 SHA-256 integrity

`sha256` is computed over the **compressed bytes on disk**, not the uncompressed concatenation:

```
sha256 = hex(SHA-256(compressed_bytes))
```

This binds the manifest entry to the exact file the operator uploads to cold storage. A restorer fetches the `.zst` file, recomputes SHA-256, and compares to the manifest entry before attempting decompression. SHA-256 is FIPS 180-4 standard and is the same hash family the chain uses elsewhere for non-consensus-critical integrity checks. (Consensus-critical hashing uses BIP340 double-tagged SHAKE-256 per ADR-053 §T2.4 / SPEC-GENESIS-001 §3; cold-storage integrity is non-consensus-critical and follows the broader interop hash convention — same reasoning that puts SHA-256 on the wire to RFC 3161 TSAs in SPEC-ARCHIVAL-001 §6.6.)

---

## 7. Pre-Flight Constraints

`export_cold_storage` enforces three constraints before opening the output directory; failure is a hard error that aborts the export:

1. **`cutoff > 0`** — genesis at height 0 stays in the live store. Archiving height 0 would produce a "batch from 0 to 0" with the genesis block alone, which provides no rotation benefit and creates a special-case the restorer would have to hardcode. Rejecting `cutoff = 0` keeps the v1 path uniform (every batch is "blocks 1..N" or "blocks N..M, M ≤ tip").
2. **`cutoff <= store.height()`** — pruning blocks the chain has not yet finalised is a config error, not a feature. The error message is intentionally explicit ("`pruning what doesn't exist is a config error, not a feature`") because operator typos in the cutoff (e.g. confusing `block_count` with `block_height`) are the most common failure mode this check catches.
3. **`batch_size > 0`** — a zero-block batch is degenerate. The error is enforced at the CLI layer to prevent infinite-loop foot-guns inside the writer.

These three checks are together the v1 input contract. Future input fields (e.g. `--exclude-validator-set-changes`) ride P-COMPAT-001 and add their own constraints without weakening the v1 trio.

---

## 8. Operator Workflow

The intended operator flow is two-stage (binary + cold-storage CLI), not one-shot:

### Stage 1 — Local export

```
pqcd cold-storage-export \
    --data-dir /var/lib/pqchain/data \
    --chain-id-hex 76697065722d70712d31 \
    --cutoff 1000000 \
    --batch-size 10000 \
    --output-dir /var/cache/pqchain/cold/2026-05
```

Produces:
- `/var/cache/pqchain/cold/2026-05/blocks-00000001-00010000.zst` … `blocks-00990001-01000000.zst`
- `/var/cache/pqchain/cold/2026-05/manifest.json`

Each batch file write is atomic (`fs::write` truncates+writes the full buffer in one call); a partial export aborts cleanly without producing a manifest, so the operator never sees a manifest that lies about its batch contents.

### Stage 2 — Upload to cold-storage backend

```
aws s3 sync /var/cache/pqchain/cold/2026-05/ s3://viper-pq-cold/2026-05/ \
    --storage-class GLACIER_IR \
    --metadata-directive REPLACE
```

The binary intentionally does NOT bundle the AWS SDK. Reasons:

- **Dependency hygiene** — pqcd already carries libp2p, RocksDB, and a full PQ crypto stack; adding `aws-sdk-s3` would push the static binary past 80 MB and pull a new TLS/Hyper graph that overlaps with libp2p's `quic`+`yamux`.
- **Backend agnosticism** — `aws s3 sync` is one of many valid uploaders. `rclone`, `mc` (MinIO client), `s5cmd`, `gsutil`, and on-prem ceph CLIs all consume a flat directory of zstd files + a manifest JSON. The export format is the contract; the uploader is operator choice.
- **IRSA wiring** — the chart-side ServiceAccount + IAM-roles-for-service-accounts wiring is a separate deliverable (`charts/viper-pq-chain` issue tracker). When that lands, an in-pod uploader can be added as a sidecar without changing the v1 manifest schema.

### Stage 3 — Optional: prune from live store

After Stage 2 completes and the operator has independently verified the upload (`aws s3 ls` + manifest hash spot-check), the live store can be pruned via `pqcd snapshot-prune --below <cutoff>`. Pruning is an independent operation; the cold-storage manifest carries no field that asserts the live store has been pruned.

---

## 9. v2 Closure (TASK-188b)

The v2 schema lands as TASK-188b under ADR-060. Three orthogonal additions on top of the v1 manifest, all `Option`-typed and additive under P-COMPAT-001:

### 9.1 Optional `signature` field

Field type: `Option<ManifestSignature>` (Rust source: `pqcd::cold_storage::ManifestSignature`).

| Subfield | Type | Notes |
|----------|------|-------|
| `alg` | string | MUST equal `"slh-dsa-shake-256s"` at v2; future algs would bump the schema version to v3. |
| `signer_address_hex` | string | 32-byte operator address (hex, lowercase, no `0x`). |
| `signer_pk_hex` | string | 64-byte SLH-DSA-SHAKE-256s public key (hex, no `0x`). Recovered from the secret-key encoding `sk[64..128]` (FIPS 205 §10.3) for verifier convenience. |
| `value_hex` | string | 29 792-byte SLH-DSA-SHAKE-256s signature (hex, no `0x`). |

Signing preimage:

```
preimage = MANIFEST_SIGNING_DOMAIN || canonical_manifest_bytes(manifest)
MANIFEST_SIGNING_DOMAIN = b"VIPER-COLD-STORAGE-MANIFEST-V1"
canonical_manifest_bytes(m) = serde_json::to_vec_pretty(m_with_sig_None_and_tsa_None)
```

The `_V1` suffix on `MANIFEST_SIGNING_DOMAIN` refers to the signing scheme version (which corresponds to the manifest v2 baseline); a future scheme bump would emit `_V2`.

The struct field order is fixed by the Rust declaration so the canonical bytes are byte-deterministic across runs of the same crate version. Pin test: `canonical_bytes_strip_signature_and_tsa` asserts that a manifest with `signature + tsa_token` set serialises to the same canonical bytes as the same manifest with both stripped.

### 9.2 Optional `tsa_token` field

Field type: `Option<String>` (base64-encoded RFC 3161 `TimeStampResp` DER, max 64 KiB after decode). The DER encoder for the outbound `TimeStampReq` lives in the shared `pqc-tsa` crate (extracted from the inline copy on 2026-05-06; both `pqcd::cold_storage` and `viper-archival-sidecar` consume it).

TSA-imprint preimage (the input to SHA-256, which is then used as the RFC 3161 imprint in the `TimeStampReq`):

```
imprint_input = MANIFEST_TSA_DOMAIN || canonical_manifest_bytes(manifest)
MANIFEST_TSA_DOMAIN  = b"VIPER-COLD-STORAGE-TSA-V1"
imprint_digest        = sha256(imprint_input)
```

`MANIFEST_TSA_DOMAIN` is intentionally distinct from `MANIFEST_SIGNING_DOMAIN` so a manifest signature can never be replayed as a TSA imprint or vice-versa. Both domains are also distinct from the in-band archival overlay's `VIPER-ARCHIVAL-TSA-V1` / `VIPER-ARCHIVAL-TST-EXT-V1` so a cold-storage manifest signature can never be confused with an archival-overlay artefact.

The reply DER is forwarded opaquely. The chain does NOT parse or verify the TST cryptographically — that is the auditor's responsibility (matches SPEC-ARCHIVAL-001 §6.1).

### 9.3 Restore subcommand semantics

`pqcd cold-storage-import <node-config.json> <input-dir> [--insecure-no-verify] [--require-tsa]`. The importer enforces, in order:

1. **Pre-flight**: `live tip < manifest.low_height`. Importing into a populated store would corrupt the canonical chain.
2. **Schema gate**: `schema_version ∈ { v1, v2 }`. Unknown versions bail.
3. **Internal consistency**: `batch_count == batches.len()`.
4. **Signature gate**: verify by default; bail without `--insecure-no-verify` on a manifest with `signature == None`. v1 manifests therefore always require `--insecure-no-verify`.
5. **TSA gate**: only enforced when `--require-tsa` is set. The DER is NOT cryptographically validated even when `--require-tsa` is set.
6. **Per-batch integrity**: for each batch, in `manifest.batches[]` order:
   - SHA-256 of the on-disk `.zst` MUST match `batch.sha256`.
   - zstd-decompress; CBOR-sequence-decode each `StoredBlock` via `RocksDbChainStore::decode_block_bytes_from_reader`.
   - Decoded heights MUST be contiguous and start at `batch.low_height`; the count MUST equal `batch.high_height - batch.low_height + 1`.
   - The last block's `block_hash` MUST equal `batch.anchor_block_hash`.
   - Each block is appended via `RocksDbChainStore::append_stored_block(stored, None)`. `policy = None` is intentional: the manifest signature attests authenticity at bundle level. The chain store still re-checks tip continuity (`prev_hash`) and rejects out-of-order or duplicate inserts.

On any failure, the importer bails with an explicit error message. The on-disk RocksDB MAY be in a partial-replay state after a failed import — the operator's recovery path is to delete the data dir and restart `cold-storage-import` (the importer is idempotent against a fresh store but not against partial state).

### 9.4 Operator pre-v2 advice (still applicable for v1 archives)

For v1 manifests in flight or already on disk:

1. Record the `manifest.json` SHA-256 in your operator runbook at upload time (the v1 manifest itself does not anchor).
2. Restrict S3 bucket write access to a single principal so the bucket's audit log is the authenticity claim.
3. Pass `--insecure-no-verify` to the importer when restoring v1 archives (explicit acceptance of unauthenticated bundle).

---

## 10. Invariants

The following invariants MUST hold for any v1 manifest produced by `pqcd cold-storage-export`:

| Invariant | Check |
|-----------|-------|
| `schema_version == "viper-cold-storage-v1"` | First field written; pinned in `cold_storage.rs::MANIFEST_SCHEMA_VERSION`. |
| `low_height >= 1` | Genesis stays in the live store. |
| `high_height <= store.height() at export time` | §7 constraint 2. |
| `batch_count == len(batches)` | Derived field consistency. |
| `batches[0].low_height == manifest.low_height` | §4.2. |
| `batches[-1].high_height == manifest.high_height` | §4.2. |
| Contiguity: `batches[i].high_height + 1 == batches[i+1].low_height` for all i | §4.2. |
| Per-batch SHA-256 matches the on-disk `.zst` file | §6.4. |
| Each `anchor_block_hash` is the canonical block hash at `high_height` | §6.3 / SPEC-CONSENSUS-001 §7.4. |
| All batch file names match `^blocks-\d{8}-\d{8}\.zst$` | §5. |

A restorer or auditor MUST treat any v1 manifest that violates an invariant above as malformed and refuse to consume its data.

---

## 11. Test Strategy

| Layer | Test ID | Coverage | Location |
|-------|---------|----------|----------|
| Unit | T1 | `cutoff = 0` rejected with explicit error | `cold_storage.rs::tests::export_zero_cutoff_is_rejected` |
| Unit | T2 | `cutoff > tip` rejected with explicit error | `cold_storage.rs::tests::export_cutoff_above_tip_is_rejected` |
| Unit | T3 | `batch_size = 0` rejected with explicit error | `cold_storage.rs::tests::export_zero_batch_size_is_rejected` |
| Integration | T4 | Happy-path export writes correct files, manifest, sizes, SHA-256 hashes, and batch-range partition | `cold_storage.rs::tests::export_happy_path_writes_files_and_manifest` |
| Integration | T5 | zstd round-trip recovers the exact byte stream `export_block_bytes` produced — pins the contract a future restore path relies on | `cold_storage.rs::tests::batch_decompression_round_trip_recovers_block_bytes` |
| Unit | T6 | Canonical preimage strips `signature` + `tsa_token` (sig+tsa-set serialises to identical bytes as sig+tsa-None) | `cold_storage.rs::tests::canonical_bytes_strip_signature_and_tsa` |
| Unit | T7 | RFC 3161 `TimeStampReq` carries SHA-256 OID and the digest bytes | `cold_storage.rs::tests::rfc3161_request_carries_sha256_oid_and_digest` |
| Integration | T8 | Sign-then-verify round-trip recovers the embedded public key from `archival_sk[64..128]` | `cold_storage.rs::tests::signed_manifest_round_trip_recovers_pk` |
| Integration | T9 | Tampering with a signed manifest's fields invalidates the signature | `cold_storage.rs::tests::verify_rejects_tampered_manifest` |
| Integration | T10 | `--sign-with-operator <unknown_addr>` rejected with explicit "no entry" error | `cold_storage.rs::tests::sign_with_unknown_operator_is_rejected` |
| Integration | T11 | Importer refuses an unsigned manifest without `--insecure-no-verify` | `cold_storage.rs::tests::import_refuses_unsigned_manifest_without_insecure_flag` |
| Integration | T12 | Importer refuses a tampered batch (XOR one byte → SHA mismatch) | `cold_storage.rs::tests::import_refuses_tampered_batch_sha` |
| Integration | T13 | Export → import round-trip replays all blocks; final tip hash matches source | `cold_storage.rs::tests::export_then_import_round_trip_replays_blocks` |
| Integration | T14 | `--require-tsa` rejects a manifest with no `tsa_token` | `cold_storage.rs::tests::require_tsa_flag_rejects_unanchored_manifest` |

---

## 12. References

- ADR-045 — Archival Overlay (SLH-DSA-SHAKE-256s + RFC 3161 TSA pattern this spec inherits for v2)
- KNOWN-ISSUES R-10 — Cold-storage rotation gap (closed by TASK-188 / commit `b6d6e80`)
- SPEC-ARCHIVAL-001 — Archival overlay (especially §4.5 SLH-DSA signing, §6 TSA anchor, §6.6 hash interop)
- SPEC-ARCHIVAL-001 §6 specifically — the TSA anchor pattern this spec will reuse in v2
- SPEC-CONSENSUS-001 §7.4 — canonical consensus block hash (the `anchor_block_hash` source of truth)
- SPEC-GENESIS-001 §0 — `chain_id_hex` UTF-8 byte hex contract
- SPEC-CEREMONY-001 — chart ceremony tooling (sister deliverable in the same 2026-05-05/06 window)
- Policy P-COMPAT-001 — additive schema evolution; v2 fields ride this policy
- RFC 8478 — Zstandard compression (§6.1)
- FIPS 180-4 — SHA-256 (§6.4)
- `crates/pqcd/src/cold_storage.rs` — implementation source of truth

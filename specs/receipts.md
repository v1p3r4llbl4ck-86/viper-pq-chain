# Transaction Receipt Specification

**Spec ID**: SPEC-RECEIPT-001  
**Version**: 0.1  
**Status**: Draft  
**Date**: 2026-04-15  
**Depends on**: ADR-029, SPEC-TX-001, SPEC-ACCOUNT-001, ADR-004, ADR-005  
**Amends**: SPEC-TX-001 (BlockHeader and Block wire format)

---

## 1. Scope

This document specifies the transaction receipt format for Viper PQ Chain. A receipt is a deterministic, consensus-committed record of the execution outcome of a single transaction. Receipts are produced by the execution layer for every transaction included in a block, committed into the block body, and cryptographically anchored in the block header via `receipts_root`. This allows any party holding the header chain to verify receipt authenticity without re-executing the block.

This specification does not cover:

- the transaction envelope format (SPEC-TX-001)
- fee calculation rules (SPEC-FEE-001)
- account and KeySet state transitions (SPEC-ACCOUNT-001)
- event or log systems (no VM exists in Phase 1; no such system is defined)
- Merkle proof serving over receipts (deferred, see §9)

Normative references: ADR-029, ADR-004, RFC 8949.

---

## 2. Normative Language

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT, RECOMMENDED, MAY, and OPTIONAL in this document are to be interpreted as described in RFC 2119.

---

## 3. Normative References

| Reference | Document |
|-----------|----------|
| ADR-029 | Transaction Receipts: Provable Minimal Receipt in Consensus State |
| ADR-004 | Deterministic CBOR for all signed protocol objects |
| ADR-005 | Fee model: bytes, sig-verify, and execution priced separately |
| SPEC-TX-001 | Transaction envelope specification |
| SPEC-ACCOUNT-001 | Account, KeySet, and Algorithm Registry specification |
| RFC 8949 | Concise Binary Object Representation (CBOR) |
| RFC 8949 §4.2 | Deterministic Encoding Requirements |
| FIPS 202 | SHA-3 Standard — SHAKE-256 extendable-output function |

---

## 4. Definitions

**Receipt**: a deterministic CBOR-encoded record of execution outcome for a single transaction, produced at block commit time and stored parallel to the transaction list in the block body.

**receipts_root**: a 32-byte commitment to the complete set of receipts for a block, included in the block header and therefore covered by the block header signature. `receipts_root` binds receipts to consensus state.

**receipt_hash**: the SHAKE-256 hash of the CBOR-encoded receipt for one transaction, used as the leaf value when computing `receipts_root`.

**gas_used**: the execution units consumed by the transaction as measured by the execution engine (`pqc-state::apply`). Defined in SPEC-FEE-001; recorded here for client visibility.

**fee_charged**: the venom deducted from the sender's account to pay for the transaction, regardless of execution outcome. Equals `min(gas_limit, gas_used) × exec_fee_per_gas + base_fee + byte_fee × tx_len + sigverify_fee` (per SPEC-FEE-001). A failed transaction still charges the fee; the fee is not refunded on failure.

**error_code**: a short uppercase ASCII string identifying the failure reason, present only when `status = 0x00`.

---

## 5. Receipt CBOR Encoding

### 5.1 Overview

A receipt is encoded as a deterministic CBOR map (RFC 8949 §4.2) with integer keys. String keys are not permitted. Fields MUST appear in ascending integer key order. All integer values use the minimal CBOR unsigned integer encoding. Absent OPTIONAL fields MUST be omitted from the map (not encoded as CBOR null or as a zero-length value).

### 5.2 Field Table

| Key | Field | Type | Size | Required |
|-----|-------|------|------|----------|
| 1 | `tx_hash` | bstr | 32 B | REQUIRED |
| 2 | `block_height` | uint | 8 B (u64) | REQUIRED |
| 3 | `status` | uint | 1 B (u8) | REQUIRED |
| 4 | `gas_used` | uint | 8 B (u64) | REQUIRED |
| 5 | `fee_charged` | uint | 8 B (u64) | REQUIRED |
| 6 | `error_code` | tstr | variable | OPTIONAL |

### 5.3 Field Semantics

**`tx_hash` (key 1)**

The SHAKE-256 hash of the raw transaction bytes (the full CBOR-encoded transaction envelope as it was received and included in the block), with output length 32 bytes. Identical to the hash used to index transactions in `tx_root`. The receipt is retrievable by this hash.

**`block_height` (key 2)**

The height of the block in which this transaction was included and executed. MUST equal `block.header.height`. This field allows a receipt to be self-describing without requiring a lookup of the containing block.

**`status` (key 3)**

Execution outcome:

| Value | Meaning |
|-------|---------|
| `0x01` | Success — transaction executed without error |
| `0x00` | Failure — transaction was included but execution failed |

All other values are RESERVED and MUST NOT be produced by compliant implementations. Nodes MUST reject blocks containing receipts with unknown `status` values.

A transaction that fails execution is still included in the block and still charges `fee_charged`. The fee deduction always succeeds; only the primary operation (transfer, attestation, etc.) is reverted.

**`gas_used` (key 4)**

Execution units consumed. On success, this is the actual gas consumed by the operation. On failure, this is the gas consumed up to the point of failure. It MUST NOT exceed the transaction's `gas_limit`. If the transaction fails due to out-of-gas, `gas_used` equals `gas_limit`.

**`fee_charged` (key 5)**

The venom amount deducted from the sender's account. Stored in venom (atomic units). MUST be non-zero for all transactions (the `base_fee` is always charged). The value here is the source of truth for fee accounting; clients MUST use this field rather than recomputing the fee themselves.

**`error_code` (key 6)**

Present when and only when `status = 0x00`. A short, uppercase, ASCII-only string identifying the failure reason. MUST NOT be present when `status = 0x01`. MUST NOT exceed 64 bytes in UTF-8 encoding.

### 5.4 Defined Error Codes

| Error Code | Condition |
|------------|-----------|
| `INSUFFICIENT_BALANCE` | Sender balance is less than `fee_charged + transfer_amount` |
| `INVALID_NONCE` | Transaction nonce does not match the sender's current nonce |
| `OUT_OF_GAS` | `gas_used` reached `gas_limit` before operation completed |
| `INVALID_SIGNATURE` | Signature verification failed against the sender's active key |
| `UNKNOWN_ALG` | `sig_alg_id` references an algorithm not in the Algorithm Registry |
| `DEPRECATED_ALG` | `sig_alg_id` references an algorithm with `lifecycle_status = Deprecated` or `Banned` |
| `ACCOUNT_NOT_FOUND` | Sender account does not exist in state |
| `KEY_NOT_FOUND` | Signing key version (`sig_key_version`) not found in the sender's KeySet |
| `PAYLOAD_INVALID` | Payload bytes could not be deserialized as the declared `msg_type` |
| `PERMISSION_DENIED` | Operation requires a capability the sender does not hold |

Additional error codes MAY be introduced in future protocol versions. Implementations MUST store and relay the `error_code` string as received; they MUST NOT fail to parse a receipt containing an unrecognized `error_code`.

### 5.5 CBOR Encoding Example

A success receipt for a token transfer at height 42000:

```
{
  1: h'a3f2...32 bytes...c901',   // tx_hash
  2: 42000,                        // block_height
  3: 1,                            // status = 0x01 success
  4: 58300,                        // gas_used
  5: 15000,                        // fee_charged (venom)
  // key 6 absent — no error_code on success
}
```

A failure receipt:

```
{
  1: h'7c44...32 bytes...f201',   // tx_hash
  2: 42001,                        // block_height
  3: 0,                            // status = 0x00 failure
  4: 80000,                        // gas_used = gas_limit (out-of-gas)
  5: 15000,                        // fee_charged still deducted
  6: "OUT_OF_GAS",                 // error_code
}
```

---

## 6. `receipts_root` Derivation

### 6.1 Overview

`receipts_root` is a 32-byte digest that commits to the ordered set of receipts for a block. It is deterministic: given the same set of transactions in the same order, every correct node MUST produce the same `receipts_root`.

### 6.2 Step-by-Step Algorithm

Given an ordered list of receipts `[R_0, R_1, ..., R_{n-1}]` (one per transaction, in the same order as `block.transactions`):

**Step 1 — Encode each receipt.**

For each receipt `R_i`, compute:

```
encoded_i = cbor_encode(R_i)
```

`cbor_encode` produces deterministic CBOR per RFC 8949 §4.2 and ADR-004. Fields MUST be in ascending integer key order. OPTIONAL absent fields MUST be omitted.

**Step 2 — Hash each receipt.**

For each encoded receipt `encoded_i`, compute:

```
receipt_hash_i = SHAKE-256(encoded_i, output_len=32)
```

No domain separator is applied to individual receipt hashes; the domain separator is applied at the root computation step (§6.2 Step 3) to prevent cross-context collision.

**Step 3 — Sort receipt hashes.**

Sort the receipt hash bytes lexicographically (unsigned byte comparison, big-endian byte order, shortest-first for equal prefixes — identical to the sort used for `state_root` leaf ordering in PQC-STATE-ROOT-V2):

```
sorted_hashes = sort_lexicographic([receipt_hash_0, receipt_hash_1, ..., receipt_hash_{n-1}])
```

**Step 4 — Compute `receipts_root`.**

Concatenate the domain separator and all sorted receipt hashes in sequence:

```
receipts_root = SHAKE-256(
  "VIPER-RECEIPTS-V1"          ||   // domain separator, ASCII, no null terminator, 18 bytes
  sorted_hashes[0]             ||   // 32 bytes
  sorted_hashes[1]             ||   // 32 bytes
  ...
  sorted_hashes[n-1],               // 32 bytes
  output_len = 32
)
```

The `||` operator denotes byte concatenation. No length prefix or separator is inserted between receipt hashes.

**Step 5 — Empty block edge case.**

If the block contains no transactions (and therefore no receipts), `receipts_root` is defined as:

```
receipts_root = SHAKE-256("VIPER-RECEIPTS-V1", output_len=32)
```

This is the Step 4 formula applied with an empty concatenation after the domain separator.

### 6.3 Invariants

- The `receipts_root` computation MUST be performed over the fully committed set of receipts, after all transactions in the block have been applied to state.
- The order of receipts MUST match the order of transactions in `block.transactions` before sorting. Sorting is applied to receipt hashes in Step 3, not to the receipts themselves; the canonical receipt order is insertion order (parallel to the tx list).
- An implementation MUST NOT include receipts for transactions outside the block, or omit receipts for transactions inside the block. The receipt list length MUST equal the transaction list length.
- `receipts_root` is included in the block header preimage (§7.2) and is therefore signed by the proposer. Any node that verifies the block header signature implicitly verifies `receipts_root`.

### 6.4 Rationale for Sorted Hashing

Sorting receipt hashes before hashing the root prevents the root from being sensitive to transaction ordering in the block (beyond what `tx_root` already captures). This makes it easier to construct set-membership proofs for individual receipts without requiring knowledge of the full transaction order. The sorted structure is consistent with the approach used for `state_root` in PQC-STATE-ROOT-V2.

---

## 7. Block and BlockHeader Changes

### 7.1 `Block` Structure Change

The `Block` struct in `pqc-types::block` is amended to carry a parallel receipt list:

**Before (current `pqc-types::block::Block`):**

| Field | Type | Description |
|-------|------|-------------|
| `header` | `BlockHeader` | Block header |
| `tx_hashes` | `Vec<TxHash>` | Ordered list of transaction hashes |
| `commit_signatures` | `Vec<CommitSig>` | Commit quorum signatures |

**After (SPEC-RECEIPT-001):**

| Field | Type | Description |
|-------|------|-------------|
| `header` | `BlockHeader` | Block header |
| `tx_hashes` | `Vec<TxHash>` | Ordered list of transaction hashes |
| `commit_signatures` | `Vec<CommitSig>` | Commit quorum signatures |
| `receipts` | `Vec<Receipt>` | Ordered receipt list, parallel to `tx_hashes` |

The invariant `receipts.len() == tx_hashes.len()` MUST be enforced at block assembly time and at block import time. A node MUST reject a block where this invariant is violated.

### 7.2 `BlockHeader` Structure Change

The `BlockHeader` struct in `pqc-types::block` is amended to include `receipts_root`:

**Before (current `pqc-types::block::BlockHeader`):**

| Field | Type | Description |
|-------|------|-------------|
| `height` | `u64` | Block height |
| `prev_hash` | `BlockHash` | Hash of the previous block header |
| `state_root` | `BlockHash` | Post-execution state root |
| `tx_root` | `BlockHash` | Merkle root of transaction hashes |
| `timestamp` | `u64` | Unix timestamp (seconds) |
| `proposer` | `Vec<u8>` | Validator address (32 bytes) |

**After (SPEC-RECEIPT-001):**

| Field | Type | Description |
|-------|------|-------------|
| `height` | `u64` | Block height |
| `prev_hash` | `BlockHash` | Hash of the previous block header |
| `state_root` | `BlockHash` | Post-execution state root |
| `tx_root` | `BlockHash` | Merkle root of transaction hashes |
| `receipts_root` | `BlockHash` | Receipt commitment (§6) |
| `timestamp` | `u64` | Unix timestamp (seconds) |
| `proposer` | `Vec<u8>` | Validator address (32 bytes) |

`receipts_root` is placed after `tx_root` and before `timestamp`. This ordering MUST be followed in all CBOR-encoded representations of `BlockHeader`.

### 7.3 Block Header Preimage

The block header preimage (the bytes that are hashed to produce the block hash, and over which the proposer's signature is computed) MUST include `receipts_root`. The preimage construction in `pqc-consensus::engine` MUST incorporate `receipts_root` in the same fixed position as the struct ordering in §7.2.

The specific preimage format is: the CBOR encoding of `BlockHeader` with all fields present in the order defined in §7.2, using deterministic CBOR (ADR-004). The block hash is `SHAKE-256(cbor_encode(BlockHeader), output_len=32)`.

### 7.4 CBOR Field Assignment for `BlockHeader`

The existing `BlockHeader` CBOR map key assignment (from SPEC-TX-001's block record section and `pqc-consensus::engine`) must be extended:

| Key | Field |
|-----|-------|
| 1 | `height` |
| 2 | `prev_hash` |
| 3 | `state_root` |
| 4 | `tx_root` |
| 5 | `receipts_root` ← **new** |
| 6 | `timestamp` |
| 7 | `proposer` |

Keys previously assigned to `timestamp` (6) and `proposer` (7) are shifted. This is a **breaking change** to the `BlockHeader` wire format (see §8).

### 7.5 `Block` CBOR Map Extension

| Key | Field |
|-----|-------|
| 1 | `header` |
| 2 | `tx_hashes` |
| 3 | `commit_signatures` |
| 4 | `receipts` ← **new** |

---

## 8. Upgrade Path

### 8.1 Nature of the Breaking Change

Adding `receipts_root` to `BlockHeader` is a **wire-format breaking change** to `BlockHeader` (SPEC-TX-001 §7.2 and the CBOR key assignment). Under the Phase 4 backward-compatibility rule, no field addition to `BlockHeader` or `Block` is permitted without an ADR and a coordinated upgrade path. ADR-029 records this decision.

### 8.2 Upgrade Height

This change is introduced at a designated **upgrade height** `H_receipts`, agreed upon by all validators before the upgrade activates. The upgrade height MUST be published in the genesis configuration (or via governance proposal) so that all nodes can prepare.

- Blocks at height `h < H_receipts`: `BlockHeader` does NOT contain `receipts_root`. Blocks MUST NOT contain `receipts`. Any node that receives a post-upgrade `BlockHeader` for a pre-upgrade height MUST reject it.
- Blocks at height `h >= H_receipts`: `BlockHeader` MUST contain `receipts_root`. Blocks MUST contain `receipts`. Any node that receives a pre-upgrade `BlockHeader` for a post-upgrade height MUST reject it.

### 8.3 Node Behavior During Upgrade

**Pre-upgrade nodes** (nodes that have not applied this spec):
- Will fail to parse `BlockHeader` at `H_receipts` because CBOR key 5 is unexpected.
- Will crash or halt at `H_receipts`.
- This is intentional: pre-upgrade nodes MUST NOT participate in consensus at or after `H_receipts`. Node operators MUST upgrade before `H_receipts`.

**Post-upgrade nodes** (nodes implementing this spec):
- Accept and produce `BlockHeader` with `receipts_root` at and after `H_receipts`.
- Accept `BlockHeader` without `receipts_root` below `H_receipts`.
- When importing historical blocks (below `H_receipts`) from disk or via P2P sync, parse them using the pre-upgrade `BlockHeader` schema.

### 8.4 Historical Block Access

Nodes MUST maintain the ability to parse and serve historical blocks (below `H_receipts`) using the pre-upgrade schema. This requires the CBOR deserialization path to be height-aware. The `DiskChainStore` and `ChainStore` implementations MUST branch on height when decoding `BlockHeader`.

For blocks below `H_receipts`:
- `receipts_root` is absent — any access to `block.header.receipts_root` MUST return an error or a sentinel value (`[0u8; 32]`), never a fabricated hash.
- Receipt API requests (`GET /v1/txs/:tx_hash/receipt`) for transactions in pre-upgrade blocks MUST return `404` with error code `RECEIPT_NOT_AVAILABLE` (§10.2).

### 8.5 Devnet / Testnet Strategy

For the devnet, the simplest upgrade strategy is a **chain reset** at `H_receipts = 0`: wipe chain data and restart from genesis with the new block format. This avoids the historical schema branching requirement entirely and is the recommended approach for pre-mainnet deployments. The `make reset-chain` target (ADR-028) automates this.

For mainnet, a live upgrade at a well-defined height is required.

---

## 9. API Specification

### 9.1 `GET /v1/txs/:tx_hash/receipt`

Fetch the receipt for a specific transaction.

**Path parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `tx_hash` | hex string | SHAKE-256 hash of the raw transaction bytes, hex-encoded, 64 characters |

**Request**: no request body.

**Success response** (`200 OK`):

```json
{
  "tx_hash": "a3f2c9...64 hex chars",
  "block_height": 42000,
  "status": "success",
  "gas_used": 58300,
  "fee_charged": 15000,
  "error_code": null
}
```

**Success response** (`200 OK`, failed transaction):

```json
{
  "tx_hash": "7c44f1...64 hex chars",
  "block_height": 42001,
  "status": "failure",
  "gas_used": 80000,
  "fee_charged": 15000,
  "error_code": "OUT_OF_GAS"
}
```

**JSON field specification:**

| Field | JSON type | Description |
|-------|-----------|-------------|
| `tx_hash` | string | Hex-encoded 32-byte SHAKE-256 hash of the transaction |
| `block_height` | number (u64) | Block height in which the transaction was included |
| `status` | string | `"success"` or `"failure"` |
| `gas_used` | number (u64) | Execution units consumed |
| `fee_charged` | number (u64) | Venom deducted from sender |
| `error_code` | string or null | Error code string on failure; `null` on success |

The `status` field MUST be the string `"success"` or `"failure"`, not a numeric value (numeric status is CBOR-internal; the JSON API uses human-readable strings for clarity).

**Error responses:**

| HTTP Status | Condition | JSON body |
|-------------|-----------|-----------|
| `404 Not Found` | Transaction not found in any committed block, or transaction in a pre-upgrade block | `{"error": "TX_NOT_FOUND"}` or `{"error": "RECEIPT_NOT_AVAILABLE"}` — see §10 |
| `400 Bad Request` | `tx_hash` is not a valid 64-character hex string | `{"error": "INVALID_TX_HASH"}` |
| `503 Service Unavailable` | Node is syncing and has not yet processed this height | `{"error": "NODE_SYNCING"}` |

### 9.2 `POST /v1/txs` — Receipt in Commit Response

The existing `POST /v1/txs` endpoint (which submits a transaction and waits for commitment before returning) MUST include the receipt in its response body once the transaction is committed. The response shape is amended as follows:

**Current response shape (before SPEC-RECEIPT-001):**

```json
{
  "tx_hash": "...",
  "block_height": 42000,
  "status": "committed"
}
```

**Amended response shape (SPEC-RECEIPT-001):**

```json
{
  "tx_hash": "...",
  "block_height": 42000,
  "status": "committed",
  "receipt": {
    "tx_hash": "...",
    "block_height": 42000,
    "status": "success",
    "gas_used": 58300,
    "fee_charged": 15000,
    "error_code": null
  }
}
```

The `receipt` field is added additively. The existing fields (`tx_hash`, `block_height`, `status: "committed"`) MUST remain present and unchanged (Phase 4 additive-only API stability rule). The embedded `receipt.status` (`"success"` / `"failure"`) is distinct from the outer `status` (`"committed"`); the outer status reflects inclusion; the inner `receipt.status` reflects execution outcome.

If the node is not configured to wait for commitment (fire-and-forget submission mode), the `receipt` field MAY be `null` or absent. In that case, callers MUST use `GET /v1/txs/:tx_hash/receipt` to retrieve the receipt after inclusion.

---

## 10. Error Codes

### 10.1 Receipt-Level Error Codes

These appear in `Receipt.error_code` (CBOR key 6). See §5.4 for the full list.

### 10.2 API Error Codes

These appear in HTTP error response bodies from the `/v1/txs/:tx_hash/receipt` endpoint.

| Code | HTTP Status | Meaning |
|------|-------------|---------|
| `TX_NOT_FOUND` | 404 | The `tx_hash` does not appear in any committed block known to this node |
| `RECEIPT_NOT_AVAILABLE` | 404 | The transaction exists in a committed block below the upgrade height `H_receipts`; no receipt was recorded for it |
| `INVALID_TX_HASH` | 400 | The `tx_hash` path parameter is not a valid 64-character lowercase hex string |
| `NODE_SYNCING` | 503 | The node has not yet synced to the height at which this transaction was committed; try again later |

---

## 11. Implementation Checklist

The following crates and modules MUST be modified to implement SPEC-RECEIPT-001. Changes are listed in dependency order.

### 11.1 `pqc-types` — Core type definitions

- [ ] Add `Receipt` struct to `crates/pqc-types/src/block.rs` with fields: `tx_hash: [u8; 32]`, `block_height: u64`, `status: u8`, `gas_used: u64`, `fee_charged: u64`, `error_code: Option<String>`.
- [ ] Add CBOR serialization (`serde`/`ciborium` or hand-rolled deterministic encoding) for `Receipt` with integer keys per §5.2.
- [ ] Add `receipts_root: BlockHash` field to `BlockHeader` struct (after `tx_root`, before `timestamp`).
- [ ] Add `receipts: Vec<Receipt>` field to `Block` struct (after `commit_signatures`).
- [ ] Update `BlockHeader` CBOR encoding to include `receipts_root` as key 5; shift `timestamp` to key 6 and `proposer` to key 7.
- [ ] Update `Block` CBOR encoding to include `receipts` as key 4.
- [ ] Add `compute_receipts_root(receipts: &[Receipt]) -> [u8; 32]` function implementing the algorithm in §6.2.
- [ ] Add unit tests: empty receipt list, single receipt success, single receipt failure with error_code, multi-receipt determinism, round-trip CBOR encode/decode.

**Audit note**: `pqc-types` is in audit scope. The `Receipt` CBOR encoding and `compute_receipts_root` function are cryptographically load-bearing and MUST be reviewed for correctness of key ordering, domain separator, and sort order.

### 11.2 `pqc-state` — Execution and receipt production

- [ ] In `crates/pqc-state/src/apply/` (all `apply_*` functions): return a `Receipt` from each transaction application instead of returning unit. Each apply function MUST capture `gas_used` and `fee_charged` at the point of deduction and populate `status` and `error_code` on the error path.
- [ ] Update `pqc-state::apply` top-level dispatcher to collect `Vec<Receipt>` across all transactions in a block.
- [ ] Ensure `fee_charged` is populated correctly even on failure paths (fee is always charged).
- [ ] Add unit tests: verify receipt produced on success has `status = 0x01` and no `error_code`; verify receipt produced on each failure variant has `status = 0x00` and the correct `error_code` string.

**Audit note**: `pqc-state::apply` is in audit scope. The error path that sets `error_code` must not leak internal key material or timing information (Phase 4 security rule).

### 11.3 `pqc-consensus::engine` — Block assembly

- [ ] In `crates/pqc-consensus/src/engine.rs` (`build_next_block` or equivalent): after applying all transactions to state, collect the `Vec<Receipt>` from `pqc-state::apply`.
- [ ] Call `compute_receipts_root(&receipts)` (from `pqc-types`) to produce `receipts_root`.
- [ ] Set `block.header.receipts_root = receipts_root`.
- [ ] Set `block.receipts = receipts`.
- [ ] Enforce the invariant `block.receipts.len() == block.tx_hashes.len()` before finalizing the block.
- [ ] Update block hash computation to include the new `BlockHeader` shape (automatic if the hash is derived from CBOR-encoding the full `BlockHeader`).
- [ ] Add the `H_receipts` upgrade-height gate: blocks below `H_receipts` MUST be produced and validated using the old schema.

### 11.4 `pqc-consensus::chain` / `pqc-consensus::storage` — Block import and validation

- [ ] In block import (`crates/pqc-consensus/src/chain.rs`): validate the incoming block's `receipts_root` by recomputing it from `block.receipts` and comparing with `block.header.receipts_root`. MUST reject the block if they differ.
- [ ] Enforce `receipts.len() == tx_hashes.len()` on import.
- [ ] In `crates/pqc-consensus/src/storage.rs`: persist `block.receipts` alongside the block. The receipt store MUST be indexed by `tx_hash` for O(1) lookup by the API layer.
- [ ] Add a receipt index: `receipt_by_tx_hash: HashMap<TxHash, Receipt>` or equivalent persistent index.
- [ ] Handle height-aware schema branching for historical blocks (§8.4).

### 11.5 `pqcd::api` — HTTP API

- [ ] In `crates/pqcd/src/api.rs`: add route `GET /v1/txs/:tx_hash/receipt` with the response shape defined in §9.1.
- [ ] Parse `:tx_hash` as a 64-character lowercase hex string; return `400 INVALID_TX_HASH` on malformed input.
- [ ] Look up receipt in the persistent receipt index. Return `404 TX_NOT_FOUND` if not present.
- [ ] Return `404 RECEIPT_NOT_AVAILABLE` if the transaction is found but was included at a height below `H_receipts`.
- [ ] Amend `POST /v1/txs` response to embed the `receipt` field (§9.2) after the transaction is committed.
- [ ] Update `API.md` to document the new endpoint and the amended `POST /v1/txs` response shape.

### 11.6 Upgrade height configuration

- [ ] Add `receipts_upgrade_height: u64` to the node configuration structure (`pqcd::node` or genesis config).
- [ ] Default to `0` for devnet (all blocks use new format from genesis, equivalent to a chain reset).
- [ ] Expose the upgrade height in `GET /v1/status` response as `receipts_upgrade_height`.

---

## 12. Open Questions

### 12.1 Merkle Proof Serving (deferred)

ADR-029 describes receipts as "provable." The current spec commits `receipts_root` into the header, which is necessary but not sufficient for serving individual receipt proofs. A full Merkle proof path (from a single receipt hash up to `receipts_root`) would require a Merkle tree structure rather than the sorted-hash-concatenation approach defined in §6. A future spec (SPEC-RECEIPT-002) may define a Merkle tree structure and a `GET /v1/txs/:tx_hash/receipt/proof` endpoint. The sorted-hash approach in §6 is compatible with upgrading to a Merkle tree: the root computation can switch to a tree without changing the individual receipt encoding.

### 12.2 Receipt Storage Size

At 1 block/second and 100 txs/block, each receipt is approximately 60–120 bytes (CBOR-encoded). Receipt storage grows at ~6–12 KB/block (~15–30 GB/year at 100 tx/block). A receipt pruning policy (retain receipts for 90 days, then evict to cold storage) is not defined in this spec and is deferred to Phase 6 operations planning.

### 12.3 `gas_used` Granularity

The current fee model (SPEC-FEE-001) uses a coarse gas accounting model. Whether `gas_used` in the receipt reflects fine-grained per-opcode gas or the coarse block-level estimate is left to the SPEC-FEE-001 implementation. The receipt records whatever value `pqc-state::apply` returns; the spec does not further constrain it beyond requiring `gas_used <= gas_limit`.

### 12.4 Replay of Pre-Upgrade Blocks

When a node syncs from genesis on a chain that has already passed `H_receipts`, it must apply pre-upgrade blocks (no receipts) and post-upgrade blocks (with receipts) in sequence. The pre-upgrade blocks will not have receipt records in the store. The correctness of state transitions does not depend on receipts, so this is a storage and API concern only. This path is not currently tested and SHOULD be validated before mainnet.

---

## 13. Cross-References

| Document | Relationship |
|----------|-------------|
| ADR-029 | Decision that mandates this spec; source of all design choices |
| SPEC-TX-001 | Transaction envelope; defines `tx_hash`, `gas_limit`, `fee`; amended by this spec (BlockHeader and Block wire format) |
| SPEC-ACCOUNT-001 | Account and balance model; `fee_charged` deducted from sender's account balance |
| SPEC-FEE-001 | Fee model; defines `gas_used` units, fee coefficient computation |
| ADR-004 | Deterministic CBOR; applies to `Receipt` encoding |
| ADR-005 | Fee decomposition; `fee_charged` is the sum of base, byte, sigverify, and exec components |
| ADR-028 | Chain reset procedure; recommended upgrade path for devnet (`make reset-chain`) |
| `pqc-types::block` | Primary Rust module to be modified; see §11.1 |
| `pqc-state::apply` | Receipt producer; see §11.2 |
| `pqc-consensus::engine` | Block assembly integration; see §11.3 |
| `pqcd::api` | HTTP API layer; see §11.5 |
| `API.md` | Must be updated when `GET /v1/txs/:tx_hash/receipt` is added |

# API

## Status

**Implementation status**: 2026-08-24, public-release branch. `pqcd`
serves two HTTP routers on port 26657:

- `pqcd devnet-serve <node.json>` — the node runtime. This is what every
  role (`validator`, `sentry`, `full`, `rpc`, `archive`, `bootnode`,
  `single_node`) runs, and the router in `crates/pqcd/src/devnet.rs` is
  the public API surface of the network.
- `pqcd api-serve <node.json> [addr]` — a read-only server over the
  persisted chain (`crates/pqcd/src/api.rs`), for offline inspection of a
  data directory. It overlaps with the runtime router but is not
  identical.

`viper-testnet-2` is live since 2026-08-25: the endpoints below are served at
`https://pqchain.agwswebconsulting.it` (read API under `/v1/`, notary under `/api/`,
alias `rpc.pqchain.agwswebconsulting.it`).

Three configuration flags in the `api` section of `node.json` gate parts
of the runtime surface (`crates/pqcd/src/node.rs`, `ApiConfig`):

| Flag | Gates | Default in code | In `configs/roles/*.json` |
|---|---|---|---|
| `public_tx_submission` | `POST /v1/txs` | `true` | `true` for `full`, `rpc`, `sentry`, `archive`; `false` for `validator`, `bootnode` (and `single_node` by role default) |
| `expose_token_state` | `/v1/accounts/{address}`, `/v1/accounts/{address}/attestations`, `/v1/fee-market` | `true` | `false` in every role config (no native token) |
| `expose_notary_routes` | `/api/credentials/*`, `/api/proofs/*` | `true` | `false` in every role config (the notary is a separate, private deployment) |

The startup config lint reports a validator or bootnode that turns
`public_tx_submission` on (ADR-069). `/internal/metrics` and
`/internal/p2p/*` exist for cluster-internal use only and are **not part
of the public surface**; do not expose them.

## Implemented endpoints

Runtime router (`pqcd devnet-serve`), always on:

| Method | Path | Notes |
|---|---|---|
| GET | `/v1/status` | chain id, height, tip hash, state root, base fee |
| GET | `/v1/blocks/{height}` | finalized block by height |
| GET | `/v1/txs/{hash}` | finalized transaction lookup |
| GET | `/v1/attestations/{id}` | finalized attestation record |
| GET | `/v1/proofs/{anchor_id}` | proof anchor (`anchor_id` = tx hash hex) |
| GET | `/v1/validators` | validator set with `peer_id_hex` |
| GET | `/v1/validators/{address}` | one validator |
| GET | `/v1/algorithms` | algorithm registry |
| GET | `/v1/algorithms/{alg_id}` | one registry entry |
| GET | `/v1/governance/proposals` | proposals list |
| GET | `/v1/governance/proposals/{proposal_id}` | proposal detail |
| GET | `/v1/governance/proposals/{proposal_id}/votes` | votes on a proposal |
| GET | `/v1/archival/records` | archival overlay records (ADR-045) |
| GET | `/v1/archival/records/{epoch}` | archival record for one epoch |
| GET | `/v1/metrics` | Prometheus text format |
| GET | `/api/health` | health, height, uptime |
| GET | `/openapi.yaml` | OpenAPI 3.0 document |
| GET | `/docs` | Swagger UI |

Runtime router, gated by the flags above:

| Method | Path | Flag |
|---|---|---|
| POST | `/v1/txs` | `public_tx_submission` |
| GET | `/v1/accounts/{address}` | `expose_token_state` |
| GET | `/v1/accounts/{address}/attestations` | `expose_token_state` |
| GET | `/v1/fee-market` | `expose_token_state` |
| POST | `/api/credentials/issue` | `expose_notary_routes` |
| GET | `/api/credentials/{id}` | `expose_notary_routes` |
| POST | `/api/proofs/anchor` | `expose_notary_routes` |
| GET | `/api/proofs/{id}` | `expose_notary_routes` |

Read-only router (`pqcd api-serve`):

| Method | Path |
|---|---|
| GET | `/v1/network` |
| GET | `/v1/blocks/latest` |
| GET | `/v1/txs/{hash}` |
| GET | `/v1/accounts/{address}` |
| GET | `/v1/attestations/{id}` |
| GET | `/v1/proofs/{anchor_id}` |
| GET | `/v1/governance/receipts/{proposal_id}` |

**Specified, not implemented** (documented in the specification below,
no route in either router): `GET /v1/txs` (list), `GET /v1/attestations`
(list), `GET /v1/anchors/{anchor_id}`, `GET /v1/governance/parameters`.
`GET /v1/network` and `GET /v1/blocks/latest` exist only on the
read-only router. These are tracked in `KNOWN-ISSUES.md` D-07.

### GET /v1/status

Returns the current node status including chain identity, block position, and AIMD adaptive base fee.

```json
{
  "node_id": "string",
  "chain_id": "hex-string",
  "height": 1,
  "tip_hash": "64-hex-chars",
  "state_root": "64-hex-chars",
  "base_fee": 100
}
```

`base_fee` is the current AIMD adaptive base fee in venom (SPEC-FEE-002). Zero until the first block is committed.

### GET /v1/fee-market

Returns the current AIMD adaptive fee market state (SPEC-FEE-002).

```json
{
  "base_fee": 100,
  "block_gas_limit": 10000000,
  "burn_rate_bps": 0,
  "target_utilization_bps": 5000
}
```

`base_fee` is in venom. `block_gas_limit` is the per-block gas ceiling. `burn_rate_bps` is the fraction of fees burned (0 in Phase 8; activated by governance). `target_utilization_bps` is the 50% AIMD target (fixed).

### GET /v1/network

**Implemented**: yes, on the read-only router (`pqcd api-serve`) only; the runtime router exposes the same fields through `GET /v1/status`.

Returns chain identity and latest committed block position.

```json
{
  "chain_id": "hex-string",
  "height": 1,
  "tip_hash": "64-hex-chars",
  "state_root": "64-hex-chars",
  "recovery_source": "full_replay | trusted_checkpoint"
}
```

### GET /v1/blocks/latest

Returns the most recently committed block header.

```json
{
  "height": 1,
  "hash": "64-hex-chars",
  "prev_hash": "64-hex-chars",
  "state_root": "64-hex-chars",
  "tx_root": "64-hex-chars",
  "timestamp": 1710000000,
  "tx_count": 1
}
```

Returns `404` if no blocks have been committed yet.

### GET /v1/txs/{hash}

Looks up a finalized transaction by its SHAKE-256 hash (hex-encoded, 64 chars).

```json
{
  "hash": "64-hex-chars",
  "block_height": 1,
  "sender": "64-hex-chars",
  "msg_type": "TokenTransfer",
  "nonce": 0,
  "fee": 100,
  "fee_tip": 0,
  "status": "finalized"
}
```

Returns `400` for malformed hash, `404` if not found.

### GET /v1/accounts/{address}

Returns account state by address (hex-encoded 32-byte address, 64 chars).

```json
{
  "address": "64-hex-chars",
  "balance": 49900,
  "nonce": 2,
  "keys": [
    {
      "alg_id": 2,
      "key_version": 1,
      "valid_from_height": 0,
      "status": "active",
      "allowed_tx_types": 4294967295
    }
  ]
}
```

Returns `400` for malformed address, `404` if not found.

### GET /v1/attestations/{id}

Returns a finalized attestation record by attestation id (`tx_hash` of the original `attestation_create`).

```json
{
  "attestation_id": "64-hex-chars",
  "attester": "64-hex-chars",
  "status": "active",
  "attestation_type": 2,
  "attestation_type_name": "document_notarization",
  "subject": "64-hex-chars",
  "content_hash": "64-hex-chars",
  "schema_id": "64-hex-chars",
  "metadata_hash": "64-hex-chars",
  "anchor_height": 1,
  "expires_at_height": 50,
  "revocation": null
}
```

Returns `400` for malformed attestation id, `404` if not found.

---

### GET /v1/proofs/{anchor_id}

Returns a finalized proof anchor record by anchor id (`tx_hash` of the `proof_anchor` transaction, 64-hex-char string).

```json
{
  "data": {
    "anchor_id": "64-hex-chars",
    "claimer": "64-hex-chars",
    "claim_type": 1,
    "claim_type_name": "ownership",
    "asset_id_hash": "64-hex-chars",
    "proof_hash": "64-hex-chars",
    "schema_id": null,
    "anchor_height": 3
  }
}
```

`claim_type_name` values: `"ownership"` (0x0001), `"custody"` (0x0002), `"asset_metadata"` (0x0003); `null` for unrecognized values (cannot occur for Phase 1 valid anchors).

Returns `400` with code `INVALID_ANCHOR_ID` for malformed anchor ids. Returns `404` with code `PROOF_ANCHOR_NOT_FOUND` if not found.

---

## Service API Endpoints

These endpoints provide business-friendly access to on-chain data and convenience wrappers for building transactions. They are served alongside the core `/v1/` endpoints on the same API port. `/api/health` is always on; the `/api/credentials/*` and `/api/proofs/*` wrappers are gated by `api.expose_notary_routes`, which every reference role config sets to `false` because the notary service is deployed separately.

### GET /api/health

Returns node health status, chain height, and uptime.

```json
{
  "status": "ok",
  "chain_height": 1234,
  "node_id": "devnet-node-1",
  "uptime_seconds": 86400
}
```

---

### POST /api/credentials/issue

Convenience endpoint that validates credential issuance parameters and returns a structured response describing the `attestation_create` transaction that would be built.

**Request body**:

```json
{
  "issuer_address": "64-hex-chars",
  "subject": "64-hex-chars",
  "credential_type": "diploma",
  "content_hash": "64-hex-chars",
  "schema_id": "edu-diploma-v1"
}
```

**Response**:

```json
{
  "status": "accepted",
  "credential_id": "64-hex-chars",
  "msg_type": "attestation_create",
  "verify_url": "/api/credentials/<id>"
}
```

Returns `400` with code `INVALID_INPUT` for malformed fields.

---

### GET /api/credentials/{id}

Business-friendly wrapper around `/v1/attestations/{id}`. Returns credential-oriented field names.

```json
{
  "credential_id": "64-hex-chars",
  "issuer": "64-hex-chars",
  "subject": "64-hex-chars",
  "credential_type": "document_notarization",
  "issued_at_block": 123,
  "status": "active",
  "content_hash": "64-hex-chars",
  "verify_url": "/api/credentials/<id>"
}
```

Returns `400` for malformed id, `404` if not found.

---

### POST /api/proofs/anchor

Convenience endpoint that validates proof anchoring parameters and returns a structured response describing the `proof_anchor` transaction that would be built.

**Request body**:

```json
{
  "owner_address": "64-hex-chars",
  "claim_type": "ownership",
  "document_hash": "64-hex-chars",
  "proof_hash": "64-hex-chars"
}
```

**Response**:

```json
{
  "status": "accepted",
  "proof_id": "64-hex-chars",
  "msg_type": "proof_anchor",
  "verify_url": "/api/proofs/<id>"
}
```

Returns `400` with code `INVALID_INPUT` for malformed fields.

---

### GET /api/proofs/{id}

Business-friendly wrapper around `/v1/proofs/{anchor_id}`. Returns proof-oriented field names.

```json
{
  "proof_id": "64-hex-chars",
  "owner": "64-hex-chars",
  "claim_type": "ownership",
  "document_hash": "64-hex-chars",
  "proof_hash": "64-hex-chars",
  "anchored_at_block": 456,
  "status": "anchored",
  "verify_url": "/api/proofs/<id>"
}
```

Returns `400` for malformed id, `404` if not found.

---

### GET /openapi.yaml

Serves the OpenAPI 3.0 specification as YAML. Content-type: `text/yaml`.

### GET /docs

Serves the Swagger UI interactive documentation page. Content-type: `text/html`.

---

## Interface Families

| Surface | Audience | Purpose | Phase 1 status |
|---------|----------|---------|----------------|
| Public read API | wallets, explorers, integrators | network, block, account, attestation, governance, and validator reads | minimal finalized subset live; broader list/query surfaces still planned |
| Transaction submission API | wallets, SDKs, automation | broadcast signed canonical CBOR transactions | implemented (`POST /v1/txs`, gated by `api.public_tx_submission`) |
| Operator API | validators and node operators | health, metrics, maintenance, snapshots | internal only at first testnet (ADR-014) |
| P2P protocol | nodes only | peer discovery, block propagation, consensus traffic | not specified here |

---

## Design Principles

- signed payloads are canonical CBOR bytes first; the API exposes a derived JSON view, never the reverse
- `tx_bytes` (canonical CBOR) is always the source of truth for submission and hash derivation
- every public interface is versioned from day one (`/v1/`)
- read surfaces return deterministic snapshots of finalized state; pending mempool data is clearly labeled
- the API observes protocol state — it does not define it; all semantics are defined in the spec documents
- pagination is required on all list endpoints; unbounded responses are not permitted
- error responses include enough detail for clients to compute the corrected request

---

## Base URL Convention

```text
Local node:     http://localhost:<port>/v1
Public gateway: https://<network-host>/v1
```

---

## Authentication Model

| Surface | Authentication |
|---------|----------------|
| Public read API | none; rate limiting applied |
| Transaction submission API | none; rate limiting and per-sender anti-abuse controls applied |
| Operator API | strong operator authentication; mechanism TBD; not publicly exposed at first testnet |

---

## Common Response Shape

### Success

```json
{
  "data": { },
  "meta": {
    "network_id": "pqchain-testnet-1",
    "api_version": "v1",
    "height": 12345
  }
}
```

### Error

```json
{
  "error": {
    "code": "INSUFFICIENT_FEE",
    "message": "fee 900000 is below required minimum 1250000",
    "details": {
      "required_min_fee": "1250000",
      "declared_fee": "900000"
    }
  }
}
```

### Pagination

All list endpoints accept `?limit=N&offset=M` query parameters.

- `limit`: maximum results per response; default `50`; maximum `100`
- `offset`: number of results to skip; default `0`
- Responses include a `pagination` object in `meta`:

```json
"meta": {
  "pagination": {
    "limit": 50,
    "offset": 0,
    "total": 312,
    "has_more": true
  }
}
```

---

## Status Enumerations

These status values appear in resource representations across multiple endpoints.

| Resource | Status values |
|----------|--------------|
| Transaction | `pending` \| `finalized` \| `failed` \| `not_found` |
| Attestation | `active` \| `revoked` |
| Algorithm | `active` \| `discouraged` \| `deprecated` \| `banned` |
| Validator | `candidate` \| `active` \| `jailed` \| `unbonding` \| `exited` |
| Governance proposal | `proposed` \| `active` \| `passed` \| `rejected` \| `executed` \| `expired` \| `cancelled` |

---

## Public Read API — full specification

> **Status note**: this section is the **specification** of the Public
> Read API. The subset wired to handlers in `pqcd` is listed above under
> "Implemented endpoints". Endpoints marked *specified, not implemented*
> have request/response shapes stable enough to write SDK code against,
> but a node built from this tree answers 404 for them.

### GET /v1/network

Returns network metadata and public health signal. Serves as the minimal status indicator without exposing operator API surfaces (ADR-014).

**Implemented**: yes, on the read-only router (`pqcd api-serve`) only; on the runtime router the equivalent is `GET /v1/status`.

**Response `data` fields**:

```json
{
  "network_id": "viper-testnet-2",
  "chain_id_hex": "76697065722d72657365617263682d31",
  "status": "live",
  "syncing": false,
  "latest_height": 12345,
  "latest_block_hash": "<hex>",
  "latest_finalized_height": 12344,
  "tx_version": 1,
  "epoch": 123,
  "epoch_length": 200,
  "active_algorithm_ids": [1, 2, 3, 16, 32]
}
```

`status` values: `live` | `syncing` | `halted` (if a `protocol_halt_signal` governance action is active)

---

### GET /v1/algorithms

**Implemented**: yes (`pqcd devnet-serve`, route in `crates/pqcd/src/devnet.rs`).

Returns all Algorithm Registry entries.

Optional filter: `?lifecycle_status=active` (accepts any lifecycle status value).

**Response `data`**: array of algorithm objects.

**Algorithm object**:

```json
{
  "alg_id": 2,
  "name": "ML-DSA-65",
  "spec_ref": "FIPS-204",
  "param_set": "ML-DSA-65",
  "sig_class": "V-B",
  "pk_size": 1952,
  "sig_size": 3309,
  "lifecycle_status": "active",
  "min_fee": "55000",
  "allowed_use_cases_mask": 15
}
```

`allowed_use_cases_mask` is a decimal representation of the 32-bit bitmask (bit 0 = vault, bit 1 = attestation, bit 2 = key management, bit 3 = governance).

---

### GET /v1/algorithms/{alg_id}


**Implemented**: yes (`pqcd devnet-serve`, route in `crates/pqcd/src/devnet.rs`).

Returns a single Algorithm Registry entry by `alg_id` (decimal integer).

**404** if `alg_id` is not in the registry.

---

### GET /v1/accounts/{address}

Returns account state including KeySet summary.

`address` is a 64-character lowercase hex string (32 bytes).

**Response `data`**:

```json
{
  "address": "<hex>",
  "balance": "10000000000",
  "nonce": 42,
  "policy_version": 3,
  "policy_hash": "<hex-32>",
  "keys": [
    {
      "key_version": 1,
      "alg_id": 2,
      "alg_name": "ML-DSA-65",
      "pk_hex": "<hex>",
      "status": "active",
      "valid_from_height": 100,
      "allowed_tx_types_mask": 15
    },
    {
      "key_version": 2,
      "alg_id": 32,
      "alg_name": "SLH-DSA-SHA2-128s",
      "pk_hex": "<hex>",
      "status": "active",
      "valid_from_height": 5000,
      "allowed_tx_types_mask": 4
    }
  ]
}
```

`balance` is returned as a decimal string to preserve u128 precision across JSON parsers.

Revoked keys are included in the response with `"status": "revoked"` for audit purposes; clients SHOULD filter by status if they only need active keys.

---

### GET /v1/accounts/{address}/attestations

**Implemented**: yes, gated by `api.expose_token_state` (off in every `configs/roles/*.json`).

Returns attestations created by this address (attester-indexed lookup).

Optional filters: `?attestation_type=2&status=active`.

**Response `data`**: array of attestation summary objects (see `/v1/attestations/{id}` for full shape).

---

### GET /v1/blocks/latest

**Implemented**: yes, on the read-only router (`pqcd api-serve`) only; on the runtime router use `GET /v1/status` for the tip and `GET /v1/blocks/{height}`.

Returns the latest finalized block header.

---

### GET /v1/blocks/{height}

Returns a finalized block by height.

**Response `data`**:

```json
{
  "height": 12345,
  "hash": "<hex>",
  "prev_hash": "<hex>",
  "proposer": "<address-hex>",
  "finalized_at": "2026-04-09T14:23:01Z",
  "tx_count": 12,
  "tx_hashes": ["<hex>", "..."],
  "commit_validator_count": 17,
  "commit_size_bytes": 56253
}
```

`commit_size_bytes` and `commit_validator_count` are exposed to help monitor PQ commit overhead (see SPEC-VAL-001 §9.4 and TESTING.md benchmark reference).

**404** if height is beyond the current finalized height (pending blocks are not exposed via read API).

---

### GET /v1/txs/{hash}

Returns transaction status and result.

`hash` is a 64-character lowercase hex string.

**Response `data`**:

```json
{
  "tx_hash": "<hex>",
  "status": "finalized",
  "finalized_at_height": 12345,
  "sender": "<address-hex>",
  "msg_type": 256,
  "msg_type_name": "attestation_create",
  "nonce": 42,
  "fee_charged": "1250000",
  "gas_used": 180000,
  "gas_limit": 200000,
  "sig_alg_id": 2,
  "sig_alg_name": "ML-DSA-65",
  "tx_bytes_len": 3812,
  "result": {
    "ok": true,
    "object_id": "<hex>"
  }
}
```

`object_id` in `result` is the primary identifier of the object created or modified by the transaction (e.g. `attestation_id` for `attestation_create`, `anchor_id` for `proof_anchor`). It is absent for operations that do not create a new identifiable object (e.g. `token_transfer`, `vault_policy_update`).

**Status semantics**:
- `pending`: in mempool, not yet finalized
- `finalized`: included in a finalized block; state changes applied
- `failed`: included in a finalized block but execution failed (e.g. ran out of gas); fee still charged
- `not_found`: no record in mempool or finalized state

---

### GET /v1/txs

**Implemented**: no — specified, not implemented (`KNOWN-ISSUES.md` D-07).

Returns a list of transactions, filterable by sender or block height.

Optional filters: `?sender=<address>&height=<height>&status=finalized`.

Ordered by finalization height descending (most recent first).

---

### GET /v1/validators

Returns the current validator set summary.

Optional filter: `?status=active` (accepts any validator status value).

**Response `data`**: array of validator summary objects.

**Validator summary object**:

```json
{
  "operator_address": "<address-hex>",
  "status": "active",
  "self_bond": "5000000000",
  "consensus_alg_id": 2,
  "consensus_alg_name": "ML-DSA-65"
}
```

Consensus public keys are NOT exposed via the public read API. Only the algorithm is shown.

---

### GET /v1/validators/{address}


**Implemented**: yes (`pqcd devnet-serve`, route in `crates/pqcd/src/devnet.rs`).

Returns detail for a single validator by operator address.

**Response `data`** adds:

```json
{
  "operator_address": "<address-hex>",
  "status": "active",
  "self_bond": "5000000000",
  "consensus_alg_id": 2,
  "consensus_alg_name": "ML-DSA-65",
  "joined_at_height": 1,
  "missed_blocks_in_window": 2,
  "liveness_window": 100,
  "jailed_at_height": null,
  "unbonding_start_height": null
}
```

---

### GET /v1/attestations/{id}

Returns a finalized attestation record.

`id` is the `tx_hash` of the `attestation_create` transaction (64-character hex).

**Response `data`**:

```json
{
  "attestation_id": "<hex>",
  "attester": "<address-hex>",
  "status": "active",
  "attestation_type": 2,
  "attestation_type_name": "document_notarization",
  "subject": "<hex-32>",
  "content_hash": "<hex-32>",
  "schema_id": "<hex-32>",
  "metadata_hash": "<hex-32>",
  "anchor_height": 10200,
  "expires_at_height": null,
  "revocation": null
}
```

If `status = "revoked"`:

```json
"revocation": {
  "revoked_at_height": 11500,
  "revoker": "<address-hex>",
  "revocation_reason_hash": "<hex-32>"
}
```

**404** if attestation not found.

---

### GET /v1/attestations

**Implemented**: no — specified, not implemented (`KNOWN-ISSUES.md` D-07).

Returns a list of attestation records.

Optional filters: `?subject=<hex>&attestation_type=2&attester=<address>&status=active`.

Ordered by `anchor_height` descending.

---

### GET /v1/anchors/{anchor_id}

**Implemented**: no — specified, not implemented (`KNOWN-ISSUES.md` D-07).

Returns a proof anchor record.

`anchor_id` is the `tx_hash` of the `proof_anchor` transaction.

**Response `data`**:

```json
{
  "anchor_id": "<hex>",
  "claimer": "<address-hex>",
  "claim_type": 1,
  "claim_type_name": "ownership",
  "asset_id_hash": "<hex-32>",
  "proof_hash": "<hex-32>",
  "schema_id": "<hex-32>",
  "anchor_height": 10350
}
```

---

### GET /v1/governance/proposals

**Implemented**: yes (`pqcd devnet-serve`, route in `crates/pqcd/src/devnet.rs`).

Returns governance proposals.

Optional filters: `?status=active&proposal_type=1`.

**Response `data`**: array of proposal summary objects.

**Proposal summary object**:

```json
{
  "proposal_id": "<hex>",
  "proposal_type": 1,
  "proposal_type_name": "registry_update",
  "submitter": "<address-hex>",
  "status": "active",
  "voting_start_height": 12000,
  "voting_end_height": 12400,
  "yes_weight": "15000000000",
  "no_weight": "2000000000",
  "abstain_weight": "500000000",
  "total_eligible_weight": "25000000000",
  "rationale_hash": "<hex-32>"
}
```

---

### GET /v1/governance/proposals/{proposal_id}


**Implemented**: yes (`pqcd devnet-serve`, route in `crates/pqcd/src/devnet.rs`).

Returns full detail for a governance proposal including payload summary.

**Response `data`** adds to the summary:

```json
{
  "payload_hash": "<hex-32>",
  "execution_activation_height": 12600,
  "execution_window_end_height": 13200,
  "executed_at_height": null,
  "notice_period_epochs": 2
}
```

---

### GET /v1/governance/proposals/{proposal_id}/votes


**Implemented**: yes (`pqcd devnet-serve`, route in `crates/pqcd/src/devnet.rs`).

Returns all votes cast on a proposal.

**Response `data`**: array of vote objects.

```json
{
  "voter": "<address-hex>",
  "vote": "yes",
  "weight": "5000000000",
  "cast_at_height": 12150
}
```

`vote` values: `yes` | `no` | `abstain`

---

### GET /v1/governance/receipts/{proposal_id}

**Implemented**: yes, on the read-only router (`pqcd api-serve`, `crates/pqcd/src/api.rs`) only.

Returns the finalized execution receipt for the currently implemented governance slice.

```json
{
  "proposal_id": "64-hex-chars",
  "proposal_type": 1,
  "proposal_type_name": "registry_update",
  "proposer": "64-hex-chars",
  "target_alg_id": 2,
  "lifecycle_before": "active",
  "lifecycle_after": "discouraged",
  "min_fee_before": 0,
  "min_fee_after": 500,
  "rationale_hash": "64-hex-chars",
  "executed_at_height": 1
}
```

Returns `400` for malformed proposal id, `404` if not found.

---

### GET /v1/governance/parameters

**Implemented**: no — specified, not implemented (`KNOWN-ISSUES.md` D-07).

Returns the current values of all governed protocol parameters.

**Response `data`**: flat map of parameter names to current values.

```json
{
  "base_fee": "500000",
  "byte_fee": "100",
  "exec_fee_per_gas": "10",
  "benchmark_class_fee_VA": "40000",
  "benchmark_class_fee_VB": "55000",
  "benchmark_class_fee_VC": "3200000",
  "max_validator_set_size": 24,
  "epoch_length": 200,
  "liveness_window": 100,
  "max_missed_blocks": 10,
  "last_changed_by": {
    "base_fee": "<proposal_id-hex>"
  }
}
```

`last_changed_by` maps each parameter to the `proposal_id` of the governance proposal that last changed it, for auditability.

---

## Transaction Submission API

### POST /v1/txs

**Implemented**: yes, only when `api.public_tx_submission` is on. The reference configs enable it for `full`, `rpc`, `sentry` and `archive` nodes and disable it for `validator` and `bootnode`; submit through an rpc node, never through a validator.

Broadcasts a signed transaction envelope.

The signed canonical CBOR bytes are the authoritative form. The JSON wrapper is transport only.

**Request body**:

```json
{
  "encoding": "cbor-base64",
  "tx_bytes": "<base64url-encoded canonical CBOR transaction envelope>"
}
```

`encoding` MUST be `"cbor-base64"`. Other encodings are not accepted in Phase 1.

**Success response** (transaction admitted to mempool):

```json
{
  "data": {
    "tx_hash": "<hex>",
    "status": "pending",
    "min_fee_used": "1250000"
  }
}
```

**Error response** (transaction rejected):

```json
{
  "error": {
    "code": "INSUFFICIENT_FEE",
    "message": "fee 900000 is below required minimum 1250000",
    "details": {
      "required_min_fee": "1250000",
      "declared_fee": "900000",
      "breakdown": {
        "base_fee": "500000",
        "byte_fee": "381200",
        "sigverify_fee": "368800",
        "exec_fee": "0"
      }
    }
  }
}
```

For `INSUFFICIENT_FEE`, the response MUST include `required_min_fee` and SHOULD include the fee breakdown so clients can construct a corrected transaction without guessing.

**Canonical bytes are authoritative**: the `tx_hash` returned is `SHAKE-256(tx_bytes_decoded, 32)` as defined in SPEC-TX-001 §8. Clients MUST NOT rely on any other hash derivation.

---

## Transaction Validation Reference

Before a transaction is accepted into the mempool, nodes execute the full 15-step validation pipeline defined in SPEC-TX-001 §9. The API surfaces the result as a rejection code and message. The following table maps protocol rejection codes to API error codes:

| Protocol rejection code | API error code | HTTP status |
|------------------------|----------------|-------------|
| `ENCODING_ERROR` | `ENCODING_ERROR` | 400 |
| `ENCODING_NOT_CANONICAL` | `ENCODING_NOT_CANONICAL` | 400 |
| `MISSING_FIELD` / `UNKNOWN_FIELD` | `MALFORMED_ENVELOPE` | 400 |
| `UNSUPPORTED_VERSION` | `UNSUPPORTED_VERSION` | 400 |
| `CHAIN_ID_MISMATCH` | `CHAIN_ID_MISMATCH` | 400 |
| `UNSUPPORTED_MSG_TYPE` | `UNSUPPORTED_MSG_TYPE` | 400 |
| `INVALID_SENDER` | `INVALID_SENDER` | 400 |
| `PAYLOAD_INVALID` / `PAYLOAD_TOO_LARGE` | `INVALID_PAYLOAD` | 400 |
| `UNSUPPORTED_ALGORITHM` | `UNSUPPORTED_ALGORITHM` | 400 |
| `INVALID_SIGNATURE_SIZE` | `INVALID_SIGNATURE` | 400 |
| `KEY_NOT_FOUND` | `KEY_NOT_FOUND` | 400 |
| `KEY_ALG_MISMATCH` | `KEY_ALG_MISMATCH` | 400 |
| `KEY_NOT_YET_ACTIVE` | `KEY_NOT_YET_ACTIVE` | 400 |
| `KEY_REVOKED` | `KEY_REVOKED` | 400 |
| `KEY_PERMISSION_DENIED` | `KEY_PERMISSION_DENIED` | 403 |
| `INVALID_SIGNATURE` | `INVALID_SIGNATURE` | 400 |
| `NONCE_CONFLICT` | `NONCE_CONFLICT` | 409 |
| `INSUFFICIENT_FEE` | `INSUFFICIENT_FEE` | 400 |
| `RATE_LIMITED` | `RATE_LIMITED` | 429 |
| `RATE_LIMITED` | `SENDER_RATE_LIMITED` | 429 |
| `REPLACEMENT_UNDERPRICED` | `REPLACEMENT_UNDERPRICED` | 400 |
| — | `NOT_FOUND` | 404 |
| — | `INTERNAL_ERROR` | 500 |

All 400 errors are client errors that can be corrected and resubmitted. 409 (`NONCE_CONFLICT`) indicates a replay or ordering issue. `RATE_LIMITED` (429) means the per-sender admission budget is exhausted (SPEC-FEE-001 §10.1); `SENDER_RATE_LIMITED` (429) means the per-sender window quota returned by the API-layer check fired before the mempool pipeline (i.e., before signature verification). Both indicate the sender should back off until the window resets. The source IP rate limit also returns 429 with `RATE_LIMITED`.

---

## Canonical vs JSON Representation

The API exposes JSON representations of protocol objects. The following rules MUST be respected by both node implementations and API consumers:

| Object | Canonical form | API form |
|--------|---------------|---------|
| Transaction envelope | deterministic CBOR (SPEC-TX-001) | `tx_bytes` base64url in JSON wrapper |
| Transaction hash | `SHAKE-256(canonical_cbor_bytes, 32)` | lowercase hex string |
| Address | 32-byte binary | 64-character lowercase hex |
| Balance / fee / amount | u128 integer | decimal string (preserves precision) |
| Hash fields (content_hash, policy_hash, etc.) | 32-byte binary | 64-character lowercase hex |
| Block height | u64 integer | JSON number |
| Bitmasks (allowed_tx_types, allowed_use_cases) | u32 integer | decimal integer |

JSON numbers MUST NOT be used for u128 values (balance, fee, self-bond, voting weight) because standard JSON parsers do not preserve integers larger than 2^53. These fields are always returned as decimal strings.

---

## Deliberately Deferred

- GraphQL or advanced indexing APIs
- WebSocket subscriptions and event streams
- Operator API public exposure (internal only at first testnet — ADR-014)
- Bridge or interoperability APIs
- Smart-contract developer APIs
- Token delegation and governance delegation endpoints
- Batch transaction submission
- Historical state queries (queries against non-finalized or pruned state)

# Viper Notary — Product Specification

**Status**: Phase 7 — Product Layer (proposed)
**ADR reference**: none yet (pending Phase 7 ADR)
**Last updated**: 2026-04-12

---

## 1. Product Summary

Viper Notary is the first application layer product built on Viper PQ Chain. It is a **document notarization service** that anchors cryptographic proof of a document's existence and content on-chain, without transmitting or storing the document itself.

The core guarantee: *if a document's hash is on-chain at block height H, it existed before block H was finalized — and no one can alter that record.*

Notary is the Phase 7 wedge product designed to demonstrate the chain's core value proposition — long-lived, high-assurance proofs — to a non-technical audience.

---

## 2. Target Users

| Segment | Use case | Pain point today |
|---------|----------|------------------|
| **Legal professionals** | Timestamp contracts, wills, letters of intent | Notary seals are expensive ($15–250/document), physical, and easy to forge |
| **IP creators** | Prove creation date of designs, code, research | Copyright registrations take months; email timestamps are unreliable |
| **Compliance teams** | Anchor audit logs, policy snapshots, certifications | Audit trails stored in mutable databases; no external anchor |
| **Healthcare / pharma** | Anchor clinical trial data, consent forms | Regulatory demands for immutable records with timestamped proof |
| **Journalists / researchers** | Prove data collection dates for FOIA or litigation | Sources easily disputed without verifiable timestamps |

**Primary persona**: a legal or compliance professional who needs proof of document existence with no technical background. They upload a file; they get a receipt.

---

## 3. User Workflow

### 3.1 Notarize a document

```
User opens Viper Notary web app
    │
    ▼
Uploads document (PDF, DOCX, image, ZIP, any format)
    │
    ├─► Client-side hash: SHA-3-256(file bytes) — no upload to server
    │
    ▼
User confirms: "Notarize this document"
    │
    ▼
Viper Notary service creates a signed attestation_create transaction:
    sender  = Notary service account
    subject = keccak-like address derived from document hash
    schema_id = VIPER-NOTARY-V1 (registered schema)
    payload_hex = hex(SHA-3-256(file)) || hex(SHA-3-256(metadata_json))
    │
    ▼
Transaction submitted to /v1/txs; included in next block
    │
    ▼
User receives a Notarization Receipt (JSON + PDF option):
    - document_hash (hex)
    - attestation_id (on-chain)
    - block_height
    - block_timestamp
    - chain_id: <configured `NOTARY_CHAIN_ID`, e.g. `viper-pq-1` on the live deploy>
    - verify_url: notary.viper-chain.io/verify?id=<attestation_id>
```

### 3.2 Verify a notarization

```
Verifier opens verify URL or manually inputs attestation_id
    │
    ▼
Optionally uploads the original document
    │
    ├─► Client-side: recompute SHA-3-256(file)
    │
    ▼
Fetch attestation from /v1/attestations/:id
    │
    ▼
Compare document_hash in payload_hex with computed hash
    │
    ├─ Match: "Document verified — notarized at block #H, timestamp T"
    └─ Mismatch: "Document does not match notarization record"
```

### 3.3 Revocation

If a notarization needs to be retracted (e.g., document replaced by corrected version), the issuer submits an `attestation_revoke` transaction. The revoked record remains on-chain with its `revoked_at_height` set — the history is immutable; only the active status changes.

---

## 4. Verification Model

### 4.1 What the chain proves

- The document (identified by its SHA-3-256 hash) **existed** before block H was finalized.
- The notarization was submitted by the Viper Notary service account (or a user's own vault if self-notarizing).
- The record is **tamper-evident**: altering it would require breaking SHA-3-256 and the ML-DSA-65 signature on the block.

### 4.2 What the chain does not prove

- The **identity** of the document's author (unless the author self-notarizes from their own vault with a verified identity).
- The **legal admissibility** in any specific jurisdiction — this depends on local law and whether blockchain timestamps are recognized.
- The **meaning** or **correctness** of the document's content.

### 4.3 Schema registry

The `VIPER-NOTARY-V1` schema must be registered on-chain before notarizations can begin. Schema fields:

```json
{
  "schema_id": "viper-notary-v1",
  "version": 1,
  "fields": {
    "document_hash": "hex(SHA-3-256, 32 bytes)",
    "metadata_hash": "hex(SHA-3-256, 32 bytes)",
    "mime_type": "MIME type string (informational)",
    "filename": "original filename (informational, not verified)"
  }
}
```

Schema registration is a governance operation (Phase 6 definition of schema registry is deferred; Phase 7 uses a static schema ID agreed in genesis).

---

## 5. Revenue Model

| Tier | Target | Pricing (USD equiv.) | Notes |
|------|--------|---------------------|-------|
| **Free** | Individuals, open source | 0 | Up to 3 notarizations/month; paid in VPR gas only |
| **Professional** | Law firms, freelancers | $9/month | 100 notarizations/month; PDF receipts; API access |
| **Enterprise** | Compliance teams, pharma | $299/month | Unlimited notarizations; bulk upload API; webhook on block inclusion; SLA |
| **Self-service API** | Developers | Pay-per-use | $0.05 per notarization; direct API key; no monthly commitment |

VPR token flow:
- All notarizations pay on-chain gas in VPR regardless of tier.
- Viper Notary service pre-funds its service account with VPR; fiat revenue from subscriptions is used to purchase VPR for gas.
- Free tier users are subsidized by the service account; their on-chain fees are paid by Notary.

This creates sustained demand for VPR without speculative framing — every notarization burns a small amount of VPR as gas.

---

## 6. Tech Stack

### 6.1 Frontend

- **Framework**: React 18 with TypeScript
- **Styling**: Tailwind CSS (dark industrial palette matching Viper Explorer)
- **Hashing**: WebCrypto API `subtle.digest("SHA-256", buffer)` — client-side, no file upload
  - Note: SHA-3-256 is not in WebCrypto; use a small pure-JS SHA-3 library (e.g. `sha3` npm package, 6 KB) or fallback to SHA-256 with explicit documentation that the scheme is SHA-256 at Phase 7 with SHA-3-256 upgrade in Phase 8.
- **Deployment**: Static site (Vercel / Cloudflare Pages)

### 6.2 Backend service

- **Language**: Rust (same stack as pqcd)
- **Role**: Holds the Notary service account key; signs and submits `attestation_create` txs; stores receipt metadata.
- **API**:
  - `POST /api/notarize` — accepts `{ document_hash: hex, metadata: {...} }`, returns `{ attestation_id, tx_hash, receipt_url }`
  - `GET /api/verify/:attestation_id` — fetches from chain and returns structured verification result
  - `POST /api/bulk` — Enterprise; accepts array of document hashes; batches into one or more txs
- **Key storage**: Notary service account key stored in HSM or secrets manager (same recommendations as validator-onboarding.md §3). Key is an ML-DSA-65 keypair.

### 6.3 Chain integration

Uses `@viper-pqchain/sdk` (TASK-075) for all chain reads. Transaction signing uses the Rust notary backend (signing limitation documented in SDK applies).

### 6.4 Receipt format

```json
{
  "viper_notary_receipt": "1.0",
  "attestation_id": "<hex>",
  "document_hash": "<sha256-hex>",
  "hash_algorithm": "SHA-256",
  "notarized_at": {
    "block_height": 42,
    "block_hash": "<hex>",
    "block_timestamp_utc": "2026-04-12T10:00:00Z"
  },
  "chain_id": "viper-pq-1",
  "issuer": "<notary-service-address-hex>",
  "verify_url": "https://notary.viper-chain.io/verify?id=<attestation_id>"
}
```

Receipts are signed by the Notary service using a separate signing key (Ed25519 off-chain, for receipt integrity only — not a chain operation).

---

## 7. Competitive Advantage

| Competitor | Model | Viper Notary advantage |
|-----------|-------|----------------------|
| **DocuSign Notary** | Centralized, US-only legal notary, $25/doc | Fully decentralized; no geography restriction; 100× cheaper at scale |
| **Bernstein** | Patent timestamping on Bitcoin | ML-DSA post-quantum signatures on every block; SLH-DSA recovery path |
| **OriginStamp** | SHA-256 anchoring on Bitcoin/Ethereum | Real-time inclusion (next block, ~seconds); no reliance on PoW chains |
| **Ethereum timestamps** | Smart contract + PoW/PoS | No EVM complexity; purpose-built schema; explicit key rotation policy |
| **OpenTimestamps** | Bitcoin OP_RETURN anchoring | Faster confirmation; richer metadata schema; verifiable key lifecycle |

Core differentiation: **post-quantum-native proof anchoring with explicit key lifecycle**. If quantum computers break ECDSA or RSA, every existing notarization on legacy chains becomes forgeable. Viper Notary receipts are anchored to ML-DSA-65 block signatures — resistant to quantum attack at genesis.

---

## 8. Phase 7 Scope

### In scope (Phase 7)

- [ ] Notary frontend web app (React + TypeScript)
- [ ] Notary backend service (Rust): sign + submit `attestation_create`; receipt generation
- [ ] `VIPER-NOTARY-V1` schema registration (genesis or first governance proposal)
- [ ] Verify endpoint (`/verify/:id`) — chain lookup + hash comparison
- [ ] Free and Professional tiers (manual payment processing)
- [ ] PDF receipt generation (Rust `printpdf` or similar)
- [ ] SDK integration (`@viper-pqchain/sdk`)

### Deferred (Phase 8+)

- Enterprise bulk upload API
- Webhooks on block inclusion
- SHA-3-256 hash upgrade (pending WebCrypto support or Phase 8 client library)
- Self-notarize flow (user provides their own ML-DSA key via pqcd CLI — Phase 8 when signing is in SDK)
- Native mobile apps
- Jurisdiction-specific legal language on receipts (legal review required)
- Multi-language support
- Schema registry governance UI

### Phase 7 exit criteria

1. A document can be notarized end-to-end via the web app against a live testnet node.
2. A verifier can independently verify the notarization using only the attestation ID and the original file.
3. The Notary service account key is stored in a secrets manager (not in plain config).
4. At least one external user (not team member) completes the full notarize + verify flow.

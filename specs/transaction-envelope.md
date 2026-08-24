# Transaction Envelope Specification

**Spec ID**: SPEC-TX-001  
**Version**: 0.3  
**Status**: Accepted  
**History**: v0.3 revised for the `viper-pq-1` launch (2026-04-25); that chain is retired, the envelope format is unchanged on `viper-testnet-1`.  
**Date**: 2026-04-25  
**Depends on**: ADR-004 (deterministic CBOR), ADR-005 (fee model), ADR-006 (algorithm baseline), ADR-044 (crypto agility), ADR-053 (`viper-pq-1` genesis architecture)

> **Revision history**
>
> | Version | Date | Change |
> |---------|------|--------|
> | 0.1 | 2025-Q4 | Initial envelope spec (pre-ADR-044). |
> | 0.2 | 2026-04-21 | **Revised by ADR-044 (crypto agility)** — introduces signature and public-key TLV envelopes with explicit `algo_id`, on-chain Algorithm Registry verifier dispatch, and the `sig_alg_id`-in-envelope alignment. |
> | 0.3 | 2026-04-25 | **Revised for `viper-pq-1` launch (ADR-053).** Adds §6.1 ForkDigest signing-domain prefix (ADR-053 §T1.2, TASK-191). §7 signed-preimage construction now wraps the body in BIP340 double-tagged hashing under `"PQC-TX-V1"` (ADR-053 §T2.4, TASK-202). §5.4 `sender` derivation references SPEC-ADDRESS-001 v0.3 (chain-id-bound, ADR-053 §T1.3). §12.1 retitled "viper-pq-1 launch compatibility" — the breaking change is now historical. |

---

## 1. Scope

This document specifies the PQ Chain transaction envelope: the canonical wire format for all signed protocol transactions. It defines field semantics, encoding rules, the signed preimage construction, transaction hash derivation, and the validation pipeline that every node MUST execute before accepting a transaction into the mempool.

This specification does not define:

- the semantics of individual operation types (see SPEC-OPS, TASK-007)
- KeySet lifecycle rules (see SPEC-ACCOUNT, TASK-004)
- Algorithm Registry governance (see SPEC-ACCOUNT, TASK-004)
- validator economics or staking (see TASK-005)

---

## 2. Normative Language

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT, RECOMMENDED, MAY, and OPTIONAL in this document are to be interpreted as described in RFC 2119.

---

## 3. Normative References

| Reference | Document |
|-----------|----------|
| RFC 8949 | Concise Binary Object Representation (CBOR) |
| RFC 8949 §4.2 | Deterministic Encoding Requirements |
| FIPS 204 | ML-DSA — Module-Lattice-Based Digital Signature Standard |
| FIPS 205 | SLH-DSA — Stateless Hash-Based Digital Signature Standard |
| FIPS 206 (draft) | FN-DSA — FFT over NTRU-Lattice-Based Digital Signature Standard |
| NIST SP 800-185 | SHA-3 Derived Functions: cSHAKE, KMAC, TupleHash, ParallelHash |

---

## 4. Envelope Object Definition

A transaction envelope is a CBOR map. Integer map keys are used throughout; string keys are not permitted in canonical envelopes.

### 4.1 Field Table

| Key | Field | Type | Size | Required |
|-----|-------|------|------|----------|
| 1 | `tx_version` | uint | 1 B | REQUIRED |
| 2 | `chain_id` | bstr | 4–32 B | REQUIRED |
| 3 | `msg_type` | uint | 2 B (u16) | REQUIRED |
| 4 | `sender` | bstr | 32 B | REQUIRED |
| 5 | `nonce` | uint | 8 B (u64) | REQUIRED |
| 6 | `fee` | uint | 8 B (u64) | REQUIRED |
| 7 | `fee_tip` | uint | 8 B (u64) | OPTIONAL |
| 8 | `gas_limit` | uint | 8 B (u64) | REQUIRED |
| 9 | `payload` | bstr | variable | REQUIRED |
| 10 | `sig_alg_id` | uint | 2 B (u16) | REQUIRED |
| 11 | `sig_key_version` | uint | 4 B (u32) | REQUIRED |
| 12 | `signature` | bstr | variable | REQUIRED |

When `fee_tip` is omitted, it is treated as zero. It MUST NOT appear with a value of zero; an explicitly zero tip MUST be omitted.

> **ADR-044 note**: `sig_alg_id` (key 10) is an explicit CBOR field in the envelope map AND is redundantly encoded inside the `signature` and public-key TLV envelopes (see §5.10 and §5.12). The two representations MUST be consistent; a node MUST reject an envelope where the `algo_id` inside the TLV does not match the top-level `sig_alg_id`.

---

## 5. Field Semantics

### 5.1 `tx_version` (key 1)

The protocol version that governs how this envelope is parsed and validated.

- MUST be `1` for this specification
- Nodes MUST reject envelopes with an unknown `tx_version`
- Future versions increment this value; a new spec document governs each version

### 5.2 `chain_id` (key 2)

Identifies the network. Prevents cross-network replay.

- MUST be between 4 and 32 bytes inclusive
- Format: human-readable ASCII prefix (minimum 3 bytes) followed by a random or deterministic suffix; exact format is network-defined and MUST be documented in the network genesis parameters
- Nodes MUST reject transactions whose `chain_id` does not match the local network's configured chain identifier
- `chain_id` is part of the signed preimage

### 5.3 `msg_type` (key 3)

Routes the `payload` to the correct execution handler.

- MUST be a 16-bit unsigned integer
- Defined ranges (see also SPEC-OPS, TASK-007):

| Range | Use |
|-------|-----|
| `0x0000` | reserved |
| `0x0001–0x00FF` | vault account operations |
| `0x0100–0x01FF` | attestation and notarization operations |
| `0x0200–0x02FF` | key management operations |
| `0x0300–0x03FF` | governance operations |
| `0x8000–0xFFFF` | reserved for future use |

- Nodes MUST reject transactions with an unrecognized `msg_type`
- The set of recognized `msg_type` values is a protocol parameter, not a node implementation detail

### 5.4 `sender` (key 4)

The account address of the transaction originator.

- MUST be exactly 32 bytes
- Derived from the host chain's `chain_id`, the initial public key bytes, and the `sig_alg_id` of the account's first key at account creation time. The canonical derivation is specified in **SPEC-ADDRESS-001 §2.2** (v0.3, ADR-053 §T1.3 + §T2.4):

  ```
  sender = tagged_hash("VIPER-ADDR-V1", chain_id || sig_alg_id_be16 || pk_bytes)
  ```

  Reference implementation: `pqc_crypto::derive_address` in `crates/pqc-crypto/src/address.rs:33`.
- The address is stable across key rotations; only the KeySet changes, not the address.
- The address is **chain-bound**: a public key registered on `viper-pq-1` does NOT correspond to the same `sender` on any other chain. Cross-chain replay defense at the address layer (ADR-053 §T1.3); composes with §6.1 ForkDigest signing-domain defense at the signing layer.

### 5.5 `nonce` (key 5)

Monotonically increasing counter for replay protection.

- MUST be a 64-bit unsigned integer
- For a given `sender`, each transaction MUST use `nonce = account_nonce + 1` where `account_nonce` is the current on-chain nonce for that account
- Nodes MUST reject transactions where `nonce ≤ account_nonce` (replay) or `nonce > account_nonce + 1` (gap, unless a future spec introduces batch nonces)

### 5.6 `fee` (key 6)

The maximum fee the sender is willing to pay, expressed in the network's base token unit.

- MUST be a 64-bit unsigned integer
- MUST satisfy: `fee ≥ base_fee + byte_fee × len(canonical_tx_bytes) + sigverify_fee[sig_alg_id] + exec_fee × gas_limit`
- Nodes MUST reject transactions that do not satisfy the fee sufficiency condition at mempool admission time
- Actual fee charged MAY be less than `fee` if execution costs less than `gas_limit`; the remainder is returned to the sender

### 5.7 `fee_tip` (key 7)

An optional priority tip paid to the block proposer, in addition to `fee`.

- MUST be omitted or a positive 64-bit unsigned integer (zero-value MUST be omitted)
- Not included in the minimum fee sufficiency check; purely a priority signal
- The total amount deducted from the sender is `fee + fee_tip`

### 5.8 `gas_limit` (key 8)

The maximum execution budget the sender authorizes for this transaction.

- MUST be a 64-bit unsigned integer
- Nodes MUST abort execution and discard state changes if execution exceeds `gas_limit`
- A transaction that hits its `gas_limit` is still charged the full `fee`; it is not refunded

### 5.9 `payload` (key 9)

The operation-specific data, encoded as deterministic CBOR.

- MUST be a byte string containing a valid deterministic CBOR value
- The internal structure is defined per `msg_type` in SPEC-OPS
- The `payload` field is opaque to the envelope layer; the envelope layer does not parse or validate its contents beyond confirming it is valid CBOR
- Maximum payload size: 1 MB (1,048,576 bytes). Nodes MUST reject envelopes where `len(payload) > 1,048,576`

### 5.10 `sig_alg_id` (key 10)

Identifies the signature algorithm used to produce `signature`.

- MUST be a 16-bit unsigned integer
- MUST reference an algorithm with `lifecycle_status = active` in the Algorithm Registry at the time of mempool admission
- Known values (initial set):

| Value | Algorithm | Notes |
|-------|-----------|-------|
| `0x0001` | ML-DSA-44 | FIPS 204, NIST L2 |
| `0x0002` | ML-DSA-65 | FIPS 204, NIST L3 — default |
| `0x0003` | ML-DSA-87 | FIPS 204, NIST L5 |
| `0x0010` | FN-DSA-padded-512 | future FIPS 206, NIST L1 — monitored |
| `0x0011` | FN-DSA-padded-1024 | future FIPS 206, NIST L5 — monitored |
| `0x0020` | SLH-DSA-SHA2-128s | FIPS 205, NIST L1 — restricted use |
| `0x0021` | SLH-DSA-SHA2-192s | FIPS 205, NIST L3 — restricted use |
| `0x0000`, `0x8000–0xFFFF` | reserved | MUST NOT be used |

- Nodes MUST reject transactions using a `sig_alg_id` that is not recognized or whose `lifecycle_status` is `deprecated` or `banned`
- Nodes SHOULD warn on transactions using a `sig_alg_id` with `lifecycle_status = discouraged` and MAY require a higher minimum fee (per Algorithm Registry `min_fee`)

### 5.11 `sig_key_version` (key 11)

Selects which key in the sender's KeySet was used to sign this transaction.

- MUST be a 32-bit unsigned integer
- The verifier resolves the public key via `(sender_address, sig_key_version)` against the current on-chain KeySet
- The resolved key entry MUST have `status = active` and `allowed_tx_types` that includes the requested `msg_type`
- Nodes MUST reject transactions where the resolved key is missing, revoked, or does not have permission for the requested `msg_type`

### 5.12 `signature` (key 12)

The cryptographic signature over the signed preimage, wrapped in a TLV envelope (ADR-044).

**Signature envelope wire format:**

```
signature_envelope := <version:u8><algo_id:varint><sig_len:varint><signature_bytes>[<aux_len:varint><aux>]
```

**Public key envelope wire format** (used in the KeySet on-chain; referenced here for consistency):

```
public_key_envelope := <version:u8><algo_id:varint><pk_len:varint><pk_bytes>
```

Field semantics:
- `version` — envelope format version; MUST be `0x01` for this specification
- `algo_id` — unsigned varint; MUST match the `sig_alg_id` at envelope key 10 (see ADR-044 note in §4.1)
- `sig_len` / `pk_len` — unsigned varint length prefix for the following byte payload
- `signature_bytes` — the raw signature bytes for the algorithm identified by `algo_id`; expected sizes: ML-DSA-44: 2,420 B; ML-DSA-65: 3,309 B; ML-DSA-87: 4,627 B; FN-DSA-padded-512: 666 B; FN-DSA-padded-1024: 1,280 B; SLH-DSA-SHA2-128s: 7,856 B
- `aux` — optional algorithm-specific context (e.g. SLH-DSA context string, FN-DSA pre-hash flag, nested composite envelopes for HYBRID_PARALLEL); omitted when not needed

Nodes MUST reject envelopes where:
- `version` ≠ `0x01`
- `algo_id` inside the TLV does not match top-level `sig_alg_id`
- `len(signature_bytes)` does not match `expected_size(algo_id)`

The `signature` field (and its TLV wrapper) is NOT included in the signed preimage.

---

## 5a. Algorithm Registry (ADR-044) {#algorithm-registry}

The Algorithm Registry is an on-chain governance-controlled mapping that ties each `algo_id` to a deployed verifier contract. It is the authoritative source for algorithm lifecycle status and dispatch.

### 5a.1 `algo_id` Numbering

`algo_id` values are assigned from two coordinated sources:

1. **Multicodec upstream** (`github.com/multiformats/multicodec`): codepoints are registered in the multicodec table for off-chain tooling interoperability. New entries for ML-DSA-44/65/87, SLH-DSA-SHAKE-128s/192s/256s, and FN-DSA-512/1024 MUST be registered before mainnet.

2. **On-chain registry**: the canonical live mapping used by the protocol:

   ```
   algo_id → {
     verifier_address: address,   // deployed verifier contract
     lifecycle_status: enum { active | discouraged | deprecated | banned },
     deprecated: bool,            // true blocks new usage; historical sigs remain verifiable
     min_fee: u64,                // minimum fee override for discouraged algorithms
   }
   ```

The `deprecated: bool` flag is a one-way ratchet: setting it `true` prevents new signatures with that `algo_id` from being accepted by the mempool, but existing signed transactions and historical blocks remain fully verifiable. Historical verifier contracts are NEVER removed.

### 5a.2 Governance

Additions and status changes to the Algorithm Registry require a governance proposal with:
- a minimum quorum as defined in SPEC-GOV
- a timelock of ≥ 30 days for status changes to `deprecated` or `banned`
- a supermajority of 66% for emergency `banned` escalation

### 5a.3 Verifier Dispatch

At signature verification time (validation pipeline step 12), the node:
1. Reads `sig_alg_id` from the envelope
2. Looks up `verifier_address` in the on-chain Algorithm Registry
3. Calls the verifier contract with `(preimage, signature_bytes, public_key_bytes)`
4. Accepts the transaction only if the verifier returns success

This indirection means new PQ algorithms can be activated on-chain without a protocol hard fork.

---

## 6. ForkDigest Signing-Domain Prefix (ADR-053 §T1.2, TASK-191)

### 6.1 Construction

Every signing preimage in the protocol — transactions (this spec §7), prevotes / precommits / proposals (SPEC-CONSENSUS-001 §8.4 + §11), archival anchor signatures (SPEC-ARCHIVAL-001), and any future signed protocol object — MUST be prefixed by a 4-byte `ForkDigest` derived from the host chain's genesis. The digest is computed once at genesis and used unchanged for the lifetime of a fork:

```
ForkDigest = SHAKE-256(
    "VIPER-FORK-V1" || u32_be(fork_version) || genesis_validators_root,
    output_len = 4,
)
```

where:

- `"VIPER-FORK-V1"` is the fixed domain tag for the digest construction itself (independent of the per-object signing domain like `"PQC-TX-V1"` or `"VIPER-VOTE-V1"`).
- `fork_version: u32` is `1` (`VIPER_FORK_VERSION_V1`) at `viper-pq-1` genesis. Every hard fork bumps this value and re-derives the digest; every signature made after the fork therefore lives in a disjoint preimage space from every signature made before.
- `genesis_validators_root: [u8; 32]` is the binary-Merkle root over the canonical sorted genesis validator set, sealed at the moment the genesis block is produced.

The reference implementation is `pqc_types::ForkDigest::compute` at `crates/pqc-types/src/fork.rs:41`. The 4-byte digest is exposed via `ForkDigest::as_bytes()` and is consumed verbatim as a raw prefix by every preimage builder.

### 6.2 Application

Every signed object's preimage MUST start with the 4-byte `ForkDigest` of the host chain. For transactions, this is enforced by `pqc_tx::preimage::build_preimage` in `crates/pqc-tx/src/preimage.rs:33`, which prepends `fork_digest.as_bytes()` to the canonical CBOR body before applying the BIP340 double-tagged outer hash under `"PQC-TX-V1"` (see §7).

### 6.3 Rationale (cross-chain replay defense at the signing layer)

Without a genesis-scoped prefix, a validator's signed vote (or a user's signed transaction) on `viper-pq-1` is byte-identical to a signed vote on any parallel or future chain that shares the legacy domain tag (e.g. `"PQC-TX-V1"`, `"VIPER-VOTE-V1"`). An attacker could capture a single signed transaction on one chain and resubmit it verbatim on another. The 4-byte `ForkDigest` prefix closes that hole at signing time: the signed bytes carry a non-removable commitment to the host chain's `(fork_version, genesis_validators_root)` pair, and any verifier on a different chain will reject the signature.

ForkDigest binding at the signing layer is **complementary** to chain-id binding at the address layer (SPEC-ADDRESS-001 §2.3, ADR-053 §T1.3). The two layers compose:

| Defense | Layer | What it prevents |
|---------|-------|------------------|
| Chain-id-bound address | Identity | The `sender` field referencing the same account on two chains. |
| ForkDigest in preimage | Signature | The signed bytes verifying as authentic on two chains. |

A cross-chain replay must defeat both layers simultaneously; defeating either alone is insufficient.

### 6.4 Pre-genesis placeholder (test/dev only)

Test harnesses and pre-genesis devnet code paths use `ForkDigest::viper_pq_1_placeholder()` (`crates/pqc-types/src/fork.rs:66`), which computes the digest from `(VIPER_FORK_VERSION_V1, [0u8; 32])`. This placeholder is NOT the production digest — each chain's real digest is sealed when its genesis block is produced and is pinned in the genesis JSON (`viper-testnet-1`: assigned at genesis). Production nodes MUST configure the real digest (via `CommitQuorumPolicy::with_fork_digest` and the equivalent tx-validation-context wiring). The placeholder is retained only so internal test fixtures sign and verify bytes with the same shape as production.

---

## 7. Deterministic CBOR Encoding Rules

All canonical transaction bytes MUST conform to the following rules, derived from RFC 8949 §4.2 (Core Deterministic Encoding Requirements):

1. **Map key order**: integer keys MUST appear in ascending numeric order
2. **Shortest integer encoding**: integers MUST use the shortest CBOR encoding (e.g. values 0–23 use a single byte, not a multi-byte encoding)
3. **No indefinite-length items**: all byte strings, text strings, arrays, and maps MUST use definite-length encoding
4. **No duplicate keys**: a map MUST NOT contain duplicate keys
5. **No floating point**: floating-point values are not used in any protocol-defined structure
6. **No CBOR tags**: no CBOR tags are used unless explicitly specified in a future extension

A node MUST reject any transaction envelope that fails these rules. Rejection MUST occur before any signature verification or state lookup.

---

## 8. Signed Preimage

The signed preimage is the byte string over which the sender's signature is computed. The construction layers the §6 ForkDigest signing-domain prefix, the canonical CBOR-encoded envelope body, and the BIP340 double-tagged outer hash under `"PQC-TX-V1"` (ADR-053 §T2.4).

### 8.1 Construction (ADR-053 §T1.2 + §T2.4)

```
body     = fork_digest[4] || canonical_cbor(preimage_map)
preimage = tagged_hash("PQC-TX-V1", body)
         = SHAKE-256(H("PQC-TX-V1") || H("PQC-TX-V1") || body, 32)
```

Where:

- `fork_digest[4]` is the 4-byte `ForkDigest` of the host chain (§6.1).
- `canonical_cbor(preimage_map)` is the deterministic CBOR encoding of the §8.2 map (per §7).
- `"PQC-TX-V1"` is the per-object signing-domain tag, distinct from the fork-digest tag `"VIPER-FORK-V1"` and from every other tagged-hash domain in the workspace.
- `tagged_hash(tag, body)` is the BIP340-style double-tagged hash defined in `pqc_crypto::tagged_hash` (`crates/pqc-crypto/src/hash.rs:111`), and consumed for transactions by `pqc_tx::preimage::build_preimage` (`crates/pqc-tx/src/preimage.rs:33`).

The 32-byte output of `tagged_hash` IS the signed message: the signer invokes `ml_dsa_sign` (or the equivalent algorithm-specific signing function) over those 32 bytes directly. The verifier reconstructs the 32 bytes the same way and feeds them to the verifier function.

### 8.2 Preimage Map

The preimage map MUST include exactly the following keys, in ascending key order:

```
{
  1: tx_version,
  2: chain_id,
  3: msg_type,
  4: sender,
  5: nonce,
  6: fee,
  7: fee_tip,   -- included as 0 if omitted in the envelope
  8: gas_limit,
  9: payload,
  10: sig_alg_id,
  11: sig_key_version
}
```

When `fee_tip` was omitted from the envelope, it MUST appear as integer `0` in the preimage map. This ensures the preimage is fully determined by the semantic intent of the transaction, not by encoding choices.

### 8.3 Signing

The sender signs `preimage` (the 32-byte tagged-hash digest from §8.1) using the algorithm identified by `sig_alg_id` and the private key corresponding to `sig_key_version` in their KeySet.

Verifiers MUST reconstruct `preimage` independently from the received envelope (re-deriving the §6 `ForkDigest` from the host chain's `(fork_version, genesis_validators_root)` configuration, re-encoding the §8.2 CBOR map, and re-applying the BIP340 double-tagged outer hash) and verify `signature` against `preimage` using the public key resolved from `(sender, sig_key_version)`.

---

## 9. Transaction Hash Derivation

The transaction hash (`tx_hash`) uniquely identifies a finalized transaction.

```
tx_hash = SHAKE-256(canonical_tx_bytes, 32)
```

Where:

- `canonical_tx_bytes` = the full deterministic CBOR encoding of the envelope, including the `signature` field (key 12)
- `SHAKE-256(input, 32)` = 32 bytes of SHAKE-256 output (256-bit)
- `tx_hash` is used as the transaction identifier in block references, API responses, and receipts

A node MUST NOT compute or expose a `tx_hash` for a transaction that has not passed full validation. The hash is only meaningful for transactions that have been accepted into the mempool or finalized in a block.

---

## 10. Validation Pipeline

Nodes MUST execute validation in the following order. A failure at any step MUST result in immediate rejection with the corresponding rejection code. Steps MUST NOT be reordered.

| Step | Check | Rejection code |
|------|-------|---------------|
| 1 | CBOR is well-formed | `ENCODING_ERROR` |
| 2 | Deterministic CBOR rules satisfied (key order, shortest form, no indefinite length) | `ENCODING_NOT_CANONICAL` |
| 3 | All required fields present; no unknown keys | `MISSING_FIELD` / `UNKNOWN_FIELD` |
| 4 | `tx_version` is recognized | `UNSUPPORTED_VERSION` |
| 5 | `chain_id` matches local network | `CHAIN_ID_MISMATCH` |
| 6 | `msg_type` is recognized | `UNSUPPORTED_MSG_TYPE` |
| 7 | `sender` is exactly 32 bytes | `INVALID_SENDER` |
| 8 | `payload` is valid CBOR and does not exceed 1 MB | `PAYLOAD_INVALID` / `PAYLOAD_TOO_LARGE` |
| 9 | `sig_alg_id` is in the Algorithm Registry with `lifecycle_status ∈ {active, discouraged}` | `UNSUPPORTED_ALGORITHM` |
| 10 | TLV envelope `version = 0x01` and `algo_id` inside TLV matches `sig_alg_id` | `INVALID_SIGNATURE_ENVELOPE` |
| 10b | `len(signature_bytes)` inside TLV matches `expected_size(sig_alg_id)` | `INVALID_SIGNATURE_SIZE` |
| 11 | `(sender, sig_key_version)` resolves to an active key with permission for `msg_type` | `KEY_NOT_FOUND` / `KEY_PERMISSION_DENIED` |
| 12 | Signature verifies against reconstructed preimage (host-chain `ForkDigest` re-derived per §6.1; BIP340 double-tagged outer hash applied per §8.1; on-chain verifier dispatch per §5a.3) | `INVALID_SIGNATURE` |
| 13 | `nonce = account_nonce + 1` | `NONCE_CONFLICT` |
| 14 | Fee sufficiency: `fee ≥ base_fee + byte_fee × tx_bytes + sigverify_fee[sig_alg_id] + exec_fee × gas_limit` | `INSUFFICIENT_FEE` |
| 15 | Per-sender verify budget not exceeded | `RATE_LIMITED` |

Steps 1–8 (structural checks) MUST be performed before any cryptographic or state operations. Steps 9–12 (cryptographic checks) MUST be performed before any state reads beyond key and account lookup. Steps 13–15 (state and economic checks) follow.

---

## 11. Mempool Admission Rules

In addition to the validation pipeline, nodes MAY apply the following mempool-level policies. These are not consensus rules but local anti-DoS measures:

- **Per-sender queue depth**: a node MAY reject transactions from a sender that already has `N` pending transactions in the mempool (recommended maximum: 16)
- **Verify budget**: a node MAY track cumulative `sigverify_fee` units consumed per sender in a rolling time window and reject transactions that exceed the budget
- **Discouraged algorithm surcharge**: if `sig_alg_id` has `lifecycle_status = discouraged`, the node MUST enforce `fee ≥ Algorithm_Registry[sig_alg_id].min_fee` in addition to the standard fee check
- **Replacement policy**: a transaction with the same `(sender, nonce)` MAY replace an existing mempool entry if its `fee` is at least 10% higher

---

## 12. Rejection Conditions

The following are non-exhaustive conditions that MUST result in rejection:

- `tx_version` is not `1`
- `chain_id` does not match the node's configured network
- CBOR map keys are not in ascending order
- Integer values are not in shortest encoding form
- Any required field is missing
- `sender` is not 32 bytes
- `payload` exceeds 1,048,576 bytes
- `sig_alg_id` is `0x0000`, in the `0x8000–0xFFFF` reserved range, or not in the Algorithm Registry
- `sig_alg_id` has `lifecycle_status = deprecated` or `banned`
- TLV envelope `version` ≠ `0x01`
- `algo_id` inside the signature TLV does not match top-level `sig_alg_id`
- `len(signature_bytes)` inside the TLV does not match `expected_size(sig_alg_id)`
- `sig_key_version` does not resolve to an active key for the sender
- The resolved key does not have `allowed_tx_types` permission for `msg_type`
- Signature verification fails
- `nonce ≤ account_nonce` or `nonce > account_nonce + 1`
- `fee` does not satisfy the fee sufficiency condition

---

## 13. Forward Compatibility and Versioning

- `tx_version` is the primary versioning mechanism. A node MUST reject envelopes with unknown versions rather than attempting to parse them
- New fields MUST NOT be added to an existing `tx_version`. A new field requires a new `tx_version`
- `msg_type` ranges are reserved to allow new operation types without version bumps
- `sig_alg_id` values are assigned by governance via the Algorithm Registry; new algorithms are activated without a `tx_version` change
- Nodes SHOULD log all rejected envelopes with their rejection code to support debugging and network health monitoring
- Hard forks bump the `fork_version` field used by the §6.1 ForkDigest construction. Every signature made after the fork lives in a disjoint preimage space from every signature made before; pre-fork transactions remain verifiable under their original `ForkDigest` for archival and proof-of-history purposes.

### 13.1 viper-pq-1 launch compatibility (historical)

> *This subsection records a one-time pre-launch breaking-change event. It is preserved for the audit trail. Under Policy P-COMPAT-001 (ADR-052) every subsequent breaking change must travel via a forward-compatible upgrade path; no further chain reset is permitted.*

The TLV envelope format introduced in v0.2 (ADR-044) changed the wire representation of `signature` (key 12) from a raw byte string to a versioned TLV-prefixed byte string. The v0.3 revision (ADR-053) layered the `ForkDigest` signing-domain prefix (§6.1, ADR-053 §T1.2) and the BIP340 double-tagged outer hash (§8.1, ADR-053 §T2.4) on top of the v0.2 format.

These were breaking changes that ran on the `viper-devnet-2` → `viper-pq-1` cutover. v0.1 envelopes are not accepted on `viper-pq-1`, and v0.3 envelopes are not accepted on the retired `viper-devnet-2` chain. The v0.3 envelope format has been canonical since the `viper-pq-1` genesis (chain_id_hex `0x76697065722d70712d31`; chain since retired) and is the format used by `viper-testnet-1`.

---

## 14. Security Considerations

### 14.1 Canonical Encoding Is a Security Requirement

Non-canonical CBOR must be rejected before signature verification. Accepting a non-canonical encoding and then normalizing it before hashing would allow two different byte sequences to refer to the same transaction, breaking hash-based deduplication and potentially enabling transaction malleability attacks.

### 14.2 Domain Separation

Three layers of domain separation operate on every signed transaction:

1. **`ForkDigest` prefix** (§6.1, ADR-053 §T1.2) binds the signature to a specific `(fork_version, genesis_validators_root)` pair. A signed transaction on `viper-pq-1` cannot be replayed verbatim on any parallel or future chain.
2. **`"PQC-TX-V1"` BIP340 outer tag** (§8.1, ADR-053 §T2.4) prevents signatures produced for this transaction format from being valid in any other tagged-hash context (votes, proposals, governance, archival, …). Every signed object type in the protocol uses a distinct tag.
3. **Chain-id-bound `sender` address** (§5.4, SPEC-ADDRESS-001 §2.3, ADR-053 §T1.3) ensures that the identity referenced by the `sender` field is itself chain-specific.

Together these prevent cross-chain replay at three independent points: signature, signing-domain, and identity.

### 14.3 Validation Order

Structural and encoding checks precede cryptographic checks for two reasons: (a) they are cheaper to compute, enabling early rejection of malformed spam, and (b) signature verification must operate on a well-defined byte sequence — validating encoding first guarantees this.

### 14.4 SLH-DSA Restricted Use

The `allowed_tx_types` mechanism in the KeySet exists specifically to prevent SLH-DSA keys from being used for high-frequency operations. SLH-DSA verification is approximately 60× slower than ML-DSA on reference hardware (~951 verify/s vs ~55,000 verify/s). A node that accepted SLH-DSA-signed transactions at high volume without rate limiting would face a significant CPU DoS vector. Protocol policy restricts SLH-DSA to rotation and recovery operations, where frequency is inherently low.

### 14.5 Fee Model as DoS Mitigation

The `sigverify_fee[sig_alg_id]` component of the fee formula ensures that the economic cost of submitting expensive-to-verify transactions is proportional to their actual CPU burden on validators. This is not optional; a fee model that prices only execution would make the verification path a free DoS channel.

---

## 15. Worked Example

### 15.1 Scenario

A sender submits an attestation anchoring operation on `viper-pq-1`, signed with ML-DSA-65.

### 15.2 Envelope Fields (before encoding)

```
tx_version:      1
chain_id:        0x76697065722d70712d31   (b"viper-pq-1", 10 bytes)
msg_type:        0x0100                  (attestation_anchor)
sender:          <32-byte address derived per SPEC-ADDRESS-001 §2.2>
nonce:           42
fee:             1500000                  (in base units)
fee_tip:         (omitted)
gas_limit:       200000
payload:         <CBOR encoding of attestation payload>
sig_alg_id:      0x0002                  (ML-DSA-65)
sig_key_version: 1
signature:       <3,309 bytes of ML-DSA-65 signature>
```

### 15.3 Preimage Construction

```
fork_digest    = ForkDigest::compute(1, genesis_validators_root)   # §6.1
cbor_body      = CBOR({
                   1: 1,
                   2: h'76697065722d70712d31',
                   3: 256,
                   4: h'<32-byte sender>',
                   5: 42,
                   6: 1500000,
                   7: 0,           # fee_tip omitted in envelope → 0 in preimage
                   8: 200000,
                   9: h'<payload bytes>',
                   10: 2,
                   11: 1,
                 })
body           = fork_digest[0..4] || cbor_body
preimage_hash  = tagged_hash("PQC-TX-V1", body)   # 32 bytes
                # = SHAKE-256(H("PQC-TX-V1") || H("PQC-TX-V1") || body, 32)
```

The 32-byte `preimage_hash` is the message fed to the ML-DSA-65 signer.

### 15.4 Transaction Hash

```
tx_hash = SHAKE-256(CBOR({1: 1, 2: ..., 12: h'<3309-byte sig>'}), 32)
```

### 15.5 Validation Steps Applied

1–2. CBOR parsed; keys in order 1,2,3,4,5,6,8,9,10,11,12 (7 absent → fee_tip zero); shortest encoding confirmed.  
3–8. All required fields present; `tx_version=1` recognized; `chain_id=b"viper-pq-1"` matches; `msg_type=0x0100` recognized; `sender` 32 bytes; `payload` valid CBOR and under 1 MB.  
9–10. `sig_alg_id=0x0002` (ML-DSA-65) is active; `len(signature)=3309` matches expected size.  
11. `(sender, key_version=1)` resolves to an active ML-DSA-65 key with `allowed_tx_types` including attestation operations.  
12. Signature verifies against the reconstructed `preimage_hash` (verifier re-derives the §6.1 `ForkDigest` from local `(fork_version, genesis_validators_root)` config and re-applies the BIP340 double-tagged outer hash).  
13. `nonce=42 = account_nonce(41) + 1` — valid.  
14. `fee=1,500,000 ≥ base_fee + byte_fee × tx_bytes + sigverify_fee[ML-DSA-65] + exec_fee × 200,000` — satisfied.  
15. Per-sender verify budget not exceeded — admitted to mempool.

---

## 16. Open TBDs

| ID | Item | Blocking? |
|----|------|-----------|
| TBD-TX-01 | `chain_id` exact format: is it a fixed 32-byte random identifier set at genesis, or a structured prefix+suffix? | No — networks can define it at genesis until a cross-chain spec is needed |
| TBD-TX-02 | `gas_limit` unit definition: what constitutes one unit of execution gas? | Deferred to SPEC-OPS (TASK-007) where operation costs are defined |
| TBD-TX-03 | Exact fee coefficient values (`byte_fee`, `sigverify_fee`, `exec_fee`) | Deferred to Phase 2 after prototype benchmarks (ADR-015) |
| TBD-TX-04 | Batch nonce support for account abstraction or sponsored transactions | Not in Phase 1 scope |

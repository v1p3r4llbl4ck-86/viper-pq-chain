# SPEC-ADDRESS-001: Address Derivation

**Status**: Accepted
**History**: v0.3 revised for the `viper-pq-1` genesis (2026-04-25; that chain is retired, the derivation is unchanged on `viper-testnet-1`).
**Version**: 0.3
**Date**: 2026-04-25
**References**: SPEC-ACCOUNT-001, SPEC-TX-001, SPEC-FEE-002 (burn address), SPEC-SLASH-001 (treasury address), ADR-053

**Revision history**

| Version | Date | Change |
|---------|------|--------|
| 0.1 | 2026-04-16 | Initial draft. Single-tag SHAKE-256 derivation with `sig_alg_id` domain separator only. |
| 0.2 | 2026-04-21 | Editorial polish around §4 (special addresses) and §6 (migration). |
| 0.3 | 2026-04-25 | **Aligned to viper-pq-1 launch code.** §2.2 rewritten under ADR-053 §T1.3 (chain-id-bound address derivation, TASK-192) and ADR-053 §T2.4 (BIP340 double-tagged hashing, TASK-202). New §2.3 documents `chain_id` cross-chain replay resistance. §2.5 (legacy "sig_alg_id-only domain separation") moved into the new §2.4 BIP340 rationale subsection. §6 rewritten as a historical pre-launch note — no further migration is possible under Policy P-COMPAT-001 / ADR-052. |

---

## 1 Purpose

This specification defines the canonical address derivation for Viper PQ Chain accounts. An address is a compact, collision-resistant, **chain-bound** identifier derived from a signing public key, its algorithm identifier, and the host chain's `chain_id`. The derivation is deterministic: the same key material on the same host chain always produces the same address.

Addresses appear in transaction envelopes (`sender` field), account state, genesis configuration, API responses, and user-facing display strings. A single, unambiguous derivation rule is required so that all participants — nodes, wallets, SDKs, explorers — agree on the mapping from `(chain_id, alg_id, public key)` to address.

The implementation lives in `crates/pqc-crypto/src/address.rs::derive_address` and is the single ground-truth source for this specification.

---

## 2 Raw Address Derivation

### 2.1 Inputs

| Input | Type | Description |
|-------|------|-------------|
| `chain_id` | `[u8]` | The host chain identifier as raw bytes (e.g. `b"viper-pq-1"`). Same value as `chain_id` field in the transaction envelope (SPEC-TX-001 §5.2). |
| `sig_alg_id` | `u16` | Algorithm identifier from the `AlgId` enum (e.g. `0x0002` for ML-DSA-65). |
| `pk_bytes` | `[u8]` | Raw public key bytes (length depends on algorithm; 1952 bytes for ML-DSA-65). |

### 2.2 Procedure (BIP340 double-tagged, ADR-053 §T1.3 + §T2.4)

```
sig_alg_id_be16 = sig_alg_id encoded as 2 bytes, big-endian
body            = chain_id || sig_alg_id_be16 || pk_bytes
raw_address     = tagged_hash("VIPER-ADDR-V1", body)
                = SHAKE-256(H(tag) || H(tag) || body)[..32]
```

where:

- `tag = b"VIPER-ADDR-V1"` is the domain-separation tag fixed by ADR-053 §T1.3.
- `H(tag) = SHAKE-256(tag, 32)` is the 32-byte tag digest.
- `tagged_hash(tag, body)` is the BIP340-style **double-tagged** hash defined in ADR-053 §T2.4: `SHAKE-256(H(tag) || H(tag) || body, 32)`.
- `body` is absorbed contiguously without internal length framing. The field layout is unambiguous per-chain because `chain_id` is fixed for a given host chain, `sig_alg_id_be16` is exactly 2 bytes, and `pk_bytes` length is determined by `alg_id` via the active algorithm registry (SPEC-ACCOUNT-001).

The canonical implementation is `pqc_crypto::derive_address(chain_id, alg_id, pk_bytes)` at `crates/pqc-crypto/src/address.rs:33`. The BIP340 double-tagged primitive is `pqc_crypto::tagged_hash` at `crates/pqc-crypto/src/hash.rs:111`.

The tagged-hash construction is regression-pinned by `derive_address_preimage_pin` in `crates/pqc-crypto/src/address.rs:112-126`. Any change to the body layout, the tag string, or the hash construction is a consensus-breaking address-space migration and will trip that test.

### 2.3 Chain-ID Domain Separation (ADR-053 §T1.3)

The `chain_id` byte string is part of the address preimage. The **same** `(alg_id, pk_bytes)` pair therefore resolves to a **different** address on every chain that differs in its `chain_id`:

```
derive_address(b"viper-pq-1", AlgId::MlDsa65, pk) ≠ derive_address(b"viper-pq-2",     AlgId::MlDsa65, pk)
derive_address(b"viper-pq-1", AlgId::MlDsa65, pk) ≠ derive_address(b"some-other-l1",  AlgId::MlDsa65, pk)
```

This is the cross-chain replay defense at the address layer. Without it, a public key registered as account `A` on `viper-pq-1` would also be account `A` on every parallel or future chain that shares the address-derivation rule, and a signed transaction that referenced "account A" would be valid on either. With chain-id binding, an attacker who replays a `viper-pq-1` transaction on a parallel chain finds that the `sender` field does not name a real account on that other chain — the address itself is chain-scoped.

Chain-id binding is complementary to the `ForkDigest` signing-domain prefix (ADR-053 §T1.2, see SPEC-TX-001 §6 and SPEC-CONSENSUS-001 §12): the signing-domain prefix prevents a **signed message** from being replayed across chains; the chain-bound address prevents the **identity** referenced by that message from being the same account across chains. The two layers compose.

The chain-id binding invariant is regression-pinned by `derive_address_chain_id_domain_separation` in `crates/pqc-crypto/src/address.rs:91-101`.

### 2.4 Algorithm-ID Domain Separation and BIP340 Outer Hash

The 2-byte `sig_alg_id_be16` field inside `body` ensures that the same raw public key bytes under two different signature algorithms (e.g. a hypothetical key valid for both ML-DSA-65 and ML-DSA-87) produce distinct addresses, preventing cross-algorithm address collision.

The BIP340 double-tagged outer hash (ADR-053 §T2.4) protects against the CVE-2012-2459 class of attacks: an attacker cannot find any `body'` such that `tag || body` and `tag' || body'` share the same digest, because the inner `H(tag)` values each occupy a full hash block and cannot be reached by crafting `body'` alone. In practice this means no domain-tag collision can forge an alternative preimage that the verifier would accept.

Cost of the double-tag construction: one extra hash block per address derivation (32 bytes of pre-state), which is negligible at the per-account scale.

### 2.5 Algorithm Identifier Values

These values match the `AlgId` enum in `pqc-crypto::alg`.

| Algorithm | `AlgId` value | `sig_alg_id_be16` |
|-----------|---------------|-------------------|
| ML-DSA-44 | `0x0001` | `[0x00, 0x01]` |
| ML-DSA-65 | `0x0002` | `[0x00, 0x02]` |
| ML-DSA-87 | `0x0003` | `[0x00, 0x03]` |
| FN-DSA-512 | `0x0010` | `[0x00, 0x10]` |
| SLH-DSA-128s | `0x0020` | `[0x00, 0x20]` |
| ML-KEM-768 | `0x0100` | `[0x01, 0x00]` |

Activation status of each `alg_id` is governed by the on-chain Algorithm Registry (SPEC-ACCOUNT-001 §Algorithm Registry). New algorithms are added via the `ProposalEffect::AddAlgorithm` governance proposal type (ADR-049).

### 2.6 Output

The raw address is exactly 32 bytes. This is the canonical internal representation used in state storage, transaction matching, and state root computation.

---

## 3 Display Format

### 3.1 Bech32m Encoding

For human-readable display (CLI output, block explorers, user interfaces), raw addresses are encoded using Bech32m (BIP-350).

| Component | Value |
|-----------|-------|
| Human-readable part (HRP) | `vpr` (mainnet), `vpt` (testnet/devnet) |
| Data | 32 raw address bytes, converted to 5-bit groups per BIP-173 |
| Checksum | Bech32m checksum per BIP-350 |

Example (mainnet): `vpr1qw508d6qejxtdg4y5r3zarvary0c5xw7k...` (truncated)

Example (testnet): `vpt1qw508d6qejxtdg4y5r3zarvary0c5xw7k...` (truncated)

The implementation is `pqc_crypto::address::address_to_bech32m` / `bech32m_to_address` in `crates/pqc-crypto/src/address.rs:45-70`.

### 3.2 Hex Encoding

For API responses, configuration files, internal logging, and programmatic use, addresses are encoded as lowercase hex:

```
hex_address = hex::encode(raw_address)
```

This produces a 64-character hexadecimal string. Hex encoding is used in:

- `/v1/accounts/{address}` API path parameter and response body
- Genesis configuration files (`genesis_accounts` entries)
- Node configuration (`validator_address` field)
- Log output and tracing events
- Transaction CBOR (the `sender` field stores raw bytes; hex is only for display)

### 3.3 Parsing

Implementations MUST accept both Bech32m and hex formats as user input (CLI arguments, API parameters). Internally, all address comparisons and storage use the 32-byte raw form.

When parsing Bech32m input:
1. Decode the Bech32m string, verifying the checksum.
2. Verify the HRP matches the expected network (`vpr` or `vpt`).
3. Convert the 5-bit data groups back to 32 raw bytes.
4. Reject inputs where the decoded data length is not exactly 32 bytes.

When parsing hex input:
1. Verify the string is exactly 64 hexadecimal characters.
2. Decode to 32 raw bytes.

---

## 4 Special Addresses

### 4.1 Zero Address (Burn)

```
ZERO_ADDRESS = [0x00; 32]
```

The zero address is provably unspendable — no known public key under any supported algorithm hashes (under any `chain_id`) to 32 zero bytes (this would require a SHAKE-256 / BIP340-tagged-hash preimage, which is computationally infeasible). It is used as the fee burn destination when `burn_rate_bps > 0` (SPEC-FEE-002 §9.3).

Transactions with `sender = ZERO_ADDRESS` MUST be rejected at mempool admission.

### 4.2 Treasury Address

```
TREASURY_ADDRESS = [0x01; 32]
```

The treasury address receives slashing penalty amounts (SPEC-SLASH-001 §9). Like the zero address, it is unspendable by any external signer. Treasury funds are disbursed only through governance proposals.

Transactions with `sender = TREASURY_ADDRESS` MUST be rejected at mempool admission.

### 4.3 Genesis Accounts

Genesis accounts (founder, treasury, genesis validators, reserved pool per SPEC-TOKEN-002) use addresses derived by the standard procedure in §2 with `chain_id` set to the chain's own identifier (`b"viper-pq-1"` on the retired chain; the `viper-testnet-1` identifier is assigned at genesis). Their public keys, algorithm identifiers, and resulting addresses are pinned in the chain's genesis configuration file (historical example: `deploy/ansible/files/genesis-viper-pq-1.json`).

---

## 5 Security Considerations

### 5.1 Collision Resistance

SHAKE-256 with 32-byte output provides 128 bits of collision resistance (birthday bound). The BIP340 double-tagged construction does not weaken this bound — the outer hash is still SHAKE-256 with 32 bytes of output. An attacker would need approximately 2^128 operations to find two distinct `(chain_id, alg_id, pk)` triples that map to the same address.

### 5.2 Preimage Resistance

SHAKE-256 with 32-byte output provides 256 bits of preimage resistance. Given an address, it is computationally infeasible to find a `(chain_id, alg_id, pk)` triple that produces that address. This property underpins the unspendability of the zero and treasury addresses.

### 5.3 Domain Separation Rationale

The address preimage layers three independent domain separators:

1. **BIP340 outer tag** (`tag = "VIPER-ADDR-V1"`, ADR-053 §T2.4) — prevents domain-tag collisions across the workspace's other tagged hashes (state-leaf, state-branch, vote, proposal, fork-digest, governance, …).
2. **`chain_id` bytes inside the body** (ADR-053 §T1.3) — prevents an address derived on `viper-pq-1` from coinciding with an address on any parallel or future host chain.
3. **2-byte `sig_alg_id` inside the body** — prevents the same `pk_bytes` from resolving to the same address under two different signature algorithms.

Each layer addresses a distinct attack class. Removing any one of them re-enables a class of replay or aliasing attack that the others do not cover.

### 5.4 No Key Recovery from Address

The address does not encode the public key — it is a one-way hash. To verify a signature against an address, the verifier MUST obtain the full public key from the account's KeySet in state (SPEC-ACCOUNT-001). The address serves only as a lookup key.

---

## 6 Historical pre-launch migration notes

> The `viper-pq-1` genesis (chain_id `viper-pq-1`, hex `0x76697065722d70712d31`; chain since retired) shipped with the §2.2 derivation already in place. The pre-launch addresses on the retired `viper-devnet-2` chain — derived under the v0.1 single-tag, no-chain-id formula — are not portable to `viper-pq-1`. This subsection is preserved as a record of that one-time discontinuity.

### 6.1 Pre-launch derivation (retired)

```
# Pre-launch on viper-devnet-2 (SPEC-ADDRESS-001 v0.1):
legacy_address = SHAKE-256(sig_alg_id_be16 || pk_bytes, 32)
```

### 6.2 Chain-id-bound derivation (canonical, §2.2 above; introduced with `viper-pq-1`)

```
canonical_address = tagged_hash("VIPER-ADDR-V1", chain_id || sig_alg_id_be16 || pk_bytes)
```

These produce different addresses for the same `(alg_id, pk)` pair. The chain reset that introduced this change is the same reset that introduced ADR-053 §T1.3 / §T2.4 / §T1.2 / §T1.4 / §T2.4. Under Policy P-COMPAT-001 (ADR-052) **no further chain reset is permitted**; any future change to address derivation must travel via a forward-compatible upgrade path that keeps existing addresses verifiable indefinitely.

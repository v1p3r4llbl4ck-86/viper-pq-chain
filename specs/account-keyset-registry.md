# Account, KeySet, and Algorithm Registry Specification

**Spec ID**: SPEC-ACCOUNT-001  
**Version**: 0.1  
**Status**: Draft  
**Date**: 2026-04-09  
**Depends on**: ADR-003 (crypto agility), ADR-006 (algorithm baseline), ADR-011 (deprecation process), SPEC-TX-001

---

## 1. Scope

This document specifies three interdependent protocol objects:

1. **Account** — the on-chain identity unit that holds balance, nonce, and a KeySet
2. **KeySet** — the collection of signing keys associated with an account, including their lifecycle state
3. **Algorithm Registry** — the protocol-level registry of recognized signature algorithms, their lifecycle status, and their fee parameters

Together these three objects define what it means for a transaction to be validly signed by a recognized key using an authorized algorithm. SPEC-TX-001 depends on this specification for steps 9–11 of the validation pipeline.

This specification does not define:

- operation payload semantics (see SPEC-OPS, TASK-007)
- validator staking and slashing (see TASK-005)
- governance vote mechanics (referenced but not specified here)
- fee coefficient values (deferred to Phase 2, ADR-015)

---

## 2. Normative Language

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT, RECOMMENDED, MAY, and OPTIONAL in this document are to be interpreted as described in RFC 2119.

---

## 3. Normative References

| Reference | Document |
|-----------|----------|
| SPEC-TX-001 | Transaction Envelope Specification |
| ADR-003 | Make Crypto Agility a Protocol Requirement |
| ADR-006 | ML-DSA as Default Signature Baseline |
| ADR-011 | Four-Step Algorithm Deprecation Process |
| ADR-012 | Phase 1 Scope |
| FIPS 204 | ML-DSA |
| FIPS 205 | SLH-DSA |
| FIPS 206 (draft) | FN-DSA |
| NIST SP 800-185 | SHAKE-256 |

---

## 4. Account

### 4.1 Account State

An account is the atomic unit of identity and economic participation on PQ Chain. The on-chain state of an account is:

| Field | Type | Description |
|-------|------|-------------|
| `address` | bstr (32 B) | immutable network identifier for this account |
| `balance` | uint (u128) | token balance in base units |
| `nonce` | uint (u64) | monotonically increasing transaction counter |
| `keys` | KeySet | ordered collection of key entries |

### 4.2 Address Derivation

An account address is derived once at account creation and MUST NOT change for the lifetime of the account.

```
address = SHAKE-256(pk_bytes || uint16_be(alg_id) || uint32_be(key_version), 32)
```

Where `pk_bytes`, `alg_id`, and `key_version` refer to the first key registered at account creation — the genesis key.

**Invariant**: address is permanently bound to the genesis key material used at creation. Key rotations, algorithm changes, and KeySet updates do not affect the address. An account survives the full deprecation of its genesis algorithm as long as at least one active key remains in its KeySet.

### 4.3 Account Invariants

The following conditions MUST hold at all times. A state transition that would violate any invariant MUST be rejected:

1. **Address immutability**: `address` is set at account creation and is never modified
2. **Nonce monotonicity**: `nonce` only increases; it is never decremented or reset
3. **Non-negative balance**: `balance` MUST NOT go below zero; transactions that would overdraft MUST be rejected before state is modified
4. **At least one active key**: an account MUST always have at least one key with `status = active`. A key revocation that would leave the KeySet with zero active keys MUST be rejected
5. **No duplicate key_version**: within a single account's KeySet, all `key_version` values MUST be unique

### 4.4 Account Creation

An account is created implicitly on the first transaction from a new address, or explicitly via an account creation operation. At creation:

- `balance` = initial funding amount (may be zero if creation is pre-funded elsewhere)
- `nonce` = 0
- `keys` = one entry: the genesis key (see KeySet §5.3)

---

## 5. KeySet

### 5.1 Overview

A KeySet is the ordered collection of signing key entries associated with an account. An account MAY have multiple keys active simultaneously. Keys are identified within an account by `key_version`, which is unique per account and monotonically increasing.

### 5.2 Key Entry Fields

| Field | Type | Description |
|-------|------|-------------|
| `alg_id` | uint (u16) | algorithm identifier; MUST reference an entry in the Algorithm Registry |
| `pk_bytes` | bstr | raw public key bytes; exact size determined by `alg_id` |
| `key_version` | uint (u32) | unique per-account identifier for this key; monotonically increasing |
| `valid_from_height` | uint (u64) | block height from which this key becomes active |
| `status` | enum | `pending`, `active`, or `revoked` |
| `allowed_tx_types` | uint (u32) | bitmask of permitted `msg_type` ranges |

### 5.3 Field Semantics

#### 5.3.1 `alg_id`

- MUST reference a known algorithm in the Algorithm Registry
- MUST NOT reference an algorithm with `lifecycle_status = banned`; a key with a banned algorithm MUST be treated as `revoked` for all signature verification purposes, even if its `status` field reads `active`
- If an algorithm transitions to `banned` after a key was registered, all existing keys with that `alg_id` are immediately treated as unusable without a state migration; governance MUST ensure a grace period (via `discouraged` and `deprecated` steps) before reaching `banned`

#### 5.3.2 `pk_bytes`

- MUST match the byte length specified by the Algorithm Registry for `alg_id`
- MUST be the canonical encoding of the public key as defined by the corresponding FIPS standard
- Nodes MUST reject key registration if `len(pk_bytes) ≠ expected_pk_size(alg_id)`

Expected public key sizes:

| alg_id | Algorithm | pk_bytes size |
|--------|-----------|--------------|
| 0x0001 | ML-DSA-44 | 1,312 B |
| 0x0002 | ML-DSA-65 | 1,952 B |
| 0x0003 | ML-DSA-87 | 2,592 B |
| 0x0010 | FN-DSA-padded-512 | 897 B |
| 0x0011 | FN-DSA-padded-1024 | 1,793 B |
| 0x0020 | SLH-DSA-SHA2-128s | 32 B |
| 0x0021 | SLH-DSA-SHA2-192s | 48 B |

#### 5.3.3 `key_version`

- MUST be strictly greater than all existing `key_version` values in the same account's KeySet
- Starts at `1` for the genesis key; each subsequent key increments from the highest existing value
- `key_version = 0` is reserved and MUST NOT be used
- Once assigned, `key_version` is immutable for that key entry

#### 5.3.4 `valid_from_height`

- The key MUST NOT be used to sign transactions included in blocks with `block_height < valid_from_height`
- MUST be ≥ the block height at which the key registration transaction is finalized; nodes MUST reject key registrations that set `valid_from_height` to a height already passed
- MAY be set to a future block height to schedule key activation
- When `valid_from_height = finalization_height`, the key becomes active immediately upon finalization of the registration transaction

#### 5.3.5 `status`

Three values are defined:

| Status | Meaning |
|--------|---------|
| `pending` | `valid_from_height` has not yet been reached; key MUST NOT be used to sign |
| `active` | `valid_from_height` has been reached and key has not been revoked; key MAY be used to sign |
| `revoked` | key has been explicitly revoked; key MUST NOT be used to sign; terminal state |

Status is derived and enforced as follows:

- A key entry is created with `status = pending` if `valid_from_height > current_height`, or `status = active` if `valid_from_height ≤ current_height`
- `pending → active` transition occurs automatically when the chain height reaches `valid_from_height`; no explicit transaction is required
- `active → revoked` requires an explicit key revocation or key rotation operation (see §5.5)
- `revoked` is terminal: a revoked key MUST NOT be re-activated under any circumstances
- There is no transition from `pending` to `revoked` that bypasses `active`; a pending key MAY be revoked before activation by submitting a revocation operation, which sets its `status = revoked` immediately

#### 5.3.6 `allowed_tx_types`

A 32-bit bitmask that restricts which `msg_type` ranges this key may authorize.

Bit assignments (aligned with SPEC-TX-001 §5.3 msg_type ranges):

| Bit | msg_type range | Operations |
|-----|---------------|------------|
| 0 | `0x0001–0x00FF` | vault account operations |
| 1 | `0x0100–0x01FF` | attestation and notarization |
| 2 | `0x0200–0x02FF` | key management operations |
| 3 | `0x0300–0x03FF` | governance operations |
| 4–30 | reserved | MUST be zero |
| 31 | internal | reserved for protocol use; MUST NOT be set by users |

A key with all bits 0–3 set (`allowed_tx_types = 0x0000000F`) has full operational permission.

Default policy for SLH-DSA keys: `allowed_tx_types` MUST be set to bit 2 only (`0x00000004`), restricting the key to key management operations (rotation and recovery). This policy is enforced by the key registration operation; a registration that attempts to assign broader permissions to an SLH-DSA key MUST be rejected.

The verifier MUST check: `(allowed_tx_types >> msg_type_bit(tx.msg_type)) & 1 == 1`. If this condition fails, the transaction MUST be rejected with `KEY_PERMISSION_DENIED`.

### 5.4 Key Lookup

Given a transaction with `(sender, sig_key_version, sig_alg_id)`, the verifier resolves the signing key as follows:

1. Locate the account at `sender`; if not found, reject with `INVALID_SENDER`
2. Find the key entry in `account.keys` where `key_version = sig_key_version`; if not found, reject with `KEY_NOT_FOUND`
3. Verify `key_entry.alg_id = sig_alg_id`; if mismatch, reject with `KEY_ALG_MISMATCH`
4. Verify `key_entry.status = active`; if `pending`, reject with `KEY_NOT_YET_ACTIVE`; if `revoked`, reject with `KEY_REVOKED`
5. Verify `key_entry.alg_id` is not `banned` in the Algorithm Registry; if banned, reject with `UNSUPPORTED_ALGORITHM`
6. Verify `allowed_tx_types` permits the requested `msg_type`; if not, reject with `KEY_PERMISSION_DENIED`
7. Return `key_entry.pk_bytes` for signature verification

### 5.5 KeySet Operations

#### 5.5.1 Add Key

Registers a new key in the account's KeySet.

Preconditions:
- `msg_type` MUST be in the key management range (`0x0200–0x02FF`)
- The transaction MUST be signed by an existing `active` key with bit 2 set in `allowed_tx_types`
- `new_key.key_version` MUST be strictly greater than all existing `key_version` values in the account
- `new_key.alg_id` MUST reference an algorithm with `lifecycle_status ∈ {active, discouraged}`; keys MUST NOT be registered for algorithms with `lifecycle_status ∈ {deprecated, banned}`
- `new_key.valid_from_height` MUST be ≥ the finalization height of this transaction
- SLH-DSA keys MUST have `allowed_tx_types = 0x00000004`
- `len(new_key.pk_bytes)` MUST match `expected_pk_size(new_key.alg_id)`
- After adding the key, account invariant 4 (at least one active key) is trivially maintained; no additional check required

Effect: key entry is appended to `account.keys` with `status = pending` or `active` depending on `valid_from_height`.

#### 5.5.2 Rotate Key

Atomically registers a new key and revokes an existing key in a single operation.

Preconditions:
- All preconditions of Add Key apply to the new key
- `old_key_version` MUST identify an existing key in the account with `status = active`
- The new key and the old key MUST NOT be the same entry (`new_key.key_version ≠ old_key_version`)
- After the rotation, account invariant 4 MUST hold: if the old key was the last active key, the new key's `valid_from_height` MUST be ≤ the finalization height (i.e., the new key becomes active in the same block or before)
- The signing key for this rotation transaction MUST have bit 2 set in `allowed_tx_types`; it MAY be the key being rotated out

Effect:
- New key is added with `status = pending` or `active`
- Old key transitions to `status = revoked`
- Both state changes are applied atomically at finalization

#### 5.5.3 Revoke Key

Marks an existing key as `revoked` without registering a replacement.

Preconditions:
- `target_key_version` MUST identify an existing key with `status ∈ {active, pending}`
- After revocation, account invariant 4 MUST hold: if the target key is the only `active` key, this operation MUST be rejected unless another `active` key exists or a new key is being added in the same transaction

Effect: `target_key.status → revoked` at finalization.

#### 5.5.4 Reject Conditions for All KeySet Operations

| Condition | Rejection code |
|-----------|---------------|
| `new_key.key_version ≤ max(existing key_version)` | `KEY_VERSION_CONFLICT` |
| `new_key.alg_id` has `lifecycle_status ∈ {deprecated, banned}` | `UNSUPPORTED_ALGORITHM` |
| `len(new_key.pk_bytes) ≠ expected_pk_size(new_key.alg_id)` | `INVALID_KEY_SIZE` |
| `new_key.valid_from_height < finalization_height` | `INVALID_ACTIVATION_HEIGHT` |
| SLH-DSA key with `allowed_tx_types` other than `0x00000004` | `INVALID_KEY_PERMISSIONS` |
| Revocation would leave zero active keys | `INSUFFICIENT_ACTIVE_KEYS` |
| `target_key_version` not found or already revoked | `KEY_NOT_FOUND` / `KEY_ALREADY_REVOKED` |

---

## 6. Algorithm Registry

### 6.1 Overview

The Algorithm Registry is an on-chain data structure that defines which signature algorithms the protocol recognizes, their current lifecycle status, their permitted use cases, and their fee parameters. It is the authoritative source consulted by all nodes during transaction validation.

No algorithm is implicitly supported. An algorithm MUST be present in the Registry with `lifecycle_status = active` or `discouraged` to be usable for signing.

### 6.2 Registry Entry Fields

| Field | Type | Mutable | Description |
|-------|------|---------|-------------|
| `alg_id` | uint (u16) | No | unique protocol identifier; assigned at registration; never changes |
| `spec_ref` | text | No | normative reference (e.g. `"FIPS-204"`, `"FIPS-206-draft"`) |
| `param_set` | text | No | parameter set name (e.g. `"ML-DSA-65"`, `"SLH-DSA-SHA2-128s"`) |
| `pk_size` | uint | No | expected public key byte length |
| `sig_size` | uint | No | expected signature byte length |
| `allowed_use_cases` | uint (u32) | Yes | bitmask of permitted `msg_type` ranges (same bit assignment as KeySet `allowed_tx_types`) |
| `min_fee` | uint (u64) | Yes | floor for `sigverify_fee[alg_id]`; raised by governance when algorithm is discouraged |
| `lifecycle_status` | enum | Yes | `active` / `discouraged` / `deprecated` / `banned` |

**Immutable fields** (`alg_id`, `spec_ref`, `param_set`, `pk_size`, `sig_size`) are set at registration and MUST NOT be changed by governance. If a parameter set is superseded, a new `alg_id` is assigned.

**Mutable fields** (`allowed_use_cases`, `min_fee`, `lifecycle_status`) may be updated via governance vote.

### 6.3 Initial Registry (Phase 1)

| alg_id | spec_ref | param_set | pk_size | sig_size | allowed_use_cases | lifecycle_status |
|--------|----------|-----------|---------|----------|-------------------|-----------------|
| 0x0001 | FIPS-204 | ML-DSA-44 | 1,312 B | 2,420 B | 0x0F | active |
| 0x0002 | FIPS-204 | ML-DSA-65 | 1,952 B | 3,309 B | 0x0F | active |
| 0x0003 | FIPS-204 | ML-DSA-87 | 2,592 B | 4,627 B | 0x0F | active |
| 0x0010 | FIPS-206-draft | FN-DSA-padded-512 | 897 B | 666 B | 0x0F | active |
| 0x0011 | FIPS-206-draft | FN-DSA-padded-1024 | 1,793 B | 1,280 B | 0x0F | active |
| 0x0020 | FIPS-205 | SLH-DSA-SHA2-128s | 32 B | 7,856 B | 0x04 | active |
| 0x0021 | FIPS-205 | SLH-DSA-SHA2-192s | 48 B | 16,224 B | 0x04 | active |

`allowed_use_cases = 0x0F` means all four Phase 1 operation ranges are permitted.  
`allowed_use_cases = 0x04` means key management operations only (bit 2).

### 6.4 Lifecycle States

| Status | Effect on transaction validation | Effect on key registration |
|--------|----------------------------------|--------------------------|
| `active` | accepted normally | new keys may be registered |
| `discouraged` | accepted; `min_fee` floor enforced; nodes SHOULD log | new keys MUST NOT be registered |
| `deprecated` | MUST be rejected at mempool (`UNSUPPORTED_ALGORITHM`) | new keys MUST NOT be registered |
| `banned` | MUST be rejected at mempool (`UNSUPPORTED_ALGORITHM`); existing keys with this `alg_id` treated as revoked | new keys MUST NOT be registered |

### 6.5 Lifecycle Transitions

Valid transitions:

```
active → discouraged
discouraged → deprecated
deprecated → banned
active → deprecated   (emergency fast-track, requires supermajority governance vote)
```

Invalid transitions (MUST be rejected by governance execution):

```
banned → any
deprecated → active
discouraged → active
```

An algorithm can only move toward deprecation, never back toward active. This is a protocol invariant enforced at execution time.

### 6.6 Deprecation Process (ADR-011)

The four-step deprecation process applies to all lifecycle transitions beyond `active`:

1. **Announcement** — governance votes to signal intent; a target transition timeline is recorded on-chain. No status change yet.
2. **Discouraged** — governance vote sets `lifecycle_status = discouraged` and raises `min_fee` to penalize continued use. Existing keys with this algorithm remain valid. New key registrations for this algorithm are blocked.
3. **Deprecated** — governance vote sets `lifecycle_status = deprecated`. All transactions signed with this algorithm are rejected at mempool. Accounts that have not migrated are blocked from transacting until they rotate to an active algorithm.
4. **Banned** — governance vote sets `lifecycle_status = banned`. Existing keys with this `alg_id` are treated as revoked.

The minimum time between steps is a governance parameter (TBD; a reasonable floor is one epoch between each step). The announced timeline from step 1 MUST be respected.

Emergency fast-track (active → deprecated directly) bypasses steps 1 and 2 and MUST require a supermajority governance vote. It is reserved for critical security failures.

### 6.7 `min_fee` Semantics

`min_fee` is an absolute floor for `sigverify_fee[alg_id]` in the transaction fee formula.

The effective `sigverify_fee` used in validation is:

```
effective_sigverify_fee = max(benchmark_sigverify_fee[alg_id], registry[alg_id].min_fee)
```

Where `benchmark_sigverify_fee[alg_id]` is the base fee derived from benchmark measurements (calibrated in Phase 2).

When an algorithm is discouraged, governance raises `min_fee` above the benchmark value, making transactions with that algorithm economically penalized relative to alternatives. This creates migration incentive without hard enforcement.

`min_fee` has no defined upper limit; governance may set it arbitrarily high as an emergency measure short of a full deprecation vote.

### 6.8 Algorithm Registration

New algorithms are added to the Registry via governance vote. Registration requires:

- `alg_id` not already in use
- A complete entry with all immutable fields specified
- `lifecycle_status = active` at registration (algorithms MUST NOT be added as discouraged or deprecated)
- A normative specification reference (`spec_ref`) pointing to a published or final-draft standard

Algorithms from NIST's "Additional Digital Signature Schemes" process (CROSS, MAYO, SNOVA, UOV, and others) MUST NOT be added until they reach final-draft standardization. They are tracked as research candidates only.

---

## 7. Cross-Object Validation Rules

The following rules apply at the intersection of Account, KeySet, and Algorithm Registry and are enforced during transaction validation (see SPEC-TX-001 §10, steps 9–11):

| Rule | Condition | Rejection |
|------|-----------|-----------|
| R-01 | `tx.sig_alg_id` must be in Registry | `UNSUPPORTED_ALGORITHM` |
| R-02 | `registry[tx.sig_alg_id].lifecycle_status ∈ {active, discouraged}` | `UNSUPPORTED_ALGORITHM` |
| R-03 | `(tx.sender, tx.sig_key_version)` must resolve to a key entry | `KEY_NOT_FOUND` |
| R-04 | `key_entry.alg_id = tx.sig_alg_id` | `KEY_ALG_MISMATCH` |
| R-05 | `key_entry.status = active` | `KEY_NOT_YET_ACTIVE` / `KEY_REVOKED` |
| R-06 | `registry[key_entry.alg_id].lifecycle_status ≠ banned` | `UNSUPPORTED_ALGORITHM` |
| R-07 | `(key_entry.allowed_tx_types >> msg_type_bit(tx.msg_type)) & 1 = 1` | `KEY_PERMISSION_DENIED` |
| R-08 | If `lifecycle_status = discouraged`: `tx.fee ≥ … + max(benchmark_fee, registry[alg_id].min_fee)` | `INSUFFICIENT_FEE` |

R-01 through R-07 are evaluated in this order. R-08 is evaluated as part of the fee sufficiency check (SPEC-TX-001 §10, step 14).

---

## 8. State Storage Considerations

### 8.1 KeySet Growth

An account's KeySet grows with each key registration and is bounded only by available balance (key registration consumes fee). There is no hard upper limit on KeySet size in this specification; however:

- large KeySets increase account state size and impose read costs on verifiers
- governance MAY introduce a KeySet size cap as a protocol parameter in a future spec version
- nodes SHOULD monitor average KeySet sizes during testnet and report to the fee model calibration process

### 8.2 Revoked Key Retention

Revoked keys MUST be retained in account state. They serve as an audit record and are necessary for reconstructing the signing history of old transactions. Pruning of revoked key entries is not permitted in this version.

### 8.3 Registry Immutability of Historical Entries

When an algorithm is deprecated or banned, its Registry entry MUST remain present with its immutable fields intact. Removing a Registry entry would break historical signature verification for archived blocks. The `lifecycle_status` changes; the entry itself persists.

---

## 9. Security Considerations

### 9.1 Address Stability Across Algorithm Deprecation

Because the account address is derived from the genesis key and is immutable, the deprecation of the genesis algorithm does not invalidate the address. The account can continue to operate as long as at least one active key with a non-deprecated algorithm exists in its KeySet. Users MUST rotate before their last active algorithm reaches `deprecated`.

### 9.2 SLH-DSA Restriction Rationale

SLH-DSA keys are restricted to key management operations (`allowed_tx_types = 0x04`) for two reasons: (a) SLH-DSA verification is approximately 60× slower than ML-DSA on reference hardware, making it a DoS vector at high frequency; (b) SLH-DSA's large signatures would inflate storage costs if used on the common transaction path. SLH-DSA's value is as a conservative, hash-based last resort for emergency recovery — a role that is inherently infrequent.

### 9.3 No Algorithm Downgrade

The lifecycle transition graph is acyclic toward deprecation. Governance cannot re-activate a deprecated or banned algorithm. If a previously discouraged algorithm is later found to be sound, a new Registry entry with a new `alg_id` must be registered. This prevents confusion between old and new parameter sets and ensures audit clarity.

### 9.4 Atomic Key Rotation

The Rotate Key operation is atomic: both the new key registration and the old key revocation happen in the same finalized block. This prevents a window where an account has no active key. Implementations MUST NOT process the revocation without the registration, or vice versa, even in failure recovery scenarios.

### 9.5 Pending Key Window

A key with `valid_from_height` in the future creates a window during which the key material is publicly visible but not yet usable. This is by design: it allows counterparties to observe upcoming key changes on-chain before they take effect. The pending window does not introduce a signing oracle vulnerability because the private key is not used until activation.

---

## 10. Open TBDs

| ID | Item | Blocking? |
|----|------|-----------|
| TBD-ACC-01 | Maximum KeySet size: should a cap be introduced as a protocol parameter? | No — monitor during testnet; cap if growth exceeds storage budget |
| TBD-ACC-02 | Minimum time between lifecycle transition steps (e.g. minimum epoch gap between discouraged and deprecated) | No — governance parameter; deferred to TASK-010 |
| TBD-ACC-03 | Emergency fast-track supermajority threshold (e.g. 80% vs 90% of validator stake) | No — deferred to TASK-010 |
| TBD-ACC-04 | `fee_tip` for key registration operations: should key management operations be tip-ineligible to prevent fee market distortion? | No — low priority; deferred to SPEC-OPS |

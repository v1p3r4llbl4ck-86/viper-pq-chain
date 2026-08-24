# Multisig Account Specification

**Spec ID**: SPEC-MULTISIG-001
**Version**: 0.1
**Status**: Draft
**Date**: 2026-04-15
**Depends on**: ADR-033, SPEC-TX-001, SPEC-ACCOUNT-001, SPEC-FEE-001

---

## 1. Scope

This document specifies the Viper PQ Chain multisig account type: its policy data structure, wire encoding, transaction format extension, address derivation, creation and update operations, validation algorithm, execution semantics, fee treatment, and the planned upgrade path to PQ threshold signatures.

This specification does not define:

- general KeySet lifecycle rules for single-key accounts (see SPEC-ACCOUNT-001)
- the base transaction envelope (see SPEC-TX-001)
- fee coefficient values (see SPEC-FEE-001)
- governance operations (see `specs/governance-module.md`)

---

## 2. Normative Language

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT, RECOMMENDED, MAY, and OPTIONAL in this document are to be interpreted as described in RFC 2119.

---

## 3. Normative References

| Reference | Document |
|-----------|----------|
| ADR-033 | PQ Multi-Sig Accounts: n-of-m ML-DSA-65 with Threshold-Ready Design |
| SPEC-TX-001 | Transaction Envelope Specification |
| SPEC-ACCOUNT-001 | Account, KeySet, and Algorithm Registry Specification |
| SPEC-FEE-001 | Fee Model Specification |
| RFC 8949 | Concise Binary Object Representation (CBOR) |
| FIPS 204 | ML-DSA — Module-Lattice-Based Digital Signature Standard |
| NIST SP 800-185 | SHAKE-256 |

---

## 4. Overview and Motivation

A single-key vault account is insufficient for enterprise-grade custody. Real treasury and custody workflows require n-of-m authorization: no single party can unilaterally move funds or update policy. This is the standard model in classical blockchain multisig (e.g. Bitcoin P2SH, Ethereum Safe), but existing implementations use ECDSA or Ed25519 signatures. Viper is post-quantum-native from genesis; multisig must be post-quantum-native from the start.

**The PQ threshold gap.** True PQ threshold signatures — where k parties compute a single compact threshold signature without reconstructing a secret key — do not yet exist as deployed production standards. TOPCOAT (two-party ML-DSA threshold, 2024) and Quorus (MPC-based ML-DSA threshold, 2025) are academic prototypes. NIST PQC standardization of threshold schemes may begin within 1–2 years. Waiting for threshold standardization before delivering multisig capability would block real customer use cases.

**Design choice (ADR-033).** Implement n-of-m multisig at the account and transaction layer now. Each signing member produces a full ML-DSA (or other) signature independently. Signatures are aggregated off-chain and submitted together in a `MultisigWitness`. The `sig_alg_id = 0xFFFF` sentinel in the transaction envelope routes validation to the multisig path. When PQ threshold schemes standardize, a new `AlgId` value (proposed `0xFFFE`) replaces `MultisigWitness` with a single compact threshold signature. No account migration is required at that point.

**Wire cost.** ML-DSA-65 signatures are 3,309 bytes each. A 2-of-3 multisig transaction carries at minimum 6,618 bytes of signature data. SPEC-FEE-001's `byte_fee` prices these bytes automatically — no special multisig surcharge is needed in the fee formula.

---

## 5. MsgType Namespace

### 5.1 Assigned MsgType Values

Multisig operations use the `0x0600–0x06FF` range:

| MsgType | Name | Description |
|---------|------|-------------|
| `0x0600` | `MultisigCreate` | Create a new multisig account |
| `0x0601` | `MultisigPolicyUpdate` | Update threshold or member list |

### 5.2 Namespace Conflict Resolution

ADR-033 originally assigned `0x0300` and `0x0301` to multisig operations. SPEC-TX-001 §5.3 reserved `0x0300–0x03FF` for governance operations, and specs/governance.md already assigned `0x0300` to `governance_proposal` and `0x0301` to `governance_vote`. These assignments conflict.

Resolution: this specification assigns multisig to `0x0600–0x06FF`, an unoccupied range. SPEC-TX-001 §5.3 must be amended to add this range entry. ADR-033 is superseded by this assignment. The `0x0300–0x03FF` range remains exclusively for governance operations.

Nodes MUST reject any transaction with `msg_type ∈ {0x0300, 0x0301}` that carries a `MultisigWitness` in the `signature` field; those msg_type values route to the governance handler.

### 5.3 SPEC-TX-001 Amendment

The MsgType range table in SPEC-TX-001 §5.3 is amended by adding:

| Range | Use |
|-------|-----|
| `0x0600–0x06FF` | multisig account operations |

All other ranges are unchanged.

---

## 6. Algorithm Registry Entry

### 6.1 AlgId 0xFFFF — Multisig

A new sentinel entry MUST be added to the Algorithm Registry:

| Field | Value |
|-------|-------|
| `alg_id` | `0xFFFF` |
| `spec_ref` | `SPEC-MULTISIG-001` |
| `param_set` | `Multisig` |
| `pk_size` | `0` (not applicable; public keys are per-member in the policy) |
| `sig_size` | `0` (not fixed; size is k × member_sig_size, variable) |
| `allowed_use_cases` | `0x1F` (all ranges including `0x0600–0x06FF`) |
| `min_fee` | `0` (no separate sigverify_fee; member verification costs are summed; see §12) |
| `lifecycle_status` | `active` |

The `pk_size = 0` and `sig_size = 0` values signal that the standard size checks in SPEC-TX-001 §10 step 10 do not apply to this AlgId. Validators MUST substitute the multisig validation path (§10 of this spec) for steps 10–12 of the SPEC-TX-001 validation pipeline when `sig_alg_id = 0xFFFF`.

AlgId `0xFFFF` MUST NOT be assigned to any other algorithm. The reserved range `0x8000–0xFFFF` in SPEC-TX-001 §5.10 is amended to treat `0xFFFF` as specifically assigned to this Multisig sentinel, removing it from the general "reserved, MUST NOT be used" prohibition.

---

## 7. Data Structures

### 7.1 MultisigPolicy

`MultisigPolicy` is the on-chain authorization policy for a multisig account. It is stored in the StateStore (see §16) and referenced during transaction validation.

**Constraints:**
- `threshold` MUST be ≥ 1
- `threshold` MUST be ≤ the sum of all member `weight` values
- `members` MUST contain at least 2 entries (a 1-of-1 policy is a single-key account and MUST use SPEC-ACCOUNT-001)
- `members` MUST contain at most 24 entries; a policy with more than 24 members MUST be rejected with `MemberCountExceedsMax`
- All member `address` values within a single policy MUST be distinct; duplicate addresses MUST be rejected with `DuplicateMemberAddress`
- Member `alg_id` values MUST reference algorithms with `lifecycle_status ∈ {active, discouraged}` in the Algorithm Registry at the time of policy creation or update; a member with a `banned` or `deprecated` `alg_id` makes the entire policy invalid
- `policy_version` starts at 1 at account creation and MUST be incremented by exactly 1 on every `MultisigPolicyUpdate`

#### 7.1.1 CBOR Encoding

`MultisigPolicy` is encoded as a deterministic CBOR map with integer keys:

| Key | Field | Type | Constraints |
|-----|-------|------|-------------|
| 1 | `threshold` | uint (u8) | ≥ 1; ≤ sum of member weights |
| 2 | `members` | array of MultisigMember maps | 2–24 entries |
| 3 | `policy_version` | uint (u32) | monotonically increasing; starts at 1 |

CBOR map keys MUST appear in ascending numeric order. No other keys are permitted.

### 7.2 MultisigMember

`MultisigMember` represents one authorized co-signer within a `MultisigPolicy`.

**Constraints:**
- `alg_id` MUST reference an algorithm in the Algorithm Registry with `lifecycle_status ∈ {active, discouraged}` and MUST NOT be `0xFFFF` (nesting multisig inside multisig is not permitted)
- `public_key` length MUST equal `Algorithm_Registry[alg_id].pk_size`
- `weight` MUST be ≥ 1

#### 7.2.1 CBOR Encoding

`MultisigMember` is encoded as a deterministic CBOR map with integer keys:

| Key | Field | Type | Constraints |
|-----|-------|------|-------------|
| 1 | `address` | bstr (32 B) | co-signer's on-chain account address |
| 2 | `alg_id` | uint (u16) | MUST be a non-Multisig AlgId in the Registry |
| 3 | `public_key` | bstr | length = `Registry[alg_id].pk_size` |
| 4 | `weight` | uint (u8) | 1–255; default 1 |

CBOR map keys MUST appear in ascending numeric order. No other keys are permitted.

### 7.3 MultisigWitness

`MultisigWitness` replaces the `signature` field (key 12) in the SPEC-TX-001 transaction envelope when `sig_alg_id = 0xFFFF`. The `signature` field still uses key 12 and MUST contain the CBOR encoding of `MultisigWitness` as a byte string.

**Constraints:**
- `multisig_account` MUST match a multisig account address in the StateStore
- `signatures` MUST contain at least 1 entry
- `signatures` MUST NOT contain duplicate `member_index` values; duplicates MUST be rejected with `DuplicateMemberIndex`
- Each `member_index` MUST be a valid index into `MultisigPolicy.members` (0-based, < len(members)); out-of-range indices MUST be rejected with `InvalidMemberIndex`
- Each `sig_bytes` length MUST equal `Registry[members[member_index].alg_id].sig_size`

#### 7.3.1 CBOR Encoding

`MultisigWitness` is encoded as a deterministic CBOR map with integer keys, then wrapped as a byte string for key 12 of the envelope:

| Key | Field | Type | Constraints |
|-----|-------|------|-------------|
| 1 | `multisig_account` | bstr (32 B) | multisig account address |
| 2 | `signatures` | array of [uint (u8), bstr] arrays | (member_index, sig_bytes) pairs; ordered by member_index ascending |

`signatures` is an array of 2-element CBOR arrays, each containing `[member_index: uint, sig_bytes: bstr]`. The array MUST be sorted in ascending order of `member_index`. This ordering requirement is part of the canonical encoding; witnesses with unsorted signature entries MUST be rejected with `ENCODING_NOT_CANONICAL`.

CBOR map keys MUST appear in ascending numeric order. No other keys are permitted.

#### 7.3.2 Key 12 Encoding Rule

The `signature` field (key 12) of the SPEC-TX-001 envelope MUST contain:

```
key_12_bytes = cbor_encode(MultisigWitness_map)
```

The canonical CBOR bytes of `MultisigWitness` are the value of key 12 — not the map nested directly in the envelope map, but the bytes of the encoded map wrapped as a CBOR byte string. This preserves the `bstr` type contract of key 12 established by SPEC-TX-001.

---

## 8. New Account Address Derivation

A multisig account address is derived deterministically from the creating sender and nonce. No key material is hashed; the address is purely positional.

```
new_account_address = SHAKE-256(
    "VIPER-MULTISIG-V1" || sender || nonce_be64,
    32
)
```

Where:
- `"VIPER-MULTISIG-V1"` is the domain separator, encoded as a UTF-8 byte string (17 bytes), no CBOR wrapper
- `sender` is the 32-byte address of the account submitting the `MultisigCreate` transaction
- `nonce_be64` is the `nonce` field of the `MultisigCreate` transaction encoded as an 8-byte big-endian unsigned integer
- The output is 32 bytes (256 bits of SHAKE-256 output)

The resulting address is stored in the `new_account_address` field of the `MultisigCreate` payload (§9.1) and is independently verifiable by any node from the transaction fields.

**Collision resistance.** Because `(sender, nonce)` pairs are unique per account (nonce is monotonically increasing and a sender cannot reuse a nonce), the derived address is unique. A sender cannot create two multisig accounts at the same address.

**Address stability.** A multisig account address is fixed at creation. `MultisigPolicyUpdate` does not change the address.

---

## 9. Payload Specifications

### 9.1 MultisigCreate Payload (msg_type = 0x0600)

`MultisigCreate` is a transaction submitted by an ordinary single-key account (the "creator") that funds and initializes a new multisig account.

The `payload` field of the SPEC-TX-001 envelope MUST contain a deterministic CBOR map encoding the following fields:

| Key | Field | Type | Constraints |
|-----|-------|------|-------------|
| 1 | `members` | array of MultisigMember maps | 2–24 entries; see §7.2 |
| 2 | `threshold` | uint (u8) | ≥ 1; ≤ sum of member weights |
| 3 | `initial_balance` | uint (u64) | amount in venom to transfer from creator to new account; may be 0 |
| 4 | `new_account_address` | bstr (32 B) | MUST equal the address derived per §8 |

CBOR map keys MUST appear in ascending numeric order. No other keys are permitted.

**Validation notes:**
- The node MUST independently compute `new_account_address` per §8 using `tx.sender` and `tx.nonce`. If the computed value does not match the declared `new_account_address`, the transaction MUST be rejected with `InvalidNewAccountAddress`.
- `initial_balance` MUST be ≤ `creator.balance - tx.fee - tx.fee_tip`. If not, reject with `INSUFFICIENT_BALANCE`.
- If a multisig account at `new_account_address` already exists, reject with `AccountAlreadyExists`.

### 9.2 MultisigPolicyUpdate Payload (msg_type = 0x0601)

`MultisigPolicyUpdate` changes the threshold and/or member list of an existing multisig account. The transaction itself MUST be a multisig transaction from that account — i.e., `tx.sender` MUST be the multisig account address, `tx.sig_alg_id` MUST be `0xFFFF`, and `MultisigWitness.multisig_account` MUST equal `tx.sender`. The current policy's threshold MUST be met to authorize the update.

The `payload` field of the SPEC-TX-001 envelope MUST contain a deterministic CBOR map encoding the following fields:

| Key | Field | Type | Constraints |
|-----|-------|------|-------------|
| 1 | `new_threshold` | uint (u8) | ≥ 1; ≤ sum of new member weights |
| 2 | `new_members` | array of MultisigMember maps | 2–24 entries; see §7.2 |
| 3 | `policy_version` | uint (u32) | MUST equal current `policy_version + 1` |

CBOR map keys MUST appear in ascending numeric order. No other keys are permitted.

**Validation notes:**
- If `policy_version ≠ current_policy.policy_version + 1`, reject with `PolicyVersionConflict`.
- The `new_threshold` and `new_members` together form the replacement policy. The old policy is fully replaced; partial updates (add one member, remove one member) are performed by restating the full new member list.
- A `MultisigPolicyUpdate` that would replace all current signing members with new ones is permitted. The authorization uses the current (pre-update) policy.

---

## 10. Validation Algorithm

When `tx.sig_alg_id = 0xFFFF`, the standard SPEC-TX-001 validation pipeline (steps 9–12) is replaced by the multisig validation path defined in this section. All other steps in the SPEC-TX-001 pipeline (structural, encoding, nonce, fee) apply unchanged.

### 10.1 Preconditions (applied before multisig-specific steps)

These steps from SPEC-TX-001 §10 apply without change:

| Step | Check | Rejection code |
|------|-------|---------------|
| 1 | CBOR is well-formed | `ENCODING_ERROR` |
| 2 | Deterministic CBOR rules satisfied | `ENCODING_NOT_CANONICAL` |
| 3 | All required fields present; no unknown keys | `MISSING_FIELD` / `UNKNOWN_FIELD` |
| 4 | `tx_version` is recognized | `UNSUPPORTED_VERSION` |
| 5 | `chain_id` matches local network | `CHAIN_ID_MISMATCH` |
| 6 | `msg_type` is recognized (must be `0x0600` or `0x0601`) | `UNSUPPORTED_MSG_TYPE` |
| 7 | `sender` is exactly 32 bytes | `INVALID_SENDER` |
| 8 | `payload` is valid CBOR and does not exceed 1 MB | `PAYLOAD_INVALID` / `PAYLOAD_TOO_LARGE` |

### 10.2 Multisig Validation Steps

Execute the following steps in order. A failure at any step MUST result in immediate rejection with the stated error code. Steps MUST NOT be reordered.

| Step | Check | Rejection code |
|------|-------|---------------|
| M-01 | `sig_alg_id = 0xFFFF` and `registry[0xFFFF].lifecycle_status = active` | `UNSUPPORTED_ALGORITHM` |
| M-02 | `signature` field (key 12) is a valid CBOR byte string containing a well-formed `MultisigWitness` map | `ENCODING_ERROR` |
| M-03 | `MultisigWitness.multisig_account` is exactly 32 bytes | `ENCODING_ERROR` |
| M-04 | A multisig account exists at `MultisigWitness.multisig_account` in the StateStore | `INVALID_SENDER` |
| M-05 | For `MultisigPolicyUpdate` only: `tx.sender = MultisigWitness.multisig_account` | `INVALID_SENDER` |
| M-06 | `MultisigWitness.signatures` is non-empty | `InsufficientQuorum` |
| M-07 | `MultisigWitness.signatures` is sorted in ascending order of `member_index` | `ENCODING_NOT_CANONICAL` |
| M-08 | All `member_index` values are in range `[0, len(policy.members))` | `InvalidMemberIndex` |
| M-09 | No duplicate `member_index` values in `MultisigWitness.signatures` | `DuplicateMemberIndex` |
| M-10 | For each `(member_index, sig_bytes)`: `len(sig_bytes) = Registry[policy.members[member_index].alg_id].sig_size` | `InvalidMemberSignature` |
| M-11 | For each `(member_index, sig_bytes)`: `verify(policy.members[member_index].public_key, build_preimage(tx), sig_bytes)` using `policy.members[member_index].alg_id` succeeds | `InvalidMemberSignature` |
| M-12 | `weight_sum = Σ policy.members[member_index].weight` for each entry in `MultisigWitness.signatures` | — |
| M-13 | `weight_sum ≥ policy.threshold` | `InsufficientQuorum` |

Step M-11 MUST be performed after steps M-08 through M-10 to ensure signature buffers are properly sized before verification. Nodes MUST NOT pass an incorrectly sized buffer to the signature verifier.

After step M-13, validation continues with the standard SPEC-TX-001 steps 13–15 (nonce, fee, rate limit).

### 10.3 Algorithm Registry Check for Member Keys

During step M-11, if any member's `alg_id` has `lifecycle_status = deprecated` or `banned`, the verification for that member MUST be rejected with `InvalidMemberSignature`. A multisig transaction authorized by a member using a deprecated or banned algorithm is not valid even if the signature bytes are mathematically correct. This ensures that algorithm deprecation applies to multisig members as well as to transaction-level signers.

If a member's `alg_id` has `lifecycle_status = discouraged`, the signature is accepted but the node SHOULD log a warning.

---

## 11. Signature Preimage

The signature preimage for each member's signature is **identical to single-sig**. Members sign the same preimage that a single-key sender would sign for the same transaction envelope.

```
preimage = "PQC-TX-V1" || canonical_cbor({
  1: tx_version,
  2: chain_id,
  3: msg_type,
  4: sender,           -- the multisig account address
  5: nonce,
  6: fee,
  7: fee_tip,          -- 0 if omitted in the envelope
  8: gas_limit,
  9: payload,
  10: sig_alg_id,      -- 0xFFFF
  11: sig_key_version  -- 0 for multisig accounts (see §11.1)
})
```

This is identical to the SPEC-TX-001 §8 preimage construction. The `signature` field (key 12) is excluded from the preimage.

**Rationale for identical preimage:** Members can sign with their existing local signing stack (ML-DSA, SLH-DSA, etc.) without any protocol-specific modifications. The signing primitive is unchanged. Only the assembly and submission of multiple signatures requires multisig-aware client tooling.

### 11.1 sig_key_version for Multisig

A multisig account has no KeySet in the SPEC-ACCOUNT-001 sense. The `sig_key_version` field in the envelope MUST be set to `0` for multisig transactions. Verifiers MUST NOT attempt to look up key version 0 in any KeySet for a multisig account; instead, the multisig validation path (§10) applies exclusively.

Setting `sig_key_version` to any value other than `0` in a multisig transaction MUST be rejected with `KEY_NOT_FOUND` at step 11 of the standard pipeline, before the multisig path is entered. This prevents confusion between key version lookup and policy lookup.

---

## 12. Gas and Fee Model

### 12.1 Gas Costs

| Operation | Base gas | Per-member gas | Notes |
|-----------|----------|----------------|-------|
| `MultisigCreate` (0x0600) | 20 | +5 per member (N = total members in policy) | Charged for N members regardless of how many sign the creation tx |
| `MultisigPolicyUpdate` (0x0601) | 15 | +5 per member (N = total members in new policy) | Charged for new policy member count |

Gas cost formula:

```
gas_multisig_create    = 20 + 5 × N
gas_multisig_update    = 15 + 5 × N
```

Where `N` is the number of members in the policy being created or installed.

These values are initial constants in `pqc-state::gas_schedule` alongside the values in SPEC-FEE-001 §4.4. They MUST be declared in the per-operation gas schedule table in SPEC-FEE-001 §4.4.

### 12.2 Signature Verification Fee

A multisig transaction requires verifying `k` signatures (where `k` = number of entries in `MultisigWitness.signatures`, and `k` ≤ m). The effective signature verification fee is the sum of individual member verification fees:

```
effective_sigverify_fee_multisig =
    Σ effective_sigverify_fee(policy.members[member_index].alg_id)
    for each (member_index, _) in MultisigWitness.signatures
```

Where `effective_sigverify_fee(alg_id)` uses the same derivation as SPEC-FEE-001 §5.1.

The fee formula for a multisig transaction is therefore:

```
min_fee = base_fee
        + byte_fee × tx_bytes
        + effective_sigverify_fee_multisig
        + exec_fee_per_gas × gas_limit
```

The `sig_alg_id = 0xFFFF` entry in the Algorithm Registry has `min_fee = 0` because the per-member fees already account for the full verification cost. Nodes MUST NOT apply the standard `sigverify_fee[0xFFFF]` lookup for multisig transactions; they MUST compute the sum as above.

### 12.3 Byte Fee

`tx_bytes` is the canonical CBOR byte length of the full transaction including the `signature` field (which contains the encoded `MultisigWitness`). A 2-of-3 ML-DSA-65 multisig transaction carries approximately:

- `MultisigWitness` overhead: ~50 bytes
- 2 × 3,309 bytes of ML-DSA-65 signatures: 6,618 bytes
- Total signature contribution to `tx_bytes`: ~6,668 bytes
- At `byte_fee = 2`: ~13,336 units of byte fee from signatures alone

This is the natural pricing effect described in ADR-033: no special multisig byte fee is needed because the byte fee already applies uniformly to all transaction bytes.

---

## 13. Execution: State Mutations

### 13.1 MultisigCreate Execution

On successful validation of a `MultisigCreate` transaction, the following state changes MUST be applied atomically:

1. Derive `new_account_address` per §8 and confirm it matches the payload field (already validated in §10.1).
2. Create a new entry in the MultisigAccountMap (§16.1) keyed by `new_account_address` with:
   - `policy = MultisigPolicy { threshold, members, policy_version: 1 }`
   - `balance = payload.initial_balance`
   - `nonce = 0`
3. Debit `payload.initial_balance + tx.fee + tx.fee_tip` from the creator account (`tx.sender`).
4. Increment `tx.sender.nonce` by 1.

If any of these mutations would violate an account invariant (e.g. creator balance goes negative), the entire transaction MUST be reverted with `INSUFFICIENT_BALANCE`. No partial state changes are permitted.

### 13.2 MultisigPolicyUpdate Execution

On successful validation of a `MultisigPolicyUpdate` transaction:

1. Load the current `MultisigPolicy` for `tx.sender` from the MultisigAccountMap.
2. Verify `payload.policy_version = current_policy.policy_version + 1` (already checked at M-10 of validation; this is the execution confirmation).
3. Replace the stored `MultisigPolicy` with:
   - `threshold = payload.new_threshold`
   - `members = payload.new_members`
   - `policy_version = payload.policy_version`
4. Debit `tx.fee + tx.fee_tip` from `tx.sender` (the multisig account's balance).
5. Increment `tx.sender.nonce` by 1 in the multisig account's state.

The account address and balance (beyond the fee debit) are unchanged.

---

## 14. StateStore Additions

### 14.1 MultisigAccountMap

A new state collection, `MultisigAccountMap`, is added to the StateStore. It is distinct from the regular `AccountMap` used by single-key accounts.

| Collection | Key | Value |
|------------|-----|-------|
| `MultisigAccountMap` | `[u8; 32]` (multisig account address) | CBOR-encoded `MultisigAccountState` |

`MultisigAccountState` is defined as:

| Key | Field | Type |
|-----|-------|------|
| 1 | `address` | bstr (32 B) |
| 2 | `balance` | uint (u128) |
| 3 | `nonce` | uint (u64) |
| 4 | `policy` | MultisigPolicy map (see §7.1.1) |

This is CBOR-encoded deterministically using integer keys in ascending order.

### 14.2 State Root Integration

Multisig account state MUST be included in the global state root computation. Each `MultisigAccountState` entry contributes a leaf hash using the domain string `"VIPER-MULTISIG-LEAF-V1"`:

```
leaf_hash = SHAKE-256("VIPER-MULTISIG-LEAF-V1" || address || cbor_encode(MultisigAccountState), 32)
```

All leaf hashes (from both `AccountMap` and `MultisigAccountMap`) are sorted and combined per the existing state root derivation procedure (PQC-STATE-ROOT-V2). No change to the root derivation algorithm is required; multisig accounts are additional leaves.

Changing the `"VIPER-MULTISIG-LEAF-V1"` domain string, the sort order, or the hash algorithm would break replay determinism across nodes and requires a new ADR and coordinated upgrade path (per Phase 4 rules in AGENTS.md).

### 14.3 Address Namespace Separation

A multisig account address and a single-key account address occupy the same 32-byte address space. It is possible (though statistically negligible) for a derived multisig address to collide with an existing single-key account address. The node MUST check both `AccountMap` and `MultisigAccountMap` during `MultisigCreate` execution and MUST reject with `AccountAlreadyExists` if either map contains the derived address.

Validation at mempool admission MUST also check for this collision.

---

## 15. Error Codes

The following error codes are introduced by this specification. They extend the error code set defined in SPEC-TX-001 and SPEC-ACCOUNT-001.

| Code | Name | When raised |
|------|------|-------------|
| `E-MS-001` | `InsufficientQuorum` | `weight_sum < policy.threshold` (step M-13); or `signatures` is empty (step M-06) |
| `E-MS-002` | `DuplicateMemberIndex` | `MultisigWitness.signatures` contains two entries with the same `member_index` |
| `E-MS-003` | `InvalidMemberSignature` | Signature verification fails for a member (step M-11); or sig_bytes length is wrong (step M-10); or member alg_id is deprecated/banned |
| `E-MS-004` | `PolicyVersionConflict` | `payload.policy_version ≠ current_policy.policy_version + 1` in `MultisigPolicyUpdate` |
| `E-MS-005` | `MemberCountExceedsMax` | `len(members) > 24` in policy creation or update |
| `E-MS-006` | `InvalidMemberIndex` | A `member_index` in `MultisigWitness.signatures` is ≥ `len(policy.members)` |
| `E-MS-007` | `InvalidNewAccountAddress` | Declared `new_account_address` does not match the value derived per §8 |
| `E-MS-008` | `AccountAlreadyExists` | A multisig or single-key account already exists at the derived address |
| `E-MS-009` | `DuplicateMemberAddress` | Two members within the same policy share the same `address` |
| `E-MS-010` | `NestedMultisig` | A member's `alg_id = 0xFFFF` (multisig-in-multisig is not permitted) |
| `E-MS-011` | `ThresholdExceedsWeightSum` | `threshold > Σ weight` over all members |
| `E-MS-012` | `InvalidMemberKeySize` | A member's `public_key` length does not match `Registry[member.alg_id].pk_size` |

---

## 16. API Extensions

### 16.1 GET /v1/accounts/{address}

The existing `GET /v1/accounts/{address}` endpoint (API.md §GET /v1/accounts/{address}) is extended to detect multisig accounts and return their policy in addition to standard fields.

When `address` resolves to an entry in `MultisigAccountMap`, the response MUST include a `multisig_policy` object in addition to the standard fields. The `keys` array MUST be omitted for multisig accounts (they have no KeySet).

**Response `data` for a multisig account:**

```json
{
  "address": "<64-char lowercase hex>",
  "balance": "<decimal string>",
  "nonce": 5,
  "account_type": "multisig",
  "multisig_policy": {
    "threshold": 2,
    "policy_version": 1,
    "members": [
      {
        "address": "<64-char lowercase hex>",
        "alg_id": 2,
        "alg_name": "ML-DSA-65",
        "pk_hex": "<hex>",
        "weight": 1
      },
      {
        "address": "<64-char lowercase hex>",
        "alg_id": 2,
        "alg_name": "ML-DSA-65",
        "pk_hex": "<hex>",
        "weight": 1
      },
      {
        "address": "<64-char lowercase hex>",
        "alg_id": 2,
        "alg_name": "ML-DSA-65",
        "pk_hex": "<hex>",
        "weight": 1
      }
    ]
  }
}
```

For single-key accounts, the existing response shape is unchanged. `account_type` MUST be `"standard"` for single-key accounts and `"multisig"` for multisig accounts. This field is additive and does not break existing clients that ignore unknown fields.

**404** if neither `AccountMap` nor `MultisigAccountMap` contains the address.

### 16.2 No New Endpoints

No new top-level API endpoints are introduced by this specification. Policy discovery is fully served by the existing `GET /v1/accounts/{address}` endpoint with the extension defined above.

---

## 17. Threshold-Ready Upgrade Path

ADR-033 explicitly designs for upgrade to PQ threshold signatures when Quorus, TOPCOAT, or a successor scheme reaches production standardization. This section documents the intended migration path.

### 17.1 Current Architecture

When `sig_alg_id = 0xFFFF`, validation requires `k` full member signatures in `MultisigWitness`. Wire size scales as `O(k × sig_size)`.

### 17.2 Future Architecture (PQ Threshold, AlgId 0xFFFE)

When a PQ threshold signature scheme standardizes:

1. A new AlgId `0xFFFE` (proposed; assigned by governance via Algorithm Registry registration) is added, referencing the standardized PQ threshold scheme.
2. A new `ThresholdWitness` structure replaces `MultisigWitness` for that AlgId. It carries a single compact threshold signature instead of k individual signatures.
3. The `MultisigPolicy` structure is reused without change: the same n-of-m semantics apply at the key management level.
4. No changes to the account model, address derivation, or `MultisigAccountMap` are required.
5. Existing multisig accounts migrate by submitting a `MultisigPolicyUpdate` transaction that switches to a new policy where `threshold = T` and `members = [threshold_key]` (a single threshold public key). Alternatively, the update may retain the same member list but change their keys to use the new AlgId once a threshold keygen protocol generates the distributed key material.

### 17.3 Coexistence

`AlgId 0xFFFF` (n-of-m) and `AlgId 0xFFFE` (PQ threshold) MAY coexist during the transition period. Existing multisig accounts are not forced to migrate immediately. Governance MAY eventually deprecate `0xFFFF` via the standard four-step process (SPEC-ACCOUNT-001 §6.4).

### 17.4 No Account Migration

The multisig account address is derived from `(sender, nonce)`, not from key material. Switching from n-of-m to PQ threshold does not require creating a new account or transferring balances. The account address, nonce, and balance all persist across policy updates.

---

## 18. Security Considerations

### 18.1 Weight Sum Overflow

`threshold` is `u8` (max 255). `weight` is `u8` per member (max 255). With up to 24 members, the maximum possible weight sum is `24 × 255 = 6,120`, which exceeds `u8` range. Implementations MUST compute the weight sum as `u32` or larger to avoid overflow. Validation MUST reject if `threshold > weight_sum` where `weight_sum` is the full u32 sum.

### 18.2 Member Key Reuse

Members MUST use their existing on-chain account keys; however, the `public_key` field in `MultisigMember` is a copy of that key at policy creation time. It is possible for a member to rotate their key on-chain after being added to a multisig policy — their old key will still be stored in the policy and required for signing until a `MultisigPolicyUpdate` is submitted. Implementations SHOULD warn clients about this potential divergence. Policy updates are the correct remedy, not key reuse prevention.

### 18.3 No Timing Leakage on Verification Failure

Implementations MUST verify all signatures in `MultisigWitness.signatures` using constant-time verification primitives (as required by the underlying FIPS 204 / FIPS 205 implementations). Returning `InvalidMemberSignature` after verifying k signatures MUST NOT reveal which specific index failed through timing differences. The error code MUST be the same regardless of which member's signature is invalid.

### 18.4 Signature Aggregation Off-Chain

Members sign independently and their signatures are assembled off-chain before submission. The assembler (typically the transaction initiator or a coordinator) sees all member signatures before the transaction is submitted. This is not a security concern — the preimage is public, and each member's signature only proves knowledge of their private key over that preimage. There is no key material in the witness.

### 18.5 Replay of Witness Across Transactions

A `MultisigWitness` is bound to a specific transaction via the preimage (which includes `sender`, `nonce`, `chain_id`, `msg_type`, and `payload`). A witness cannot be replayed for a different transaction or on a different chain. The `nonce` increment after execution additionally prevents reuse of the same nonce.

### 18.6 DoS via Large Member Count

A policy with 24 members and a threshold of 24 requires verifying 24 full ML-DSA-65 signatures per transaction. At 3,309 bytes per signature, the witness alone is ~79 KB. The gas cost (20 + 5×24 = 140 gas for creation; 24 × `sigverify_fee_v_b` for verification) ensures this is economically priced. Nodes MUST enforce the 24-member cap at mempool admission, not only at execution, to prevent witness parsing overhead for oversized policies.

---

## 19. Implementation Checklist

The following items MUST be completed before this specification is considered implemented.

**Data types (`pqc-types`):**
- [ ] `MultisigPolicy` struct with CBOR encode/decode (field numbers per §7.1.1)
- [ ] `MultisigMember` struct with CBOR encode/decode (field numbers per §7.2.1)
- [ ] `MultisigWitness` struct with CBOR encode/decode (field numbers per §7.3.1); enforce ascending `member_index` sort on decode
- [ ] `MultisigAccountState` struct with CBOR encode/decode (§14.1)
- [ ] Error variants for all codes in §15

**Algorithm Registry (`pqc-state`):**
- [ ] Add `AlgId::Multisig = 0xFFFF` to the AlgId enum and Algorithm Registry initial state
- [ ] Algorithm Registry entry per §6.1 with `pk_size = 0`, `sig_size = 0`

**Address derivation (`pqc-types` or `pqc-crypto`):**
- [ ] `derive_multisig_address(sender: [u8;32], nonce: u64) -> [u8;32]` per §8
- [ ] Unit test: known-answer test against a fixed `(sender, nonce)` pair

**Validation pipeline (`pqc-tx::validate`):**
- [ ] Detect `sig_alg_id = 0xFFFF` and route to multisig validation path
- [ ] Implement all steps M-01 through M-13 in §10.2 in declared order
- [ ] Implement `sig_key_version = 0` enforcement (§11.1)
- [ ] Compute `effective_sigverify_fee_multisig` per §12.2 for fee sufficiency check
- [ ] No `unwrap()` or `expect()` in validation path (Phase 4 rule)

**Execution (`pqc-state::apply`):**
- [ ] `MultisigCreate` state mutations per §13.1 (atomic; creator balance debit, new account creation)
- [ ] `MultisigPolicyUpdate` state mutations per §13.2 (atomic; policy replacement, fee debit, nonce increment)
- [ ] Both operations use u32 weight sum arithmetic (§18.1)
- [ ] Address collision check against both `AccountMap` and `MultisigAccountMap`

**State root (`pqc-state`):**
- [ ] `MultisigAccountMap` leaf hash using domain `"VIPER-MULTISIG-LEAF-V1"` per §14.2
- [ ] Leaves sorted and merged with `AccountMap` leaves before root computation
- [ ] No change to root derivation algorithm needed; verify composite root is deterministic

**Gas schedule (`pqc-state::gas_schedule`):**
- [ ] `GAS_MULTISIG_CREATE = 20 + 5 × N` constant/function per §12.1
- [ ] `GAS_MULTISIG_UPDATE = 15 + 5 × N` constant/function per §12.1
- [ ] Add to SPEC-FEE-001 §4.4 gas schedule table

**API (`pqcd::api`):**
- [ ] `GET /v1/accounts/{address}` handler: check `MultisigAccountMap` if not found in `AccountMap`
- [ ] Return `account_type: "multisig"` and `multisig_policy` object per §16.1
- [ ] Omit `keys` array for multisig accounts
- [ ] Existing single-key account response unchanged

**Tests:**
- [ ] Unit: `derive_multisig_address` known-answer
- [ ] Unit: `MultisigWitness` CBOR round-trip; reject non-ascending `member_index`
- [ ] Unit: weight sum overflow safety (24 members, weight 255 each)
- [ ] Integration: `MultisigCreate` end-to-end with state commit; verify state root changes
- [ ] Integration: `MultisigPolicyUpdate` with quorum met; verify policy replaced
- [ ] Integration: `MultisigPolicyUpdate` with quorum not met; verify `InsufficientQuorum`
- [ ] Integration: `PolicyVersionConflict` on stale version number
- [ ] Integration: duplicate member index in witness; verify `DuplicateMemberIndex`
- [ ] Integration: deprecated member alg_id; verify `InvalidMemberSignature`
- [ ] Integration: 2-of-3 multisig with correct 2 signatures; end-to-end acceptance
- [ ] Integration: 2-of-3 multisig with only 1 signature; verify `InsufficientQuorum`
- [ ] Audit: no secret material in error messages or tracing events (Phase 4 rule)
- [ ] Audit: constant-time path from `InvalidMemberSignature` regardless of which index fails

**Documentation:**
- [ ] SPEC-TX-001 §5.3 amended to add `0x0600–0x06FF` multisig range
- [ ] SPEC-ACCOUNT-001 Algorithm Registry initial table updated with `0xFFFF` entry
- [ ] SPEC-FEE-001 §4.4 gas schedule table updated with multisig operations
- [ ] API.md `GET /v1/accounts/{address}` response updated with `account_type` and `multisig_policy` fields
- [ ] CHANGELOG.md updated

---

## 20. Audit Scope

All code implementing this specification is in scope for the Phase 4 cryptographic audit:

| Component | Audit scope | Reason |
|-----------|-------------|--------|
| `pqc-types`: MultisigPolicy, MultisigMember, MultisigWitness encode/decode | Yes | Wire format correctness |
| `pqc-tx::validate`: multisig path (steps M-01 to M-13) | Yes | Signature verification and quorum logic |
| `pqc-state::apply`: MultisigCreate, MultisigPolicyUpdate | Yes | State mutation correctness |
| `pqc-state`: state root with MultisigAccountMap | Yes | Replay determinism |
| `derive_multisig_address` | Yes | Address derivation uniqueness |
| `pqcd::api`: account endpoint extension | No | Read-only; no crypto path |

---

## 21. Open TBDs

| ID | Item | Blocking? |
|----|------|-----------|
| TBD-MS-01 | Maximum transaction size with a 24-member all-ML-DSA-87 witness is ~112 KB; confirm this is below the 1 MB SPEC-TX-001 payload cap and does not require a separate witness size limit | No — well within 1 MB; document explicitly in a future spec revision |
| TBD-MS-02 | Fee calibration for `effective_sigverify_fee_multisig`: the sum of k `sigverify_fee_v_b` values is correct in theory, but pipelining multiple ML-DSA verifications on the same core may differ from k × single-verify latency; measure during Phase 4 benchmarks | No — conservative (additive) pricing is safe until measured |
| TBD-MS-03 | `sig_key_version = 0` is used as a sentinel for multisig; confirm this does not conflict with any future batch-nonce or account-abstraction spec that might also need a special key_version value | No — deferred to Phase 5 account abstraction ADR |
| TBD-MS-04 | `AlgId 0xFFFE` for PQ threshold: reserve the value now in the Algorithm Registry with `lifecycle_status = inactive` (not yet defined) to prevent future collision | Proposed — governance vote needed |
| TBD-MS-05 | Weight-sum weighted quorum is present in the spec but weighted voting requires client tooling support; confirm SDK (sdk/) includes weight-aware witness assembly helper | No — SDK update deferred to implementation phase |

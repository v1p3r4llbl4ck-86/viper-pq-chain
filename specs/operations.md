# Built-In Operation Types Specification

**Spec ID**: SPEC-OPS-001  
**Version**: 0.2  
**Status**: Draft  
**History**: v0.1 2026-04-09; v0.2 banner added 2026-04-25 after the `viper-pq-1` launch (chain since retired).  
**Date**: 2026-04-25  
**Depends on**: ADR-012 (Phase 1 scope), SPEC-TX-001, SPEC-ACCOUNT-001, SPEC-FEE-001, ADR-045 (archival overlay), ADR-053 §T3.5 (verifier_template_id)

> **Revision banner (2026-04-25)**: this spec covers the Phase-1 op families (vault / attestation / governance / key-management). Two newer op families landed in code post-Phase-1 and are not yet documented in the body below — refer to the implementing TASKs for shape until the v0.3 revision lands:
> - **`0x0700..0x0703` Archival overlay** (M4 / ADR-045 / TASK-160..165, commits `85c8343..f722226`): `ArchivalRecordCreate`, `ArchivalRecordAddAnchor`, `ArchivalRecordRenew`, `ArchivalRecordRevoke`. SLH-DSA-SHAKE-256s required (`allowed_for_archival` predicate, ADR-046 / TASK-162). Schema in `crates/pqc-types/src/archival.rs`.
> - **`0x0405 ValidatorRegisterArchivalKey`** (M4 / TASK-163, `e8fbe4d`): operator binds an SLH-DSA archival public key to their validator address; required before submitting `ArchivalRecord*` ops on behalf of the chain.
> 
> Additionally, ADR-053 §T3.5 introduces a per-account `verifier_template_id` field; at launch only the EOA template (id `0x0001`) is wired, but `ProposalEffect::AddAuthTemplate` reserves the on-chain registry slot for future templates. The op-list framing in this spec assumes the EOA template; the v0.3 revision will document the dispatch surface for non-EOA templates.

---

## 1. Scope

This document specifies the built-in operation types available in PQ Chain Phase 1. Each operation is a discrete protocol action identified by a `msg_type` value in the transaction envelope and executed by the protocol's built-in execution layer.

Phase 1 operations cover four families:

| Family | msg_type range | Purpose |
|--------|---------------|---------|
| Vault | `0x0001–0x00FF` | account creation, policy, token transfer |
| Attestation | `0x0100–0x01FF` | attestation anchoring, proof records |
| Key management | `0x0200–0x02FF` | key add, rotate, revoke; consensus key rotation |
| Governance (reserved) | `0x0300–0x03FF` | governance operations; full spec in TASK-010 |

There is no generic VM in Phase 1. Every executable action is a built-in type defined in this document or a future spec revision. Unknown `msg_type` values MUST be rejected at mempool admission (`UNSUPPORTED_MSG_TYPE`).

This specification does not define:

- governance vote mechanics — deferred to SPEC-GOV (TASK-010)
- token economics, staking, and reward distribution — deferred to TASK-011
- API transport encoding for these operations — defined in API.md (TASK-008)
- final gas cost values — TBD Phase 2; gas tiers (L/M/H) are defined here as relative ordering only

---

## 2. Normative Language

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT, RECOMMENDED, MAY, and OPTIONAL in this document are to be interpreted as described in RFC 2119.

---

## 3. Normative References

| Reference | Document |
|-----------|----------|
| ADR-012 | Phase 1 scope: vault + attestations, no native RWA tokenization |
| SPEC-TX-001 | Transaction Envelope — msg_type namespace, validation pipeline |
| SPEC-ACCOUNT-001 | Account, KeySet, Algorithm Registry — state and rules |
| SPEC-FEE-001 | Fee model — gas tiers and effective fee derivation |

---

## 4. Conventions

### 4.1 Payload Schema Notation

Payload schemas are described as CBOR maps with integer keys, consistent with SPEC-TX-001 deterministic encoding rules. Optional fields are marked `(optional)`. Fields marked `(reserved)` MUST be omitted in Phase 1; nodes MUST reject payloads that include reserved fields.

### 4.2 Signer Policy Notation

Each operation specifies a required signer policy as a combination of:

- which account's key must sign the envelope (`self`, `creator`, `operator`)
- which `allowed_tx_types` bit must be set in the signing key

Bit assignments (from SPEC-ACCOUNT-001 §5.3.6):

| Bit | Scope |
|-----|-------|
| 0 | vault operations |
| 1 | attestation and notarization |
| 2 | key management operations |
| 3 | governance operations |

### 4.3 Gas Tier Notation

Gas tiers indicate the relative execution complexity. Actual values are calibrated in Phase 2.

| Tier | Relative cost | Typical operations |
|------|--------------|-------------------|
| L | low | simple balance read/write, single state field update |
| M | medium | multi-field state writes, content hash storage |
| H | high | KeySet mutation, multi-step state transitions |

---

## 5. Vault Family (`0x0001–0x00FF`)

### 5.1 `vault_create` — `msg_type = 0x0001`

**Purpose**: explicitly creates a new account with a genesis key and optional initial metadata. An account may also be created implicitly when it receives a token transfer; this operation provides the explicit path with full genesis key control.

**Signer policy**: any existing active account with bit 0 set (`allowed_tx_types` includes vault operations). The creator account pays the fee. The created account is a distinct address.

**Payload schema**:

```
{
  1: alg_id,              -- uint(u16); algorithm for the genesis key
  2: pk_bytes,            -- bstr; public key of the genesis key
  3: allowed_tx_types,    -- uint(u32); permissions for the genesis key
  4: valid_from_height,   -- uint(u64); when the genesis key becomes active
  5: metadata_hash        -- (optional) bstr(32); SHAKE-256 of off-chain vault metadata
}
```

**Derived fields** (computed by the protocol, not provided by sender):
- `new_address = SHAKE-256(pk_bytes || uint16_be(alg_id) || uint32_be(1), 32)` where `key_version = 1` for the genesis key
- `new_account.nonce = 0`, `new_account.balance = 0`

**Preconditions**:
- `alg_id` MUST reference an active algorithm in the Algorithm Registry
- `len(pk_bytes)` MUST match `expected_pk_size(alg_id)`
- `valid_from_height` MUST be ≥ finalization height of this transaction
- if `alg_id` is SLH-DSA: `allowed_tx_types` MUST be `0x00000004` (key management only)
- `new_address` MUST NOT already exist in chain state

**State transition**:
- create account at `new_address` with `balance=0`, `nonce=0`
- add genesis key entry: `{alg_id, pk_bytes, key_version=1, valid_from_height, status=pending|active, allowed_tx_types}`

**Rejection conditions**:

| Condition | Code |
|-----------|------|
| `new_address` already in state | `ACCOUNT_EXISTS` |
| `alg_id` inactive or banned | `UNSUPPORTED_ALGORITHM` |
| SLH-DSA key with `allowed_tx_types ≠ 0x04` | `INVALID_KEY_PERMISSIONS` |
| `pk_bytes` size mismatch | `INVALID_KEY_SIZE` |
| `valid_from_height < finalization_height` | `INVALID_ACTIVATION_HEIGHT` |

**Gas tier**: M

---

### 5.2 `vault_policy_update` — `msg_type = 0x0002`

**Purpose**: records an updated vault policy commitment on-chain. The policy itself is stored off-chain; the protocol anchors only its hash. This supports spending limits, approved counterparties, time locks, or multi-sig requirements as off-chain-interpretable policy documents.

**Signer policy**: the vault account itself (`sender = vault_address`); signing key MUST have bit 0 set.

**Payload schema**:

```
{
  1: policy_version,      -- uint(u32); monotonically increasing policy version number
  2: policy_hash,         -- bstr(32); SHAKE-256 of the new policy document
  3: schema_id            -- (optional) bstr(32); identifies the policy schema version
}
```

**Preconditions**:
- `policy_version` MUST be strictly greater than the current on-chain `policy_version` for this account (prevents replay of old policies)
- `policy_hash` MUST be 32 bytes

**State transition**:
- update account's `policy_version` and `policy_hash`

**Rejection conditions**:

| Condition | Code |
|-----------|------|
| `policy_version ≤ current_policy_version` | `POLICY_VERSION_CONFLICT` |
| `len(policy_hash) ≠ 32` | `INVALID_HASH` |

**Gas tier**: L

---

### 5.3 `token_transfer` — `msg_type = 0x0003`

**Purpose**: transfers a token amount from the sender's account to a recipient account.

**Signer policy**: `sender` account; signing key MUST have bit 0 set.

**Payload schema**:

```
{
  1: recipient,           -- bstr(32); destination account address
  2: amount,              -- uint(u128); transfer amount in base units
  3: memo_hash            -- (optional) bstr(32); hash of optional memo stored off-chain
}
```

**Preconditions**:
- `amount` MUST be > 0
- `sender.balance ≥ amount + tx.fee + tx.fee_tip` (total outflow including fee)
- `recipient` address MUST be valid (32 bytes); it MAY not yet exist in state (implicit account creation)
- `sender ≠ recipient`

**State transition**:
- `sender.balance -= amount + fee_actual + fee_tip`
- if `recipient` does not exist: create account with `balance = amount`, `nonce = 0`, empty KeySet
- if `recipient` exists: `recipient.balance += amount`
- note: an implicitly created account (no genesis key) can only receive tokens; it cannot sign transactions until a key is registered via `vault_create` or `key_add`

**Rejection conditions**:

| Condition | Code |
|-----------|------|
| `amount = 0` | `INVALID_AMOUNT` |
| `sender.balance < amount + fee + tip` | `INSUFFICIENT_BALANCE` |
| `sender = recipient` | `SELF_TRANSFER` |
| `len(recipient) ≠ 32` | `INVALID_RECIPIENT` |

**Gas tier**: L

---

## 6. Attestation Family (`0x0100–0x01FF`)

### 6.1 `attestation_create` — `msg_type = 0x0100`

**Purpose**: anchors a cryptographically bound attestation on-chain. The attestation records that the signer asserts a specific claim about a subject, at a specific block height, with a specific content hash. The content itself is stored off-chain; the protocol stores only the commitment.

**Signer policy**: any account (`sender`); signing key MUST have bit 1 set (`allowed_tx_types` includes attestation operations).

**Payload schema**:

```
{
  1: subject,             -- bstr(32); address, external identifier hash, or content identifier
  2: attestation_type,    -- uint(u16); claim type code (see §6.1.1)
  3: content_hash,        -- bstr(32); SHAKE-256 of the attested content or claim document
  4: schema_id,           -- bstr(32); identifies the schema governing content_hash interpretation
  5: metadata_hash,       -- (optional) bstr(32); SHAKE-256 of off-chain metadata
  6: expires_at_height    -- (optional) uint(u64); if present, attestation is invalid after this height
}
```

**Attestation record** stored on-chain (in addition to payload fields):

```
{
  attestation_id:     tx_hash of this transaction (32 bytes)
  attester:           sender address
  anchor_height:      finalization block height
  status:             active | revoked
}
```

#### 6.1.1 Attestation Types (Phase 1)

| Value | Name | Description |
|-------|------|-------------|
| `0x0001` | `identity_claim` | attester claims a mapping between subject and an identity |
| `0x0002` | `document_notarization` | attester notarizes existence and content of a document at anchor_height |
| `0x0003` | `ownership_assertion` | attester asserts ownership of an off-chain asset identified by subject |
| `0x0004` | `custody_proof` | attester asserts custody of an asset (distinct from ownership) |
| `0x0005` | `metadata_anchor` | attester anchors asset metadata (e.g. description, provenance) without ownership claim |
| `0x0006` | `compliance_record` | attester records a compliance event or audit trail entry |
| `0x0000`, `0x8000–0xFFFF` | reserved | MUST NOT be used |

**Preconditions**:
- `len(subject) = 32`
- `len(content_hash) = 32`
- `len(schema_id) = 32`
- `attestation_type` MUST be a recognized value
- if `expires_at_height` is present: MUST be > finalization height

**State transition**:
- write attestation record indexed by `attestation_id = tx_hash`
- write secondary index: `(attester, anchor_height)` → `attestation_id`
- write secondary index: `(subject, attestation_type)` → `attestation_id` (supports subject lookups)

**Rejection conditions**:

| Condition | Code |
|-----------|------|
| Unrecognized `attestation_type` | `INVALID_ATTESTATION_TYPE` |
| `len(content_hash) ≠ 32` | `INVALID_HASH` |
| `expires_at_height ≤ finalization_height` | `INVALID_EXPIRY` |

**Gas tier**: M

---

### 6.2 `attestation_revoke` — `msg_type = 0x0101`

**Purpose**: marks a previously created attestation as revoked. Revocation is the attester's declaration that the claim no longer holds or was made in error. Revocation does not erase the original attestation record; it is an immutable append.

**Signer policy**: the original attester (`sender = attestation.attester`); signing key MUST have bit 1 set. A key with bit 2 set (key management) MAY also revoke, to allow revocation even if the bit 1 key has been rotated out.

**Payload schema**:

```
{
  1: attestation_id,          -- bstr(32); tx_hash of the attestation_create transaction
  2: revocation_reason_hash   -- (optional) bstr(32); SHAKE-256 of off-chain revocation reason document
}
```

**Preconditions**:
- `attestation_id` MUST reference an existing attestation in state
- the referenced attestation MUST have `status = active`
- `sender` MUST be the original attester of the referenced attestation

**State transition**:
- set `attestation[attestation_id].status = revoked`
- record `revocation_height` and `revoker` (= sender) on the attestation record
- the original attestation record and all indexes are preserved; only status changes

**Rejection conditions**:

| Condition | Code |
|-----------|------|
| `attestation_id` not found in state | `NOT_FOUND` |
| Attestation already revoked | `ALREADY_REVOKED` |
| `sender ≠ attestation.attester` | `UNAUTHORIZED` |

**Gas tier**: L

---

### 6.3 `proof_anchor` — `msg_type = 0x0102`

**Purpose**: a lightweight on-chain record for proofs of ownership, custody, or asset metadata that do not require the full attestation semantics. Optimized for high-volume anchoring workflows (e.g. custody ledgers, asset registries) where the claim is machine-readable and schema-bound.

Distinct from `attestation_create` in that it has a leaner on-chain footprint (no secondary indexes by default) and is intended for integration with off-chain verification systems.

**Signer policy**: any account (`sender`); signing key MUST have bit 1 set.

**Payload schema**:

```
{
  1: claim_type,          -- uint(u16); see §6.3.1
  2: asset_id_hash,       -- bstr(32); SHAKE-256 of the asset identifier
  3: proof_hash,          -- bstr(32); SHAKE-256 of the proof document or credential
  4: schema_id            -- (optional) bstr(32); schema governing proof_hash interpretation
}
```

**Proof anchor record** stored on-chain:

```
{
  anchor_id:       tx_hash of this transaction
  claimer:         sender address
  claim_type:      as declared
  asset_id_hash:   as declared
  proof_hash:      as declared
  anchor_height:   finalization height
}
```

#### 6.3.1 Claim Types (Phase 1)

| Value | Name |
|-------|------|
| `0x0001` | `ownership` |
| `0x0002` | `custody` |
| `0x0003` | `asset_metadata` |
| `0x0000`, `0x8000–0xFFFF` | reserved |

**Preconditions**:
- `claim_type` MUST be a recognized value
- `len(asset_id_hash) = 32`, `len(proof_hash) = 32`

**State transition**:
- write proof anchor record indexed by `anchor_id = tx_hash`

**Rejection conditions**:

| Condition | Code |
|-----------|------|
| Unrecognized `claim_type` | `INVALID_CLAIM_TYPE` |
| `len(asset_id_hash) ≠ 32` or `len(proof_hash) ≠ 32` | `INVALID_HASH` |

**Gas tier**: L

---

## 7. Key Management Family (`0x0200–0x02FF`)

Key management operations execute the state transitions defined in SPEC-ACCOUNT-001 §5.5. This section specifies them as formal transaction types with explicit payload schemas and rejection conditions.

### 7.1 `key_add` — `msg_type = 0x0200`

**Purpose**: registers a new key in the sender account's KeySet without revoking any existing key.

**Signer policy**: `sender` account; signing key MUST have bit 2 set.

**Payload schema**:

```
{
  1: alg_id,              -- uint(u16)
  2: pk_bytes,            -- bstr
  3: key_version,         -- uint(u32); must be > all existing key_versions in this account
  4: valid_from_height,   -- uint(u64)
  5: allowed_tx_types     -- uint(u32)
}
```

**Preconditions**: as specified in SPEC-ACCOUNT-001 §5.5.1.

**State transition**: add key entry to `sender.keys` with derived `status`.

**Rejection conditions**: as specified in SPEC-ACCOUNT-001 §5.5.4 plus `KEY_VERSION_CONFLICT`.

**Gas tier**: H

---

### 7.2 `key_rotate` — `msg_type = 0x0201`

**Purpose**: atomically adds a new key and revokes an existing key in a single transaction.

**Signer policy**: `sender` account; signing key MUST have bit 2 set. The signing key MAY be the key being rotated out.

**Payload schema**:

```
{
  1: new_alg_id,              -- uint(u16)
  2: new_pk_bytes,            -- bstr
  3: new_key_version,         -- uint(u32)
  4: new_valid_from_height,   -- uint(u64)
  5: new_allowed_tx_types,    -- uint(u32)
  6: revoke_key_version       -- uint(u32); key_version of the key being revoked
}
```

**Preconditions**: as specified in SPEC-ACCOUNT-001 §5.5.2.

**State transition**: add new key entry; set `keys[revoke_key_version].status = revoked`. Both changes are atomic.

**Rejection conditions**: all conditions from `key_add` plus:

| Condition | Code |
|-----------|------|
| `revoke_key_version` not found or already revoked | `KEY_NOT_FOUND` / `KEY_ALREADY_REVOKED` |
| Rotation would leave zero active keys after atomically applying both changes | `INSUFFICIENT_ACTIVE_KEYS` |
| `new_key_version = revoke_key_version` | `INVALID_KEY_ROTATION` |

**Gas tier**: H

---

### 7.3 `key_revoke` — `msg_type = 0x0202`

**Purpose**: marks an existing key as revoked without adding a replacement.

**Signer policy**: `sender` account; signing key MUST have bit 2 set. The signing key MUST NOT be the key being revoked.

**Payload schema**:

```
{
  1: target_key_version   -- uint(u32); key_version to revoke
}
```

**Preconditions**: as specified in SPEC-ACCOUNT-001 §5.5.3.

**State transition**: set `keys[target_key_version].status = revoked`.

**Rejection conditions**:

| Condition | Code |
|-----------|------|
| `target_key_version` not found | `KEY_NOT_FOUND` |
| Key already revoked | `KEY_ALREADY_REVOKED` |
| Revocation would leave zero active keys | `INSUFFICIENT_ACTIVE_KEYS` |
| Signing key is the key being revoked | `SIGNER_IS_TARGET` |

**Gas tier**: H

---

### 7.4 `consensus_key_rotate` — `msg_type = 0x0203`

**Purpose**: rotates the consensus signing key for a registered validator. This is a validator-only operation; non-validator accounts MUST NOT submit it.

**Signer policy**: validator operator account (`sender = validator.operator_address`); signing key MUST have bit 2 set.

**Payload schema**:

```
{
  1: new_consensus_alg_id,    -- uint(u16); ML-DSA or FN-DSA only
  2: new_consensus_pk_bytes,  -- bstr; public key for the new consensus key
  3: rotation_start_height    -- uint(u64); height at which the new key becomes the sole valid consensus key
                              --   old key remains valid for [rotation_start_height - finalization_height] blocks
}
```

**Preconditions**:
- `sender` MUST be the operator address of a validator with `status ∈ {active, candidate}`
- `new_consensus_alg_id` MUST be ML-DSA (0x0001, 0x0002, or 0x0003) or FN-DSA (0x0010 or 0x0011); SLH-DSA MUST NOT be used for consensus keys
- `new_consensus_pk_bytes` size MUST match `expected_pk_size(new_consensus_alg_id)`
- `rotation_start_height` MUST be ≥ `finalization_height + consensus_key_rotation_window` (ensuring the transition window is respected)
- `new_consensus_pk_bytes` MUST NOT already be registered as the consensus key for any other active or candidate validator

**State transition**:
- register new consensus key against the validator record
- set `rotation_start_height` as the cutover point
- old consensus key remains valid for signing until `rotation_start_height`; after that, only the new key is accepted

**Rejection conditions**:

| Condition | Code |
|-----------|------|
| `sender` not a registered validator | `NOT_A_VALIDATOR` |
| `new_consensus_alg_id` is SLH-DSA | `ALGORITHM_NOT_ALLOWED_FOR_CONSENSUS` |
| `rotation_start_height < finalization_height + consensus_key_rotation_window` | `INVALID_ROTATION_HEIGHT` |
| New consensus public key already in use by another validator | `CONSENSUS_KEY_CONFLICT` |

**Gas tier**: H

---

## 8. Governance Family (`0x0300–0x03FF`) — Reserved

The governance operation family is reserved. The `msg_type` range `0x0300–0x03FF` MUST be rejected by nodes in Phase 1 prototype builds until the governance specification (SPEC-GOV, TASK-010) is finalized and activated.

The following `msg_type` values are pre-allocated for planning purposes:

| msg_type | Planned operation | Spec |
|----------|------------------|------|
| `0x0300` | `governance_proposal` | TASK-010 |
| `0x0301` | `governance_vote` | TASK-010 |
| `0x0302` | `registry_update` | TASK-010 |
| `0x0303` | `param_update` | TASK-010 |
| `0x0304` | `validator_allowlist_update` | TASK-010 |

---

## 9. Shared Rejection Codes

These codes are referenced across multiple operations and are defined once here:

| Code | Meaning |
|------|---------|
| `NOT_FOUND` | referenced object (attestation, key, account) does not exist |
| `UNAUTHORIZED` | sender is not authorized to perform this operation on the referenced object |
| `UNSUPPORTED_MSG_TYPE` | `msg_type` is not recognized or is reserved |
| `INVALID_HASH` | a hash field is not exactly 32 bytes |
| `INVALID_AMOUNT` | amount is zero or otherwise invalid |
| `INSUFFICIENT_BALANCE` | sender does not have enough liquid balance |
| `ACCOUNT_EXISTS` | attempted to create an account at an address already in state |
| `ALREADY_REVOKED` | attempted to revoke something already in revoked status |
| `INVALID_ACTIVATION_HEIGHT` | height field is in the past relative to finalization height |

---

## 10. Gas Schedule (Phase 1 Structure)

Per-operation gas costs are defined as tiers here. Exact gas unit values are calibrated in Phase 2 based on prototype measurements.

| Operation | msg_type | Gas tier |
|-----------|----------|---------|
| `vault_create` | 0x0001 | M |
| `vault_policy_update` | 0x0002 | L |
| `token_transfer` | 0x0003 | L |
| `attestation_create` | 0x0100 | M |
| `attestation_revoke` | 0x0101 | L |
| `proof_anchor` | 0x0102 | L |
| `key_add` | 0x0200 | H |
| `key_rotate` | 0x0201 | H |
| `key_revoke` | 0x0202 | H |
| `consensus_key_rotate` | 0x0203 | H |

**Tier relationships** (enforced at calibration time):

- `gas(H) > gas(M) > gas(L)` for all operations within each tier
- Key management operations (H) are expected to cost 3–5× the cheapest L-tier operation
- Attestation creation (M) is expected to cost 2–3× a simple transfer (L) due to secondary index writes

---

## 11. Operation Scope Summary

| Operation | Scope | Who can submit |
|-----------|-------|---------------|
| `vault_create` | user | any account with vault bit |
| `vault_policy_update` | user | vault account itself |
| `token_transfer` | user | any account with vault bit |
| `attestation_create` | user | any account with attestation bit |
| `attestation_revoke` | user | original attester only |
| `proof_anchor` | user | any account with attestation bit |
| `key_add` | user | account with key management bit |
| `key_rotate` | user | account with key management bit |
| `key_revoke` | user | account with key management bit |
| `consensus_key_rotate` | validator | validator operator only |
| `0x0300–0x03FF` | governance | deferred — TASK-010 |

---

## 12. Security Considerations

### 12.1 Implicit Account Creation via token_transfer

`token_transfer` creates the recipient account if it does not exist. The implicitly created account has no signing key and cannot originate transactions. This is safe because: (a) the account can only receive tokens, not act; (b) adding a key requires a `key_add` or `vault_create` transaction signed by a key that does not yet exist for the implicit account — in practice, the intended owner must use `vault_create` explicitly or receive the address from someone who submitted `vault_create`.

There is no risk of account squatting that blocks legitimate use: addresses are derived from public keys, so the address is only knowable if the public key is known, and controlling the address requires the private key.

### 12.2 Attestation Immutability and Revocation Transparency

Attestations are immutable once anchored. Revocation appends a status update; the original record is never erased. This is intentional: the audit trail must reflect that a claim was made and later retracted. Consumers of attestation data MUST check `status` before trusting a record; an `active` status at query time does not guarantee the attestation will never be revoked.

### 12.3 Proof Anchor vs Attestation

`proof_anchor` and `attestation_create` serve overlapping but distinct use cases. `proof_anchor` has no secondary indexes by default, making it cheaper in storage cost but harder to discover without the `anchor_id`. `attestation_create` builds secondary indexes enabling queries by subject and attestation type, at a higher gas cost. Clients SHOULD use `proof_anchor` for machine-to-machine anchoring workflows and `attestation_create` for human-readable, discoverable claims.

### 12.4 Consensus Key Rotation Window

The `consensus_key_rotation_window` requirement in `consensus_key_rotate` prevents a validator from immediately invalidating its old consensus key before the network has propagated the new key. Without this window, validators who submitted votes with the old key in the same block interval as the rotation could have their votes silently rejected, causing liveness disruption. The window ensures overlap.

### 12.5 SLH-DSA Exclusion from Consensus Keys

`consensus_key_rotate` MUST reject SLH-DSA algorithms (see SPEC-VAL-001 §4). This is validated here as an operation-level check independent of the KeySet `allowed_tx_types` mechanism, because consensus keys are separate from account KeySets.

---

## 13. Open TBDs

| ID | Item | Blocking Phase 1? |
|----|------|------------------|
| TBD-OPS-01 | Exact gas unit values per tier | No — calibrated in Phase 2 |
| TBD-OPS-02 | `attestation_supersede` operation: should an attester be able to create a successor attestation that references and replaces a prior one? | No — deferred if needed |
| TBD-OPS-03 | `vault_lock` / `vault_unlock` for time-locked or condition-locked balance holds | No — deferred; not in Phase 1 wedge minimum |
| TBD-OPS-04 | Batch operations: submit multiple operations in a single transaction | No — deferred beyond Phase 1 |
| TBD-OPS-05 | Off-chain proof verification hooks for `proof_anchor` | No — off-chain concern; not protocol-layer |

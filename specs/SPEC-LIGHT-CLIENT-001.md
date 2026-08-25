# Light-Client Protocol Specification

**Spec ID**: SPEC-LIGHT-CLIENT-001
**Version**: 0.1
**Status**: Draft
**Date**: 2026-04-25
**Implements**: ADR-053 §T3.6 (Light-client protocol as first-class feature)
**Depends on**: ADR-053, SPEC-CONSENSUS-001, SPEC-VAL-001, SPEC-SLASH-001, SPEC-FORK-V1 (TASK-191), SPEC-P2P-001, SPEC-P2P-002
**References**: ADR-051 (commit signature preimage convention), Ethereum Altair beacon chain (sync committee design), Bitcoin BIP340 (tagged hashing)

---

## 1. Purpose and Non-Goals

### 1.1 Purpose

A core thesis of Viper PQ Chain is that an attestation notarized in 2026 must remain cryptographically verifiable in 2046, by an audience that did not run a node continuously between those two dates. A 2046 verifier MUST be able to verify the canonical-chain inclusion of any 2026 attestation **without full-syncing 20 years of chain history**.

This specification defines the on-chain consensus surface that makes such future light-client verification possible. At every epoch boundary, a small **sync committee** drawn from the active validator set signs a **compact header attestation** for each block it observes finalize during the epoch. The committee's per-epoch identity is deterministic from on-chain state, so any honest node — and any future light-verifier SDK — derives the same committee. Aggregated committee signatures are gossiped on a dedicated p2p topic and stored by archival nodes. A future light verifier downloads (compact header, committee attestation) pairs together with the committee composition for each epoch, follows finality forward through compact headers, and verifies inclusion proofs of any individual attestation against the binary Merkle `state_root` carried in the compact header.

### 1.2 Non-Goals

- **Light-verifier SDK is OUT OF SCOPE.** This spec defines only the consensus rules, the wire format, the gossip topic, and the slashing conditions necessary for a future SDK to exist. The SDK itself (header download, finality follow, witness verification, retry/resync logic) is post-launch and tracked under a future TASK / spec.
- **PQ signature aggregation is OUT OF SCOPE.** ML-DSA-65 does not aggregate. The MVP committee size (16) is sized so per-attestation bandwidth is acceptable without aggregation. See §8.
- **The gossip topic registration in `pqc-p2p` is OUT OF SCOPE.** The constant is declared by the consensus layer at launch but is not yet wired into the libp2p `Topics` factory; that lands when the SDK lands.
- **Slashing-rule code is OUT OF SCOPE.** This spec specifies the rule (§6); implementation reuses SPEC-SLASH-001 §16 (pluggable verifier registry) when activated post-launch.

---

## 2. Sync Committee Composition

### 2.1 Size

The sync committee has fixed size **`SYNC_COMMITTEE_SIZE = 16`** members per epoch.

The choice of 16 is conservative and reflects three constraints:

1. **PQ signature size.** ML-DSA-65 produces 3,309-byte signatures. A full committee attestation is 16 × 3,309 = ~53 KB. At Ethereum Altair's committee size of 512 the same construction would be ~1.7 MB per attestation, which is infeasible to gossip per-block under PQ signing.
2. **Validator-set scale.** The genesis configuration sets `max_validator_set_size = 64` (SPEC-CONSENSUS-001 §5.3); a 16-member sync committee samples 25% of the active set, providing meaningful resilience without exhausting it.
3. **Future aggregation.** When a PQ aggregation scheme matures (ADR-053 §T4.1), the size MAY be raised via P-COMPAT-001; a smaller MVP value is forward-compatible with raising it later, while an aggressively large value would be hard to lower without dropping committee members mid-flight.

The tradeoffs accepted by choosing 16 are: (a) per-committee resilience tolerates only 5 Byzantine members under the 11-of-16 quorum rule (§4); (b) per-epoch turnover is faster than at 512, increasing rotation overhead; (c) probability of a single malicious validator being selected in a given epoch is higher.

### 2.2 Selection Rule (Weighted-by-Stake, Without Replacement)

The committee for epoch `e` is computed deterministically from on-chain state. Every honest node MUST compute the same committee.

```
seed             = tagged_hash(
                       "VIPER-SYNC-COMMITTEE-V1",
                       epoch_be8 || state_root_at_epoch_boundary
                   )
candidate_set    = active_validator_set_at_epoch_boundary  // sorted by address
total_stake      = sum(v.voting_power for v in candidate_set)

remaining        = candidate_set.clone()
remaining_stake  = total_stake
committee        = []

for i in 0..SYNC_COMMITTEE_SIZE:
    if remaining.is_empty(): break
    chunk        = shake256_n::<32>(seed || i.to_be_bytes())
    selector     = u256_be(chunk) % remaining_stake
    picked       = weighted_select(remaining, selector)  // by voting_power
    committee.push(picked.index_in_original_set)
    remaining_stake -= picked.voting_power
    remaining.remove(picked)
```

Where:

- `tagged_hash` is the BIP340 double-tagged hash defined in ADR-053 §T2.4 / `pqc_crypto::tagged_hash`.
- `state_root_at_epoch_boundary` is the binary-Merkle `state_root` (ADR-053 §T3.1) of the last block of the prior epoch.
- `epoch_be8` is the epoch number as 8 bytes big-endian.
- `weighted_select(set, selector)` walks the stake-sorted set summing voting power until cumulative weight exceeds `selector`; the validator at that point is the pick.

The committee is therefore a **stake-weighted sample without replacement**, mirroring Ethereum Altair's `compute_sync_committee_indices`. The "without replacement" property guarantees 16 distinct validators (provided the active set has ≥ 16 members; smaller active sets are addressed in §7.2).

**Why weighted-by-stake and not first-16-by-shuffle.** A weighted sample makes a 51%-stake adversary expect to control 51% of any committee, matching the consensus security threshold; a flat shuffle would let a small-stake validator gain disproportionate influence over light-client trust by being committee-eligible at the same rate as a large staker. The marginal complexity of the weighted variant (one cumulative-sum walk per pick) is negligible relative to the consensus-security alignment.

### 2.3 Selection Determinism Invariants

The selection algorithm MUST satisfy:

- **Determinism**: any two honest nodes that observe the same `(epoch, state_root, active_validator_set)` produce byte-identical committee index lists.
- **Stake-proportional sampling**: in the limit of many epochs, each validator appears in the committee at a frequency proportional to its voting power.
- **Distinctness**: the 16 committee indices are pairwise distinct.
- **Total-set fallback**: if the active set has fewer than 16 members, the committee is the entire active set in stake-sorted order; quorum (§4) becomes `⌈2/3 × |committee|⌉ + 1`.

---

## 3. Compact Header

### 3.1 Field Set

The **compact header** for a block at height `h` is a strict subset of `BlockHeader` (`pqc_types::block::BlockHeader`, ADR-053 §T1.1) carrying only the fields a light verifier needs to follow finality and verify state-tree witnesses:

| Field | Source | Purpose |
|-------|--------|---------|
| `header_version` | `BlockHeader.header_version` | Forward-compat dispatch (P-COMPAT-001). |
| `height` | `BlockHeader.height` | Position in the canonical chain. |
| `prev_hash` | `BlockHeader.prev_hash` | Backward link. Light verifier follows this back across epochs. |
| `state_root` | `BlockHeader.state_root` | Root of the binary Merkle state tree. Witnesses verify against this. |
| `tx_root` | `BlockHeader.tx_root` | Root of the per-block tx tree. Inclusion proofs of attestations verify against this. |
| `extension_root` | `BlockHeader.extension_root` | Forward-compat commitment slot (ADR-053 §T1.1, §T3.4). |
| `epoch` | `epoch_for_height(height)` | Selects the signing committee. |

The compact header **does not** carry: `timestamp`, `proposer`, the block body, nor the BFT commit signatures. Light verification trusts the sync committee's signature, not BFT material; including BFT data would defeat the bandwidth purpose of the compact form.

### 3.2 CBOR Encoding

The compact header is encoded as a deterministic CBOR map (RFC 8949 §4.2) with integer field keys:

| Key | Field | Type |
|-----|-------|------|
| 1 | `header_version` | uint (u16) |
| 2 | `height` | uint (u64) |
| 3 | `prev_hash` | bstr (32) |
| 4 | `state_root` | bstr (32) |
| 5 | `tx_root` | bstr (32) |
| 6 | `extension_root` | bstr (32) |
| 7 | `epoch` | uint (u64) |

Keys MUST be encoded in ascending integer order. Decoders MUST reject unknown keys. Field-key allocation follows ADR-053 §T1.1 (gaps reserved for future mandatory fields; never renumber).

### 3.3 Canonical Signing Preimage

Each sync committee member signs the following preimage:

```
preimage = "VIPER-LIGHT-HEADER-V1" || fork_digest[4] || cbor(compact_header)
```

Where:

- `"VIPER-LIGHT-HEADER-V1"` is the domain tag for compact-header signatures.
- `fork_digest` is the 4-byte `ForkDigest` defined in `pqc_types::fork::ForkDigest` (ADR-053 §T1.2 / SPEC-FORK-V1, TASK-191) for the active `(fork_version, genesis_validators_root)` pair. The prefix scopes every committee signature to its host chain so a signature on `viper-pq-1` cannot be replayed on any future fork.
- `cbor(compact_header)` is the deterministic CBOR encoding from §3.2.

Sync committee signatures use ML-DSA-65 (the same algorithm and key as the validator's BFT consensus key — SPEC-VAL-001 §5.2; SPEC-CONSENSUS-001 §13). Reusing the consensus key keeps key management simple and ensures slashing for sync-committee equivocation reaches the same `self_bond` slashed for BFT equivocation.

---

## 4. Aggregated Attestation

### 4.1 Quorum Threshold

A compact-header attestation is **valid** when at least

```
SYNC_COMMITTEE_QUORUM = 2 × floor((SYNC_COMMITTEE_SIZE - 1) / 3) + 1
                     = 2 × 5 + 1
                     = 11
```

distinct committee members sign the same preimage. The 11-of-16 quorum (~69%) mirrors the BFT `2f + 1` threshold used in SPEC-CONSENSUS-001 §10 (where `f` is the maximum tolerated Byzantine count). A light verifier that observes < 11 signatures MUST reject the attestation.

### 4.2 Aggregator Role

For each finalized block, any committee member MAY act as **aggregator**:

1. Listen on the gossip topic (§5) for individual signatures matching the block's compact-header preimage.
2. Collect ≥ 11 distinct, validly-signed `(committee_index, signature)` pairs.
3. Publish a `LightClientAttestation` envelope on the same topic.

The aggregator role is permissionless and unrewarded at launch (rewards are deferred to the SDK milestone). Multiple aggregators MAY publish for the same block; the gossip layer's IDONTWANT suppresses duplicates.

### 4.3 Wire Format

```rust
LightClientAttestation = CBOR map with integer keys:
    1: epoch          : uint (u64)
    2: header_root    : bstr (32)   // tagged_hash("VIPER-LIGHT-HEADER-ROOT-V1", preimage)
    3: sigs           : [ (committee_index: u8, signature: bstr) ]
    4: agg_proof      : null | bstr // reserved for future PQ aggregation (ADR-053 §T4.1)
```

`header_root` is included so peers can de-dup an attestation set without re-deriving the preimage. `committee_index` is the 0..15 position within the epoch's committee, NOT the validator's address — recipients look up the address via the per-epoch committee derivation (§2.2).

`agg_proof` is reserved as `null` at launch and switches to a non-null bstr when a PQ-aggregation scheme is activated by governance under P-COMPAT-001 / ADR-049. Verifiers that do not understand the aggregation scheme version (carried inside the bstr's TLV header) MUST reject the attestation rather than ignore the field.

---

## 5. Gossip Topic

### 5.1 Topic Name

The dedicated GossipSub topic is:

```
SYNC_COMMITTEE_GOSSIP_TOPIC = "viper-light-client-attestations-v1"
```

This is the **wire-format topic identifier**. The full libp2p topic string follows the SPEC-P2P-001 §4.3 convention `/viper/{chain_id}/{slug}/1.0.0` and is constructed by the future SDK landing as:

```
format!("/viper/{}/{}/1.0.0", chain_id, SYNC_COMMITTEE_GOSSIP_TOPIC)
```

The slug is locked to `"viper-light-client-attestations-v1"` from genesis; raising to `-v2` requires a P-COMPAT-001 dual-path landing.

### 5.2 Topic Routing Rules

- **Senders**: any committee member or aggregator.
- **Receivers**: all peers that opt into light-client tracking (validators, archival nodes, light-verifier SDKs).
- **Envelope `MessageType`**: a new variant `LightClientAttestation` will be added to the `pqc-p2p::message::MessageType` enum at SDK landing time. Until then, the topic exists only as a string constant in `pqc-consensus`.
- **Validation rule**: a peer that receives a `LightClientAttestation` whose `epoch` does not match the topic-scoped epoch (or whose CBOR fails to decode) MUST drop the message and increment the `pqchain_p2p_envelope_mismatch_total` metric per SPEC-P2P-001 §4.3.

---

## 6. Slashing Conditions

A sync committee member is slashable for two distinct offenses:

### 6.1 Sync-Committee Equivocation (Double-Sign)

**Definition**: the committee member produces two distinct ML-DSA-65 signatures over `"VIPER-LIGHT-HEADER-V1" || fork_digest || cbor(H_a)` and `"VIPER-LIGHT-HEADER-V1" || fork_digest || cbor(H_b)` where `H_a.height == H_b.height` and `H_a` ≠ `H_b` (different `state_root`, `prev_hash`, `tx_root`, or `extension_root`), in the same epoch.

**Evidence**: two `(compact_header, signature)` pairs satisfying the predicate above.

**Slashing taxonomy**: this is the sync-committee analog of the BFT vote-equivocation offense in SPEC-SLASH-001 §4–§15.

**Penalty**: the same penalty as BFT equivocation — `slash_fraction_equivocation = 500` basis points (5% of `self_bond`), tombstone permanent, jailing immediate. **No new economic constant is introduced.** The correlation penalty (SPEC-SLASH-001 §17) applies identically.

**Activation note**: rule activation is gated on the SDK milestone. The hardcoded core-offense range `0x0001..=0x00FF` (SPEC-SLASH-001 §16.3) reserves a slot; this spec recommends `0x0005 = SyncCommitteeEquivocation`. Code activation lands with the SDK; the rule and the reserved slot are normative from launch.

### 6.2 Invalid-Header Sign

**Definition**: the committee member produces an ML-DSA-65 signature over the canonical preimage of a compact header `H` whose fields do NOT match the canonical-chain block at `H.height`. Specifically: there exists a finalized block `B` at `H.height` (per the BFT commit material in SPEC-CONSENSUS-001 §10) such that `B.header.{state_root, prev_hash, tx_root, extension_root} ≠ H.{state_root, prev_hash, tx_root, extension_root}`.

**Evidence**: the offending `(compact_header, signature)` pair plus a BFT commit certificate (per SPEC-CONSENSUS-001 §10) for a different block at the same height.

**Slashing taxonomy**: this is a sync-committee analog of "signing on an invalid chain branch" and is normatively distinct from BFT equivocation because no second sync-committee signature is required to prove guilt — the contradiction with finalized BFT material is itself the proof. This closes a documented Ethereum Altair gap, which has no slashing for sync committee.

**Penalty**: identical economic constants to §6.1 (5% slash, tombstone, jail). Reserved slot recommendation: `0x0006 = SyncCommitteeInvalidHeader`.

**Activation note**: same as §6.1.

### 6.3 What Is NOT a Slashable Offense

- **Missing a sync-committee signature**: liveness failures are not slashable in SPEC-SLASH-001 §18 and are not slashable here either. A committee member who fails to sign forfeits future committee-reward eligibility (when rewards land) but is not penalized in `self_bond`.
- **Signing the same valid compact header twice**: redundant signatures are handled by the de-duplication rule in the gossip layer (SPEC-P2P-001 §4.3 `IDONTWANT`); they are not equivocation.
- **Signing a compact header for a block that was reorged out before finality**: the attestation refers to the correct branch at the time of signing. The light-client protocol relies on BFT finality; an unfinalized branch carries no slashing risk for sync-committee members.

---

## 7. Activation

### 7.1 Genesis Activation

This spec activates at the **genesis block** of every chain that ships it (it was active from the genesis of the retired `viper-pq-1` chain and is active from the genesis of `viper-testnet-2`). The first sync committee is computed from:

```
seed = tagged_hash(
    "VIPER-SYNC-COMMITTEE-V1",
    0u64.to_be_bytes() || genesis_state_root
)
```

The active set at genesis is the genesis validator set (SPEC-VAL-001 §5.1). At genesis the active set is exactly 64 (the launch `max_validator_set_size`); the weighted sample of §2.2 produces a 16-member committee.

### 7.2 Boundary Conditions at Launch

- **Active set < 16 members**: §2.2 fallback applies — the committee is the full active set, quorum becomes `⌈2/3 × |committee|⌉ + 1`. This protects against unexpected validator-set contraction (mass jailing, network partition) without halting the light-client protocol.
- **No aggregator publishes for an epoch**: the gossip topic carries individual signatures only; archival nodes (SPEC-ARCHIVAL-001) MAY persist these for future SDK consumption. The protocol does not fail if no aggregated attestation is published — the per-signature stream is sufficient material for a future verifier.

### 7.3 SDK Milestone (Out of Scope for This Spec)

The light-verifier SDK — header download, finality follow, attestation aggregation client, witness verifier — is a post-launch deliverable tracked under a future TASK. This spec is the consensus-layer commitment that makes the SDK possible; without the launch-time commitment to committee size (§2.1), preimage shape (§3.3), gossip topic name (§5.1), and slashing rules (§6), a future SDK could not be built without a chain reset that ADR-052 forbids.

---

## 8. Future Extensions

### 8.1 PQ-Aggregated Attestations

ML-DSA-65 does not aggregate. Candidate PQ-aggregable schemes (LaBRADOR, SQISign variants) are 2–3 years from standardization (ADR-053 §T4.1). When a suitable scheme matures:

1. The new algorithm is added to the algorithm registry via ADR-049.
2. A new compact-header-signature template (e.g., `"VIPER-LIGHT-HEADER-V2"`) is reserved with the aggregated-signature-friendly preimage.
3. `LightClientAttestation.agg_proof` (§4.3) carries the aggregate.
4. Committee size MAY be raised under P-COMPAT-001 since aggregated bandwidth becomes feasible.

The `header_version` and `extension_root` slots (§3.1) provide the forward-compat surface: a v2 verifier dispatches on `header_version`; a v1 verifier rejects `header_version = 2` rather than parsing wrong bytes.

### 8.2 Committee-Reward Mechanism

Sync-committee participation rewards are deferred to the SDK milestone. The slot for a `committee_reward_bps` governance parameter is reserved.

### 8.3 Cross-Chain Light-Client Bridges

The compact-header preimage is fork-digest-scoped (§3.3), so sync-committee signatures cannot replay across forks. A cross-chain bridge consuming Viper PQ Chain light-client attestations is straightforward to add post-launch and requires no on-chain commitment beyond what this spec defines.

---

## 9. References

| Reference | Document |
|-----------|----------|
| ADR-049 | Crypto agility — algorithm registry and `AddAlgorithm` governance proposal type |
| ADR-051 | Commit signature preimage convention (round inclusion in CommitSig preimage) |
| ADR-052 | P-COMPAT-001 — forward-compatible state evolution; no post-launch resets |
| ADR-053 | `viper-pq-1` genesis architecture; §T1.2, §T2.4, §T3.1, §T3.6, §T4.1 |
| SPEC-CONSENSUS-001 | BFT consensus protocol; finality rule; commit signatures |
| SPEC-VAL-001 | Validator and staking model; lifecycle states |
| SPEC-SLASH-001 | Slashing protocol; equivocation evidence; correlation penalty |
| SPEC-FORK-V1 (TASK-191) | `ForkDigest` derivation and signing-domain prefix |
| SPEC-P2P-001 | libp2p gossip topology, topic naming convention |
| SPEC-P2P-002 | Gossip envelope / `MessageType` discriminants |
| SPEC-ARCHIVAL-001 | Archival overlay; long-term evidence persistence |
| BIP340 | Bitcoin tagged-hash construction (ADR-053 §T2.4 motivation) |
| Ethereum Altair | Sync committee design; documented absence of sync-committee slashing |

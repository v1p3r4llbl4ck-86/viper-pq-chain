# Multicodec Mapping for Viper PQ Algorithms

**Authority:** TASK-221.
**Status:** Draft — mapping proposal; the upstream `multiformats/multicodec` PR has not been submitted.
**Date:** 2026-05-06.
**Cross-references:** ADR-044 (TLV envelope), `crates/pqc-crypto/src/alg.rs` (canonical AlgId enum), `crates/pqc-crypto/src/envelope.rs` (TLV codec).

This doc proposes multicodec codepoints for Viper's post-quantum
signature and KEM algorithms and prepares the PR template for the
upstream `multiformats/multicodec` submission.

## Motivation

Viper's TLV envelope (ADR-044) carries a `algo_id: u16_le` codepoint
chosen from a chain-internal namespace (`crates/pqc-crypto/src/alg.rs`).
This is the **canonical encoding for Viper consensus** — every
signature on chain, every keystore entry, every governance proposal
references the algorithm by its u16 LE value.

The multicodec registration is **separate**: it gives the same
algorithm family a stable identifier in the multiformats ecosystem
(IPFS, libp2p stream protocols, multibase content addressing). A
cross-ecosystem consumer that wants to verify a Viper signature in a
non-chain context (e.g. a third-party explorer indexing on-chain
data into IPFS) reads the multicodec varint to know which scheme to
dispatch. Today no such consumer exists; the registration is
forward-compatibility for when one appears.

The two namespaces are intentionally separate:

| Namespace | Encoding | Source of truth | Lifecycle |
|-----------|---------|-----------------|-----------|
| Viper TLV `algo_id` | `u16_le` | `crates/pqc-crypto/src/alg.rs` | Lives forever; no codepoint reuse even after Banned |
| Multicodec varint | varint | `multiformats/multicodec` table | Maintainer-assigned; lives forever |

The PR upstream does NOT change Viper's wire format. It adds rows to
the multicodec table so cross-ecosystem tooling can name our
algorithms by their multicodec identifier.

## Scope

The PR reserves codepoints for **the PQ scheme family Viper carries
today plus the family it expects to land at Phase 9 / 10** — wider
scope than `alg.rs` currently lists, to avoid a second PR per
algorithm addition.

| Multicodec name | Viper AlgId | FIPS / spec | Notes |
|-----------------|-------------|-------------|-------|
| `mldsa44-pub` | `0x0001` (`MlDsa44`) | FIPS 204 (Cat 2) | currently registered, restricted from consensus per ADR-046 |
| `mldsa65-pub` | `0x0002` (`MlDsa65`) | FIPS 204 (Cat 3) | genesis default — most-used signature on chain |
| `mldsa87-pub` | `0x0003` (`MlDsa87`) | FIPS 204 (Cat 5) | currently registered |
| `mldsa44-sig` | (envelope-implicit) | FIPS 204 (Cat 2) | signature variant for cross-ecosystem |
| `mldsa65-sig` | (envelope-implicit) | FIPS 204 (Cat 3) | |
| `mldsa87-sig` | (envelope-implicit) | FIPS 204 (Cat 5) | |
| `slhdsa-sha2-128s-pub` | `0x0020` (`SlhDsaSha2128s`) | FIPS 205 (Cat 1) | restricted to AA accounts |
| `slhdsa-shake-128f-pub` | (reserved future) | FIPS 205 (Cat 1, fast) | not in `alg.rs` today; reserve forward-compat |
| `slhdsa-shake-128s-pub` | `0x0023` (`SlhDsaShake128s`) | FIPS 205 (Cat 1) | restricted use |
| `slhdsa-shake-192s-pub` | `0x0021` (`SlhDsaShake192s`) | FIPS 205 (Cat 3) | consensus fallback per ADR-043 |
| `slhdsa-shake-256s-pub` | `0x0022` (`SlhDsaShake256s`) | FIPS 205 (Cat 5) | archival overlay only (ADR-045) |
| `slhdsa-shake-128f-sig` | (envelope-implicit) | FIPS 205 (fast) | sig variants per scheme |
| `slhdsa-shake-128s-sig` | (envelope-implicit) | FIPS 205 (slow) | |
| `slhdsa-shake-192s-sig` | (envelope-implicit) | FIPS 205 | |
| `slhdsa-shake-256s-sig` | (envelope-implicit) | FIPS 205 | |
| `mlkem512-pub` | (reserved future) | FIPS 203 (Cat 1) | not in `alg.rs` today; reserve for cross-ecosystem |
| `mlkem768-pub` | `0x0100` (`MlKem768`) | FIPS 203 (Cat 3) | currently registered, P2P TLS only |
| `mlkem1024-pub` | (reserved future) | FIPS 203 (Cat 5) | not in `alg.rs` today; reserve forward-compat |

**FN-DSA-padded-512** (`AlgId 0x0010`) is intentionally **excluded
from this PR**. Per ADR-067, the algorithm is `Reserved` until FIPS
206 finalisation; reserving a multicodec codepoint pre-final invites
cross-ecosystem misuse during the determinism-portability evaluation
window.

## Codepoint proposal

The multicodec table reserves a clustering range for related schemes.
Looking at existing PQ-class entries in the table, recent additions
have landed in the `0x12XX` range. Initial proposal (final values
maintainer-assigned during PR review):

| Name | Proposed codepoint | Tag | Status |
|------|-------------------:|-----|--------|
| `mldsa44-pub` | `0x1200` | `pubkey` | proposed |
| `mldsa65-pub` | `0x1201` | `pubkey` | proposed |
| `mldsa87-pub` | `0x1202` | `pubkey` | proposed |
| `mldsa44-sig` | `0x1203` | `multisig` | proposed |
| `mldsa65-sig` | `0x1204` | `multisig` | proposed |
| `mldsa87-sig` | `0x1205` | `multisig` | proposed |
| `slhdsa-sha2-128s-pub` | `0x1210` | `pubkey` | proposed |
| `slhdsa-shake-128f-pub` | `0x1211` | `pubkey` | proposed |
| `slhdsa-shake-128s-pub` | `0x1212` | `pubkey` | proposed |
| `slhdsa-shake-192s-pub` | `0x1213` | `pubkey` | proposed |
| `slhdsa-shake-256s-pub` | `0x1214` | `pubkey` | proposed |
| `slhdsa-sha2-128s-sig` | `0x1215` | `multisig` | proposed |
| `slhdsa-shake-128f-sig` | `0x1216` | `multisig` | proposed |
| `slhdsa-shake-128s-sig` | `0x1217` | `multisig` | proposed |
| `slhdsa-shake-192s-sig` | `0x1218` | `multisig` | proposed |
| `slhdsa-shake-256s-sig` | `0x1219` | `multisig` | proposed |
| `mlkem512-pub` | `0x1220` | `key` | proposed |
| `mlkem768-pub` | `0x1221` | `key` | proposed |
| `mlkem1024-pub` | `0x1222` | `key` | proposed |

The maintainer may relocate these during review (existing entries in
the `0x12xx` range may collide). Re-assignment is a constants change
on the Viper side — *no wire-break*, since Viper's canonical
encoding is the chain-internal `u16_le`, not the multicodec varint.

## PR template

For the operator who submits the upstream PR. Title:

```
Reserve codepoints for ML-DSA / SLH-DSA / ML-KEM (FIPS 203/204/205)
```

Body:

```markdown
This PR reserves multicodec codepoints for the NIST FIPS 203/204/205
post-quantum schemes used by Viper PQ Chain (https://github.com/v1p3r4llbl4ck-86/viper-pq-chain)
and any other ecosystem consumer that wants stable cross-ecosystem
identifiers for these algorithms.

## Algorithms covered

- ML-DSA-44 / 65 / 87 (FIPS 204) — pubkey + signature variants
- SLH-DSA-SHA2-128s, SHAKE-128f / 128s / 192s / 256s (FIPS 205) — pubkey + signature variants
- ML-KEM-512 / 768 / 1024 (FIPS 203) — pubkey variants (KEM, not signing)

FN-DSA-padded-512 (FIPS 206) is intentionally excluded — the
standard is not yet finalized, and the deterministic-FP cross-CPU-
arch portability story is not pinned.

## Source of truth

The chain-internal canonical encoding is a u16 little-endian
(`algo_id` field of the TLV envelope, see
https://github.com/v1p3r4llbl4ck-86/viper-pq-chain/blob/main/specs/account-keyset-registry.md).
This PR adds the multicodec varint counterpart for cross-ecosystem
tooling. The two namespaces are intentionally separate; this PR
does not change any chain wire format.

## Codepoint range

The reservation lands in `0x1200..=0x1222`. Maintainers welcome to
re-assign during review.

## Reference implementations

- Rust: https://github.com/v1p3r4llbl4ck-86/viper-pq-chain/tree/main/crates/pqc-crypto
- Algorithm registry on chain:
  https://github.com/v1p3r4llbl4ck-86/viper-pq-chain/blob/main/specs/account-keyset-registry.md#7-algorithm-registry-initial-entries

## Tag mapping

- `*-pub`  → tag: pubkey
- `*-sig`  → tag: multisig (signature)

## Status field

All entries are draft until merged.
```

## Steps when the PR lands

1. Update `crates/pqc-crypto/src/alg.rs` doc comments to point at the merged codepoints (current comments cite this doc; flip to citing the multicodec table directly).
2. Update `docs/multicodec-mapping.md` (this file) "Status" column from `proposed` → `merged: 0x12XX (assigned 2026-MM-DD by <maintainer>)`.
3. Update SDK READMEs (`sdk/typescript/README.md` + Python) to document the multicodec equivalence for cross-ecosystem consumers.
4. Open a follow-up TASK if any of the proposed codepoints were re-assigned during review (the doc comments must match the merged table).

## Why we don't wait for upstream merge to land this doc

This doc is the Viper-side material. It exists so:

1. Future code touching `alg.rs` knows there's a multicodec equivalence claim.
2. Audit reports can cite a stable identifier per algorithm even before the upstream PR merges.
3. The PR template is reproducible — if the operator who submits the PR turns over to a different operator, the new operator has a complete starting point.

The upstream merge is asynchronous (typical multicodec PR review window: 1-3 weeks). This doc lands as soon as the mapping is decided; the PR submission is the operator's next operational step.

## Status (update on PR submission)

| Step | Status |
|------|--------|
| Mapping drafted | done 2026-05-06 |
| `alg.rs` doc comments | done 2026-05-06 |
| Upstream PR submitted | pending operator |
| Upstream PR merged | pending |
| Codepoint reconciliation | pending |

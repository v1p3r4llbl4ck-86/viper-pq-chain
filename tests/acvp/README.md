# NIST ACVP Conformance Vectors (TASK-154)

This directory holds a curated subset of NIST ACVP (Automated Cryptographic
Validation Protocol) test vectors consumed by the Phase 8 audit readiness
harness in `crates/pqc-crypto/tests/acvp_conformance.rs`.

It is evidence for gap **C8** in `docs/phase-8-audit-readiness.md` §4
("zero committed NIST test vectors"). A tier-1 crypto auditor
(Cryspen / Quarkslab) will request FIPS 204 / FIPS 205 conformance evidence
on day 1 of kickoff; these vectors are that evidence.

## Source

* Upstream repository: <https://github.com/usnistgov/ACVP-Server>
* Path in upstream: `gen-val/json-files/{ML-DSA-sigVer-FIPS204,SLH-DSA-sigVer-FIPS205}/`
* Upstream commit pin: **`15c0f3deeefbfa8cb6cd32a99e1ca3b738c66bf0`** (master, 2026-04-22)
* ACVP protocol: `ML-DSA` FIPS204 revision, vsId 42; `SLH-DSA` FIPS205 revision, vsId 53
* Source file per algorithm: `prompt.json` merged with `expectedResults.json`
  into one `sigVer_aft.json` per parameter set (each test carries a
  `testPassed` boolean derived from the expected-results file).

## Committed subset

Only **`sigVer` "AFT" (Algorithm Function Test)** vectors are committed — the
set that proves a verifier conforms to the standard by accepting every valid
signature and rejecting every invalid one. The upstream full set is ~34 MB;
the subsampling rules are:

* One test group per parameter set, filtered to the pure (non pre-hash,
  non external-mu) external-interface AFT group.
* Up to 4 ML-DSA test cases per parameter set (2 expected-pass + 2
  expected-fail).
* Up to 3 SLH-DSA test cases per parameter set (2 expected-pass + 1
  expected-fail) — SLH-DSA signatures are 8–50 KB each.
* Within each class, prefer cases with `context == ""` (empty context)
  and short messages, so at least one case per algorithm can be consumed
  through the `PqVerifier` wrapper which does not plumb contexts.

| directory              | algorithm           | tests | bytes  |
|------------------------|---------------------|-------|--------|
| `ml-dsa-44/`           | ML-DSA-44           | 4     | ~52 KB |
| `ml-dsa-65/`           | ML-DSA-65           | 4     | ~48 KB |
| `ml-dsa-87/`           | ML-DSA-87           | 4     | ~75 KB |
| `slh-dsa-shake-128s/`  | SLH-DSA-SHAKE-128s  | 3     | ~66 KB |
| `slh-dsa-shake-192s/`  | SLH-DSA-SHAKE-192s  | 3     | ~112 KB |
| `slh-dsa-shake-256s/`  | SLH-DSA-SHAKE-256s  | 3     | ~186 KB |

Total ~540 KB. The harness file itself (`sigVer_aft.json`) carries the
upstream commit SHA in the `acvpCommit` field so auditors can diff against
upstream without trusting this README.

## Running the harness

```bash
# ACVP tests are #[ignore]'d by default to keep CI fast. Run explicitly:
cargo test -p pqc-crypto --features pq-verifier \
    --test acvp_conformance -- --ignored --nocapture
```

The harness prints each test case's result to stdout. Summary at the end.

## Regeneration

```bash
# Pin the ACVP-Server commit (update this value if you refresh)
C=15c0f3deeefbfa8cb6cd32a99e1ca3b738c66bf0

# Download the upstream prompt + expected JSON for one algorithm
curl -L -o /tmp/ml-dsa-prompt.json \
    "https://raw.githubusercontent.com/usnistgov/ACVP-Server/${C}/gen-val/json-files/ML-DSA-sigVer-FIPS204/prompt.json"
curl -L -o /tmp/ml-dsa-expected.json \
    "https://raw.githubusercontent.com/usnistgov/ACVP-Server/${C}/gen-val/json-files/ML-DSA-sigVer-FIPS204/expectedResults.json"

# Same for SLH-DSA — swap the path component.
# Then pick the AFT group for (parameterSet, testType=AFT, signatureInterface=external,
# preHash=pure, externalMu absent/empty) and join per-case `testPassed` from expectedResults.
# See the inline rules above for subsampling.
```

## Known limitations

1. **Wrapper context path not exercised.** `PqVerifier::verify(pk, msg, sig)`
   has no `context` parameter — it hard-wires the empty context (the only
   form used on-chain; see ADR-011 §3 and SPEC-TX-001 §6). ACVP AFT cases
   have a random `context` byte string per test; we split the dispatch:
   empty-context cases go through `PqVerifier`, non-empty through the
   backend crate's `verify_with_context` / `try_verify_with_context` directly.
   The non-empty-context runs prove the *vectors* are conformant against
   the upstream FIPS implementation, not that the wrapper accepts contexts —
   a separate improvement ticket would plumb `ctx` through the wrapper if
   the chain ever adopts domain-separated signatures.

2. **`internal` (FIPS 205 `slh_verify_internal`) interface not covered.**
   SLH-DSA has both an external interface (with domain-separation byte and
   context) and an internal one (the raw hypertree verify). AFT groups
   17/34/35/36 that test the internal form are skipped — our chain uses
   the external form via the `signature::Verifier` trait (empty context).

3. **pre-hash (HashML-DSA / HashSLH-DSA) tests not covered.** AFT groups
   keyed `hashAlg` present (e.g. SHA2-512-prehashed messages) are skipped.
   The chain hashes transactions to Keccak-256 at the envelope layer and
   signs the 32-byte digest directly — pre-hash variants of the signature
   scheme itself are out of scope for Phase 8.

4. **`externalMu` AFT groups (FIPS 204 draft addendum) not covered.** ML-DSA
   AFT groups 7/8/9/10/11/12 are skipped. Our wrapper only supports
   message-in-the-clear; the external-mu path is not in the AlgId dispatch.

5. **Subsample, not full coverage.** ACVP upstream ships 15 tests per
   group; we commit 3–4 per group to stay under ~1 MB on-repo. The
   subsample is deterministically chosen (sort by (`context != ""`,
   `len(message)`) ascending) so regeneration against the same upstream
   commit produces identical bytes.

## Fallback

If the NIST site is unreachable, the `ml-dsa` crate's upstream test suite
references Wycheproof vectors under `tests/examples/` (stored as opaque
`.pub` / `.priv` binaries for keygen, not sigVer). These were NOT used
here because (a) they do not include expected-pass/expected-fail sigVer
cases and (b) the NIST site was reachable at the time of first commit
(see commit pin above). Record deviation here if regeneration ever
falls back to a non-NIST source.

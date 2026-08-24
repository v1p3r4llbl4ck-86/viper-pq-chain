# RUNBOOK — consensus-key rotation (Phase 4 Gap A fix)

**Calendar context.** Closes "Gap A" of the Phase 4 key-rotation review. Implements Option 1 of that review (pre-shipped `keystore.json` indexed by `key_version`, loader picks active version per height). Severity: HIGH — without this fix, a `ConsensusKeyRotate` tx that successfully lands on-chain causes the rotating validator to silently drop out of quorum for one block and stay out until the operator manually swaps the keystore file.

**TL;DR for the operator.** Use `pqcd wallet rotate-consensus-key … --in-place /etc/pqcd/keystore.json` instead of the legacy two-file workflow. The CLI will atomically append the new seed to the running pqcd's keystore with the next `key_version`. The running pqcd reloads the file on its next tick; both v_old and v_new seeds become eligible signers; when the on-chain activation height arrives the validator transparently switches without any process restart or operator action at the boundary.

---

## §1 — What this fixes

Prior to this fix, the on-chain activation hook (`StateStore::activate_pending_consensus_key_rotations`) flipped the validator-record's `consensus_pk` at `rotation_start_height`, but the validator's `keystore.get(addr)` was unaware of that flip and kept returning the OLD seed. The validator's commits at H+1 were signed with the old key; the verifier rejected them; the validator dropped from quorum until the operator restarted the running pqcd with a swapped keystore file.

After this fix:

- `keystore.json` supports MULTIPLE entries per validator address, each tagged with a `key_version: u32`.
- `Keystore::get_for_pk(addr, &record.consensus_pk)` selects the entry whose derived public key matches the on-chain `consensus_pk` for that operator — at every block, no operator action.
- `pqcd wallet rotate-consensus-key --in-place <keystore.json>` atomically appends the new seed to the validator's running keystore.json BEFORE the activation height. The running pqcd reloads the file via the existing mtime-gated `refresh_keystore_from_file` tick; both v_old and v_new are then staged.
- At `rotation_start_height` the on-chain activation flips the pk; the validator transparently picks the v_new entry; commit signatures verify under the new key; the validator stays in quorum across the boundary.

The legacy "manual swap" workflow is preserved verbatim when `--in-place` is omitted, so existing operator scripts continue to work.

---

## §2 — Recommended workflow (with `--in-place`)

This is what every operator should use going forward.

### 2.1 Generate the new wallet keystore

```bash
pqcd wallet create \
    --alg ml-dsa-87 \
    --output /etc/pqcd/validator.new.keystore.json
```

Pick the algorithm intentionally — cross-alg rotation (e.g. ML-DSA-65 → ML-DSA-87) is supported by both the apply path and the keystore. Same alg is fine if the rotation is purely a hygienic key refresh.

### 2.2 Submit the rotation AND stage the new seed in one step

```bash
pqcd wallet rotate-consensus-key /etc/pqcd/validator.keystore.json \
    --new-keystore /etc/pqcd/validator.new.keystore.json \
    --node https://pqchain.example/ \
    --in-place /etc/pqcd/keystore.json
```

The CLI will:
1. Load the current keystore, prompt for its passphrase, and use it to sign the `ConsensusKeyRotate` tx.
2. Submit the tx to the node.
3. Re-prompt for the NEW keystore's passphrase (or read `VIPER_NEW_PASSPHRASE` from the environment for unattended runs).
4. Decrypt the new seed and verify its derived pk matches the pk that was just submitted on-chain (fail-closed if there's a mismatch).
5. Atomically append a `(address, sig_alg_id, commit_seed_hex, key_version)` entry to `/etc/pqcd/keystore.json` — tempfile + `rename(2)`. The next `key_version` is computed automatically (max + 1, or 2 for legacy single-version files).

The output JSON's `in_place.appended_version` field reports the new slot (typically 2 on a fresh validator's first rotation).

### 2.3 Verify the running pqcd picked up the new entry

Wait one tick (≤ 6 s on devnet defaults). The running pqcd will log:

```
INFO  keystore reloaded: path="/etc/pqcd/keystore.json" len=2
```

`len=N` is the total `(address, key_version)` count — N=2 confirms both v1 and v2 are loaded. You can also exec into the running container and verify with:

```bash
jq '.validators | length' /etc/pqcd/keystore.json
# Expected: 2
```

At this point `snapshot_block_signers` has both seeds eligible. Pre-activation it picks v1 (matches the on-chain pk); post-activation it picks v2.

### 2.4 Watch the activation block

The CLI's `next_step` field in the JSON output names the activation height (typically `current_tip + 200` if `--rotation-start-height` was not specified). When the chain reaches that height, the validator's per-block activation hook flips the validator-record's `consensus_pk` and the engine logs:

```
INFO  activated 1 pending consensus_key_rotation(s) at height 50000
```

The validator's NEXT block commit is signed with the v2 seed. Verifiers accept. Quorum holds.

---

## §3 — Legacy workflow (without `--in-place`)

This is preserved for back-compat. Use it ONLY if your tooling cannot pass the `--in-place` flag.

### 3.1 Create + submit (no in-place)

```bash
pqcd wallet rotate-consensus-key /etc/pqcd/validator.keystore.json \
    --new-keystore /etc/pqcd/validator.new.keystore.json \
    --node https://pqchain.example/ \
    --rotation-start-height $(($(curl -s https://pqchain.example/v1/status | jq -r .height) + 200))
```

### 3.2 Manually swap the running keystore at the activation height

You MUST time this so the swap happens AT the activation height, not before, not after:

```bash
# At activation height (poll /v1/status until height == rotation_start_height):
mv /etc/pqcd/keystore.json.new /etc/pqcd/keystore.json
# pqcd's mtime-gated reload picks it up on the next tick.
```

### 3.3 Failure mode

If the swap is mistimed, the validator drops out of quorum for the duration of the mistime. The chain advances under N-1 quorum (it will, given a 3-of-3 devnet has m=2). Recovery: complete the swap, the running pqcd reloads, normal signing resumes.

---

## §4 — Verification + rollback

### 4.1 What to expect AFTER the activation height

```bash
curl -s http://localhost:26657/v1/validators | jq '.validators[] | select(.operator == "0x…") | .consensus_pk_hex'
# Should print the v2 pk hex.
```

### 4.2 What to expect IF the operator missed the pre-ship

If `--in-place` was not used AND the operator did not manually swap the file in time, the validator's `snapshot_block_signers` will log:

```
WARN  Phase 4 Gap A: keystore holds no seed matching the on-chain consensus_pk for this validator;
       skipping commit signature. Stage the matching key_version via
       `pqcd wallet rotate-consensus-key --in-place` and reload.
       validator_address=… expected_pk=… staged_versions=[1]
```

The block commit gets fewer signatures. If quorum holds (m signers ≥ threshold), the chain advances; the rotating validator sits out. Recovery: stage the v_new entry (manually edit `keystore.json` OR re-run with `--in-place`), pqcd reloads on the next tick, normal signing resumes.

### 4.3 Rolling back a rotation

There is no "undo" for an activated `ConsensusKeyRotate` — the chain has flipped the `consensus_pk` and the slashing-evidence window for the OLD pk is bounded by the unbonding period. If you want to rotate BACK to the original key, submit a fresh `ConsensusKeyRotate` with the old pk as `new_pk_bytes`, give it 100+ blocks (`ROTATION_WINDOW`), and stage the old seed via `--in-place` again.

---

## §5 — Testing the contract before going live

The following tests are run on every CI build:

- `crates/pqcd/src/keystore.rs::tests::keystore_loads_multi_version_entries`
- `crates/pqcd/src/keystore.rs::tests::get_for_pk_finds_correct_version`
- `crates/pqcd/src/keystore.rs::tests::get_for_pk_returns_none_when_pk_not_staged`
- `crates/pqcd/src/keystore.rs::tests::legacy_single_entry_loader_back_compat`
- `crates/pqcd/src/keystore.rs::tests::merge_combines_versions_per_address`
- `crates/pqcd/src/devnet.rs::snapshot_block_signers_tests::picks_v2_seed_after_activation`
- `crates/pqcd/src/devnet.rs::snapshot_block_signers_tests::skips_validator_when_pk_unstaged`
- `crates/pqcd/src/main.rs::in_place_keystore_tests::append_round_trips_through_keystore_loader`
- `crates/pqcd/tests/consensus_key_rotation_producer.rs::phase_b_rotation_then_v2_staged_picks_v2`
- `crates/pqc-consensus/tests/consensus_key_rotation_replay.rs` (state-store side)

Run locally:

```bash
cargo test -p pqcd
cargo test -p pqc-consensus
```

---

## §6 — Open questions / future work

- **Auto-cadence (Gap C, post-HSM).** Once HSM lands, an auto-rotate scheduler can generate the new key in HSM, sign the rotate tx, and stage the keystore entry. The keystore-versioning data model is forward-compatible.
- **Old-seed retention.** The validator side does NOT need the old seed after activation. Operators may keep it on disk for the slashing-evidence window (≤ unbonding_period) for forensics; a future `pqcd wallet retire-key-version <kv>` helper will move retired entries to a sealed archive. Manual archival is fine in the interim.
- **Multi-validator coordination.** If all N-of-N validators rotate at the same height and one missed the pre-ship, quorum is impossible. Operationally: stage rotations 1 block apart in the validator's local epoch. The CLI does not currently refuse same-height rotations from different operators — runbook discipline required.

---

*Last updated: 2026-05-08 (Phase 4 Gap A landing). Author: GSD phase executor.*

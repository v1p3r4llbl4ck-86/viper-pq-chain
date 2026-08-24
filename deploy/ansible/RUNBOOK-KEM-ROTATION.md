# RUNBOOK — ML-KEM identity-keypair rotation (Gap B fix)

**Calendar context.** Closes "Gap B" of the Phase 4 key-rotation review. Implements Strategy 1 + secret salt of that review. Severity: MEDIUM — the affected path is the cluster-internal devnet HTTP P2P session-bootstrap channel (`/internal/p2p/session`), NOT the libp2p TLS 1.3 production transport (which uses ephemeral KEM keys per connection and is unaffected).

**TL;DR for the operator.** Run `pqcd wallet kem-init --node-config /etc/pqcd/node.json` on every host. Restart pqcd one host at a time, leaving the validator for last. Verify the Gap B `warn!` line disappears from startup logs and that the per-epoch `"ML-KEM identity keypair rotated at epoch boundary"` info-line appears.

---

## §1 — What this fixes

Prior to this fix, `crates/pqcd/src/devnet.rs` derived the long-term ML-KEM identity-keypair from `config.node_id` ALONE:

```rust
let kem_d = shake256_32(&[config.node_id.as_bytes(), b"-kem-d"].concat());
let kem_z = shake256_32(&[config.node_id.as_bytes(), b"-kem-z"].concat());
let (kem_pk, kem_sk) = kem_generate(&kem_d, &kem_z);
```

`node_id` is publicly observable (logs, `/v1/status`, peer-info responses). Any attacker who knew `node_id` could recompute the long-term ML-KEM secret without ever touching the disk, then decrypt every session-bootstrap ciphertext sent to that node. The same keypair was used forever — no rotation.

After this fix:

```rust
let kem_d = shake256_32(&[
    node_id.as_bytes(),
    secret_salt,           // NEW: 32 bytes, mode 0600 in node.json
    b"-kem-d-",
    &epoch_number.to_be_bytes(),  // NEW: rotates per epoch boundary
].concat());
```

The KEM keypair becomes a function of `(public node_id, secret salt, public epoch)`. Disk steal → seed steal → key compromise (acceptable, expected). Public-`node_id` observer → cannot recompute (closed). Each epoch rotates the keypair, so even a successful key-compromise has a bounded window.

---

## §2 — How to generate the salt

On EACH host (the validator host + each full node):

```bash
sudo -u pqcd pqcd wallet kem-init --node-config /etc/pqcd/node.json
```

The command:
1. Generates a 32-byte salt from the OS CSPRNG (`getrandom`).
2. Hex-encodes it (64 chars) into `devnet.kem_seed_salt_hex`.
3. Writes `node.json` atomically (tempfile + rename).
4. Preserves file mode `0600` on the new file.

**Refusal mode.** If `devnet.kem_seed_salt_hex` is already set, the command refuses. Pass `--force` to overwrite — note that re-generating invalidates every active P2P session until the next epoch boundary.

**Stdout-only mode.** If `--node-config` is omitted, the command prints the hex salt to stdout. Use this when ansible-templating the node.json from a separate orchestrator host:

```bash
SALT=$(pqcd wallet kem-init | jq -r .kem_seed_salt_hex)
ansible-playbook ... -e "kem_seed_salt=$SALT"
```

---

## §3 — Migration sequence (3-node `viper-pq-1` host group)

**Per-host order matters.** Restart validators LAST so peer-availability stays high during the rolling restart. The grace window is one epoch (default 60 blocks ≈ 30 s for devnet, 43 200 blocks ≈ 6 h for testnet).

1. **Host follower-A** (`viper-pq-1-follower-a`):
   ```bash
   sudo -u pqcd pqcd wallet kem-init --node-config /etc/pqcd/node.json
   sudo systemctl restart pqcd
   ```
   Watch `journalctl -u pqcd -f` for:
   - The Gap B `warn!` line about "node_id ONLY" should no longer appear.
   - At the next epoch boundary, look for `"ML-KEM identity keypair rotated at epoch boundary (Gap B)"` at info level.

2. **Host follower-B** (`viper-pq-1-follower-b`): same procedure.

3. **Host validator** (`viper-pq-1-producer`): same procedure, last.

**Rollback.** If anything goes wrong, comment out / remove the `kem_seed_salt_hex` line from `node.json` and restart. The legacy `node_id`-only derivation kicks back in (with the Gap B `warn!` reappearing). The chain itself is unaffected — KEM identity keypair rotation is a P2P-layer concern, NOT a consensus-layer concern. Block production continues normally regardless of salt-presence.

---

## §4 — Soak validation

After all three hosts are restarted:

1. **Validator keeps producing blocks.** `curl http://<validator-host>:26657/v1/status | jq .height` increments at the expected rate (~2 s/block on devnet).
2. **All three validators sign every block.** Inspect the latest block's `commit_signatures` array — it should have 3 entries (one per validator).
3. **No P2P session disruption beyond the grace window.** After the first epoch boundary post-restart (so all hosts have rotated at least once), full node → validator block-fetch latency should be unchanged from baseline. Look at the `pqchain_p2p_session_errors_total` metric (if exposed) — should remain at its pre-restart value.
4. **No re-emission of the Gap B `warn!`.** `journalctl -u pqcd | grep "Gap B"` should return zero new lines. (Pre-fix lines from the previous boot remain, but no fresh ones.)

If any of (1)-(4) fails, the salt is either malformed (hex parse error in startup logs) or the node.json was clobbered by a stale ansible role. Re-inspect with `sudo cat /etc/pqcd/node.json | jq .devnet.kem_seed_salt_hex`.

---

## §5 — What the salt is NOT

- **NOT** secret-shared across hosts. Each host has its OWN salt. Salts MUST differ across hosts — re-using one salt across hosts is a configuration error and would re-introduce a multi-host single-point-of-trust.
- **NOT** the same as the consensus signing key (which lives in `keystore.json`, also mode 0600, separate file).
- **NOT** the same as the libp2p Ed25519 peer-id keypair (`peer-id.bin`).
- **NOT** rotated automatically — auto-rotation depends on HSM (Gap C, separate roadmap item). The salt is rotated when the operator runs `pqcd wallet kem-init --force`.

---

## §6 — Threat model after this fix

**Closed.** Public-from-public derivation. An attacker who knows `node_id` alone cannot recompute the KEM keypair.

**Closed (windowed).** Single-key-forever exposure. Even after a successful disk-steal, the attacker only gets the keypair for the current epoch; subsequent epochs rotate to fresh material.

**Still open** (mitigated by Phase 6 / HSM-PHASE-PLAN):
- Disk-steal still gives access to the salt → attacker can derive past + future epochs (within their visibility window) until the salt is rotated. This is what HSM ultimately closes.
- The salt itself is mode 0600 on disk, no in-memory zeroization beyond the existing `KemSeed` `ZeroizeOnDrop` pattern. Acceptable for the cluster-internal channel; HSM-Phase-2 hardens it further.

The full threat-model trace lives in the Phase 4 key-rotation research notes, which are not part of the public tree.

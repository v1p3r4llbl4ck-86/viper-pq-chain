# RUNBOOK — 90-day libp2p PeerId rotation (R-14 operational guardrail)

**Calendar context.** Closes the operational half of `KNOWN-ISSUES.md` §R-14 (classical Ed25519 GossipSub envelope) per Stage B of the 2026-05-11 PeerId-rotation scoping. Bounds the HNDL recovery window on each validator's libp2p Ed25519 long-term identity to ≤ 90 days. The structural close-out paths for R-14 are the three watch-triggers documented in `CONCERNS-DECISIONS.md` Upstream-watches §R-14 (FIPS 206 final / viper-research-1 cutover landed today / Phase 8 audit finding); this runbook is the operator-side stopgap that runs autonomously between those structural events.

**TL;DR for the operator.** After viper-research-1 has launched AND the Stage A.4 `pqcd wallet libp2p-init` pass has staged the initial salt on every host (Phase 4b of `launch-viper-research-1.yml`), flip `viper_peer_id_rotate_enabled: true` on every validator host in inventory, populate `viper_keystore_passphrase` in your Ansible vault, and rerun `make deploy-config`. The systemd timer + service + wrapper will then fire quarterly on a per-validator staggered schedule (validator-1 in Jan/Apr/Jul/Oct, validator-2 in Feb/May/Aug/Nov, validator-3 in Mar/Jun/Sep/Dec).

---

## §1 — What this rotates

Per rotation, on one validator host:

1. A fresh 32-byte salt is generated via `openssl rand -hex 32` on the host.
2. The libp2p Keypair derived from `(node_id, salt)` produces a fresh PeerId.
3. The CLI submits a `ValidatorRotatePeerId` transaction signed by the validator's operator keystore. Apply path: `crates/pqc-state/src/apply/validator.rs::apply_validator_rotate_peer_id` (ADR-047 / TASK-159).
4. The CLI polls `/v1/txs/<hash>` until the tx lands, then verifies `/v1/validators/<addr>::data.peer_id_hex` flipped to the new PeerId. Fail-closed on mismatch.
5. The CLI atomically writes `devnet.libp2p_seed_salt_hex = <new salt>` into the host's `node.json` (tmp + rename + mode/ownership preservation).
6. `systemctl restart pqcd` — the swarm reinitialises with the new keypair; ~10-15 s of one-validator-temporarily-off-mesh per scoping doc §4.

What's NOT rotated: the validator's ML-DSA-65 consensus keystore (rotation flow: `pqcd wallet rotate-consensus-key`, see `RUNBOOK-CONSENSUS-KEY-ROTATION.md`), the ML-KEM session-bootstrap salt (rotation flow: `pqcd wallet kem-init`, automatic at every epoch), the on-chain operator address, or the validator's bond.

---

## §2 — Prerequisites (one-time, before enabling)

### 2.1 viper-research-1 must be live with Stage A.4 already staged

Confirm before enabling:

```bash
# 1. viper-research-1 is alive and serving the API:
curl -s http://localhost:26657/v1/status | jq -r '.chain_id'
# Expected: "viper-research-1"

# 2. libp2p_seed_salt_hex is already populated on this host
#    (Stage A.4 = Phase 4b of launch-viper-research-1.yml):
jq -r '.devnet.libp2p_seed_salt_hex // "<UNSET>"' /etc/pqchain/node.json
# Expected: a 64-char hex string (not "<UNSET>").

# 3. The local PeerId derived from (node_id, salt) matches the on-chain binding:
SALT=$(jq -r .devnet.libp2p_seed_salt_hex /etc/pqchain/node.json)
NODE_ID=$(jq -r .node_id /etc/pqchain/node.json)
OPERATOR_ADDR=$(pqcd wallet address /etc/pqchain/keystore.json | jq -r .address_hex)
LOCAL_PEER_ID=$(pqcd peer-id "$NODE_ID" --salt "$SALT")
ONCHAIN_PEER_ID_HEX=$(curl -s http://localhost:26657/v1/validators/$OPERATOR_ADDR | jq -r .data.peer_id_hex)
echo "local=$LOCAL_PEER_ID onchain=$ONCHAIN_PEER_ID_HEX"
# If they disagree, do NOT enable the rotation cron. Fix the binding
# first by running `pqcd wallet rotate-peer-id` manually with the
# current salt to sync the on-chain side.
```

### 2.2 Populate the Ansible vault with the keystore passphrase

The wrapper script runs unattended, so the validator keystore passphrase must be available on each host at rotation time. Ship it via Ansible vault:

```bash
cd deploy/ansible
ansible-vault create group_vars/all/vault.yml
# In the editor:
#   viper_keystore_passphrase: <the operator's keystore passphrase>
# Save + exit. The file is encrypted at rest with the vault password.
```

Then reference the vault on every `make deploy-config` run:

```bash
ansible-playbook --vault-id @prompt -i inventory/hosts.ini playbooks/deploy-config.yml
```

The configure role's `cron.env` task is `no_log: true`, so the passphrase never appears in playbook output. The deployed file `/etc/pqchain/cron.env` is mode 0400 owned by `pqchain`.

### 2.3 Flip the master switch per-host

In each validator host's inventory section (or `host_vars/<host>.yml`):

```yaml
viper_peer_id_rotate_enabled: true
```

For a 3-validator setup the default month-list mapping is already correct (validator-1 = Jan/Apr/Jul/Oct, validator-2 = Feb/May/Aug/Nov, validator-3 = Mar/Jun/Sep/Dec). For larger sets, override `viper_peer_id_rotate_months` per host.

Then deploy:

```bash
make deploy-config
```

The configure role creates `/etc/systemd/system/pqcd-peer-id-rotate.{timer,service}` and the `/usr/local/sbin/pqcd-peer-id-rotate.sh` wrapper, and enables the timer.

### 2.4 Confirm the timer is loaded

```bash
ssh validator-host
systemctl list-timers pqcd-peer-id-rotate.timer
# Expected output names the next firing date (typically the next 1st of
# the validator's month-list at 03:30 UTC, plus the RandomizedDelaySec
# 0-30 min jitter).
```

---

## §3 — Normal cadence (what happens autonomously)

1. systemd fires `pqcd-peer-id-rotate.service` on the validator's scheduled day.
2. The wrapper script captures the pre-rotation state to `/var/log/pqchain/peer-id-rotate.log` (current salt, derived PeerId, on-chain peer_id_hex).
3. New 32-byte salt generated.
4. `pqcd wallet rotate-peer-id` submits the tx, polls for landing (timeout 60s by default), verifies the on-chain binding flipped, writes the new salt to node.json.
5. `systemctl restart pqcd`. The swarm reinitialises (≤ 10 s on healthy hardware).
6. Post-rotation verification: local PeerId derived from (node_id, new salt) matches the on-chain binding.
7. The wrapper exits 0; systemd marks the unit done; Zabbix monitors the journald `OnFailure=` hook for the absence of failures.

Bounded danger window: ~10-15 s between the on-chain binding flipping and the local swarm picking up the new salt. Other validators see one missed block-window of commit signatures from this host. Quorum 2/3 holds in a 3-validator set; the chain advances normally.

---

## §4 — Verification (what to check after a rotation fires)

```bash
# 1. Log a successful rotation
grep "rotate_ok" /var/log/pqchain/peer-id-rotate.log | tail -1
# Expected: a line carrying pre_salt=… post_salt=… pre_peer=… post_peer=…
# where the two salts differ.

# 2. systemd timer is queued for the next quarter
systemctl list-timers pqcd-peer-id-rotate.timer
# Expected: "next" column is ~90 days from now.

# 3. The on-chain binding agrees with the local derivation
SALT=$(jq -r .devnet.libp2p_seed_salt_hex /etc/pqchain/node.json)
NODE_ID=$(jq -r .node_id /etc/pqchain/node.json)
OPERATOR_ADDR=$(pqcd wallet address /etc/pqchain/keystore.json | jq -r .address_hex)
LOCAL_PEER_ID=$(pqcd peer-id "$NODE_ID" --salt "$SALT")
ONCHAIN_PEER_ID_HEX=$(curl -s http://localhost:26657/v1/validators/$OPERATOR_ADDR | jq -r .data.peer_id_hex)
echo "local=$LOCAL_PEER_ID onchain=$ONCHAIN_PEER_ID_HEX"
# Must match. If not, an external rotation (or a bug) raced this one;
# see §6 for recovery.

# 4. The chain is healthy
curl -s http://localhost:26657/v1/status | jq '{chain_id, height, peers}'
# height should be advancing every block_time_ms (~500 ms on viper-research-1).
```

---

## §5 — Manual trigger (out-of-band rotation)

The cron flow is just `pqcd wallet rotate-peer-id` with auto-generated inputs. To trigger off-cadence:

```bash
# Generate a fresh salt
NEW_SALT=$(openssl rand -hex 32)

# Submit the rotation (interactive — prompts for passphrase unless VIPER_PASSPHRASE is set)
pqcd wallet rotate-peer-id /etc/pqchain/keystore.json \
    --new-salt "$NEW_SALT" \
    --node http://localhost:26657 \
    --in-place /etc/pqchain/node.json

# Restart pqcd
systemctl restart pqcd
```

This is the same flow the wrapper script runs, but with the operator on the keyboard. Use this when:

- The validator's libp2p Keypair is suspected compromised (off-cadence emergency rotation).
- Validating the rotation path on a fresh host before enabling the cron.
- Recovering from a §6 failure state.

---

## §6 — Failure modes + rollback recipes

### 6.1 Tx submission fails (HTTP non-2xx from /v1/txs)

**Symptom**: wrapper logs `FATAL rotate_peer_id_cli_failed rc=…` early. node.json is untouched.

**Impact**: chain continues on OLD PeerId. systemd marks unit failed → Zabbix alert.

**Recovery**: investigate why the node refused the tx (most likely cause: stale nonce, wrong chain_id, or the validator was demoted from Active). Once root-caused, manually trigger §5 to retry the rotation.

### 6.2 Tx lands but post-apply verification disagrees

**Symptom**: wrapper logs that the CLI bailed with `post-apply verification FAILED: on-chain peer_id_hex=X but expected Y`.

**Impact**: ON-CHAIN binding has flipped, but to a different value than what we staged. node.json is untouched (so the local pqcd would derive a DIFFERENT PeerId from what's on-chain — a desync).

**Recovery**: do NOT restart pqcd. The on-chain value belongs to whoever raced us. Two paths:

1. Accept the racer's value: extract the salt that produced their PeerId (impossible — salt is secret; you can only know the PeerId). So this path requires re-rotating: generate yet another fresh salt, run §5 manually, hope no race this time.
2. Revert the on-chain binding to the OLD PeerId (the one this host is still derived from): run §5 with the PRE-rotation salt (from `/var/log/pqchain/peer-id-rotate.log::pre_rotation salt=…`). The chain accepts it; node.json is rewritten with the same OLD salt (no-op for the local file but the tx flow runs); the desync closes.

### 6.3 File write fails after on-chain binding flipped

**Symptom**: wrapper logs that `rotate-peer-id` returned non-zero AFTER the tx landed.

**Impact**: ON-CHAIN binding has the NEW PeerId; node.json still carries the OLD salt. The atomic rename means node.json is either fully OLD or fully NEW — never partial. Effectively §6.2 with no racer.

**Recovery**: run §5 with the SAME new salt (saved from the journald log line `new_salt_generated`) to re-attempt the rotation. The CLI will refuse the tx with a nonce error (already landed), but you can manually write the salt:

```bash
NEW_SALT=<from-log>
jq --arg s "$NEW_SALT" '.devnet.libp2p_seed_salt_hex = $s' \
    /etc/pqchain/node.json > /etc/pqchain/node.json.tmp
chown pqchain:pqchain /etc/pqchain/node.json.tmp
chmod 600 /etc/pqchain/node.json.tmp
mv /etc/pqchain/node.json.tmp /etc/pqchain/node.json
systemctl restart pqcd
```

### 6.4 systemctl restart pqcd fails

**Symptom**: wrapper logs `FATAL pqcd_restart_failed`.

**Impact**: node.json carries the NEW salt; the running pqcd is still on the OLD keypair (because the wrapper's `EXIT` trap re-started it, but the restart didn't succeed). The local PeerId disagrees with the on-chain binding.

**Recovery**: triage why pqcd refused to start (journalctl -u pqcd.service -n 100). Common causes: corrupt RocksDB after an unclean shutdown (use `pqcd repair`), permission drift on a keystore file. Once pqcd boots, the rotation completes cleanly — node.json + on-chain agree.

### 6.5 Quorum-impact estimation

A failed rotation drops this validator from the mesh for the time it takes to recover. For a 3-of-3 validator set: chain continues at 2/3 quorum (the formal threshold). For a 5+-validator set the impact is even smaller. **No failure mode in this runbook causes consensus to halt.**

---

## §7 — Disabling the rotation cron

```yaml
# In inventory or host_vars:
viper_peer_id_rotate_enabled: false
```

Then `make deploy-config`. The configure role's "Disable …" task runs unconditionally when the master switch is false, so the timer is stopped + disabled + (left on disk for forensic reference). The wrapper script and service unit remain on disk but never fire.

Manual stop (without re-deploying):

```bash
systemctl stop pqcd-peer-id-rotate.timer
systemctl disable pqcd-peer-id-rotate.timer
```

The chain is unaffected. R-14's operational guardrail is now off; the structural close-out paths (FIPS 206 / cutover / audit) are unchanged.

---

## §8 — Testing the contract before enabling

The following tests are run on every CI build:

- `crates/pqcd/src/p2p/tests.rs` — Stage A.1 + A.2 salt-seam derivation pins (22 tests, including the operational `validator-1` PeerId pin).
- `crates/pqcd/src/cli/wallet/in_place_node_config_tests.rs` — Stage A.3 atomic write + preflight (11 tests).
- `crates/pqcd/src/cli/wallet/libp2p_init_tests.rs` — Stage A.4 init CLI (7 tests).
- `crates/pqcd/tests/wallet_rotate_peer_id.rs` — Stage A.3 on-chain apply + API contract integration test.

Run locally:

```bash
cargo test -p pqcd --lib p2p::
cargo test -p pqcd --bin pqcd cli::wallet::in_place_node_config_tests::
cargo test -p pqcd --bin pqcd cli::wallet::libp2p_init_tests::
cargo test -p pqcd --test wallet_rotate_peer_id
```

Smoke-test the wrapper without firing the rotation (passive parse + permission check):

```bash
ssh validator-host
sudo -u pqchain bash -n /usr/local/sbin/pqcd-peer-id-rotate.sh
# Expected: empty stdout, exit 0 (bash syntax-check only).

sudo systemctl list-unit-files pqcd-peer-id-rotate.timer
# Expected: enabled
```

Manual trigger of the wrapper (consumes the validator's quota of rotation events — use only when you actually want to rotate):

```bash
sudo systemctl start pqcd-peer-id-rotate.service
journalctl -u pqcd-peer-id-rotate.service -n 50 --no-pager
```

---

## §9 — Open questions / future work

- **HSM integration.** Once HSM lands, the keystore passphrase becomes unnecessary — the HSM gates signing directly. The vault entry can be retired.
- **Cluster-wide staggering for N > 3.** The default month-list mapping covers validators 1-3. For 4+, override per-host `viper_peer_id_rotate_months` so any month has at most one validator rotating. The arithmetic: 12 months ÷ N validators × 4 rotations/year. At N = 12 the cadence degenerates to one rotation per validator-month, which is fine; at N > 12 some months will see ≥ 2 validators (use RandomizedDelaySec to spread within the month).
- **Auto-recovery on §6.2 (post-apply race).** Today the wrapper bails on a race. A more aggressive design would retry with a fresh salt automatically up to N times. Deferred — the race is theoretically possible but operationally rare (only one rotation per validator per quarter; cron times are staggered; collision requires either a clock-skew event or a deliberate concurrent operator action).

---

*Last updated: 2026-05-11 (Stage B landing). Companion to `KNOWN-ISSUES.md` §R-14 (the accepted-risk this guardrail bounds).*

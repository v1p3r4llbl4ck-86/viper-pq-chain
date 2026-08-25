# Genesis of a Viper PQ Chain network

How a network is born, from the ceremony to the first external node. Written for
`viper-testnet-2`; every other network follows the same steps with its own names.

## 0. What genesis fixes forever

- the **chain id** and, through it, every address (ADR-053 chain-id-bound derivation);
- the **validator set** at height 0 and its root (`genesis_validators_root`);
- the **fee parameters** and block time;
- the **genesis artefact** `genesis/<chain-id>.json` and its digest.

From the first external state onwards Policy P-COMPAT-001 applies: no reset, migrations
only ([AGENTS.md](../../AGENTS.md)). Everything before that is rehearsal.

## 1. Prerequisites

- A Kubernetes cluster for the author's nodes (k3s is enough) with an ingress controller
  (Traefik ships with k3s) — or Linux hosts with systemd for the Ansible path.
- The release images on `ghcr.io/v1p3r4llbl4ck-86/{pqcd,viper-archival-sidecar}` at the
  tag you are launching (`v0.1.1` at the time of writing), or a local build.
- DNS you control for three names: the explorer/status page, the read API, the P2P seed.
- The pre-genesis gaps in [KNOWN-ISSUES.md §2](../../KNOWN-ISSUES.md) closed or accepted.

## 2. Ceremony

```sh
pqcd ceremony \
  --chain-id viper-testnet-2 \
  --validators 1 \
  --block-time-ms 500 \
  --image-repository ghcr.io/v1p3r4llbl4ck-86 --image-tag v0.1.1 \
  --release-name pqchain --namespace pqchain \
  --service-account notary:<ml-dsa-65 public key hex> \
  --output values-viper-testnet-2.json --secrets-output secrets-viper-testnet-2.yaml
```

`--service-account <label>:<pk>` (repeatable) funds an operator service at genesis — the
notary, an operator wallet. Do it now or never: on a tokenless network every transaction still
settles its fee from the sender's balance, `vault_create` opens accounts at balance 0 and
transfers are not compiled in, so nothing can be funded after height 0 (that is why
`viper-testnet-1` was retired on its first day). Get the key with `pqcd wallet import-seed …`
then `pqcd wallet public-key <keystore>`; the derived address is listed under
`_service_accounts` in the values file and is what the notary takes as `NOTARY_ADDRESS_HEX`.

It produces:

- `values-viper-testnet-2.json` — Helm values: genesis inline, one `node.json` per role
  (validator, sentry ×2, full, rpc, archive, bootnode; the last three disabled), image
  coordinates, `_release_name` / `_namespace` (the chart refuses other names);
- `secrets-viper-testnet-2.yaml` — the validator consensus seed and one identity Secret per
  role (libp2p + ML-KEM salts); **keep it offline, `chmod 600`, back it up before install**.

The number of validators at genesis is the number of consensus seeds generated: with `1`
the author runs the only validator and admits others later (ADR-069 topology: sentries front
it, everything else dials the sentries).

## 3. Install

```sh
kubectl create namespace pqchain
kubectl apply -n pqchain -f secrets-viper-testnet-2.yaml
helm install pqchain charts/viper-pq-chain -n pqchain -f values-viper-testnet-2.json
kubectl -n pqchain get pods -w          # validator-0, sentry-0/1, full-0, frontend
```

Verify before exposing anything:

```sh
kubectl -n pqchain exec pqchain-viper-pq-chain-pqcd-validator-0 -- \
  wget -qO- http://127.0.0.1:26657/v1/status      # height advancing every block_time_ms
kubectl -n pqchain logs pqchain-viper-pq-chain-pqcd-sentry-0 | grep -i 'cold-start\|dial'
kubectl -n pqchain exec pqchain-viper-pq-chain-pqcd-full-0 -- \
  wget -qO- http://127.0.0.1:26657/v1/status      # same height as the validator (±1)
```

A follower stuck at height 0 with `Failed to dial the requested peer` means the bootstrap
multiaddrs do not resolve: check the release name and namespace against the values file
(the chart guard catches a mismatch at render time).

## 4. Publish

1. Copy the genesis from the values file to `genesis/viper-testnet-2.json`, compute
   `sha256sum`, commit both, and attach them to the GitHub Release of the launch tag.
2. DNS (Cloudflare):
   - `pqchain.<domain>` → the ingress (proxied): explorer at `/`, read API under `/v1/`;
   - `rpc.pqchain.<domain>` → the ingress (proxied), read API only;
   - `boot1.pqchain.<domain>` → the node host, **not proxied** (plain TCP 26656; the
     Cloudflare proxy does not carry it).
3. Open TCP 26656 on the host firewall for the bootnode/sentry service only.
4. Announce: the chain id, the genesis digest, the bootstrap multiaddr
   (`/dns4/boot1.pqchain.<domain>/tcp/26656/p2p/<peer-id>`, from `pqcd peer-id <pod-name>`
   with the role salt, or read it from the node's log line `local peer id`), and the
   validator admission path ([validator-onboarding.md](../validator-onboarding.md)).

## 5. First external node

An operator follows [RUNBOOK.md §11](RUNBOOK.md): `configs/roles/full.json`, chain id and
anchor from the published genesis, `bootstrap_peers` = the announced multiaddr, own salts,
`pqcd devnet-serve`. Sync is reached when `/v1/status` reports the validator's height.

## 6. Retiring the previous deployment

The internal lab that ran on the same cluster is deleted after genesis, never before:
`helm uninstall <old-release> -n <old-namespace>` and the PVCs with it. Its chain id is
different; no data is carried over.

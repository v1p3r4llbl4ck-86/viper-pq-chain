# genesis/

| Network | Chain id | Genesis | SHA-256 | Born |
|---|---|---|---|---|
| **viper-testnet-3** (live, TEST) | `viper-testnet-3` | [`viper-testnet-3/genesis.json`](viper-testnet-3/genesis.json) | `e28d5d67c7c52b48e017fd5df8a3a4b4242313fee8ac40a3e481aeb796fcd68d` | 2026-11-16 |
| viper-testnet-2 (retired 2026-09-23) | `viper-testnet-2` | [`viper-testnet-2.json`](viper-testnet-2.json) | `69ccf1bfab72ec8a2009ee2987d9584a3c3a6bb2e626f843ca5d9199b07681e0` | 2026-08-25 |
| viper-testnet-1 | `viper-testnet-1` | [`viper-testnet-1.json`](viper-testnet-1.json) | `0f020abf40f7a589e1d7ea312a8f5607168df7c998cdde119202c93654cf8eaf` | 2026-08-25 — **retired the same day**: replaced by viper-testnet-2, whose genesis funds the operator's service accounts (notary) — nothing could be funded after genesis on a tokenless network |

## Join `viper-testnet-3`

**This is a test network.** No token, nothing of value; it may be reset at any time, and a reset
is a new chain id and a new genesis here.

```bash
curl -fsSL https://raw.githubusercontent.com/v1p3r4llbl4ck-86/viper-pq-chain/main/scripts/join-testnet.sh | bash
```

or by hand: [`viper-testnet-3/full.json`](viper-testnet-3/full.json) is a complete `full` node config — set
`node_id`, run `pqcd wallet libp2p-init --node-config full.json`, then `pqcd devnet-serve full.json`.
Details and the container path: [docs/validator-onboarding.md](../docs/validator-onboarding.md).

Public seed (the author's sentry; QUIC first, TCP/TLS 1.3 fallback; both negotiate X25519MLKEM768):

```
/dns4/boot1.pqchain.agwswebconsulting.it/udp/26656/quic-v1/p2p/12D3KooWS2a6495jsyZ91izS5zbEgXv9oE52TUst4L3QhpVN9pxb
/dns4/boot1.pqchain.agwswebconsulting.it/tcp/26656/p2p/12D3KooWS2a6495jsyZ91izS5zbEgXv9oE52TUst4L3QhpVN9pxb
```

Read API: `https://pqchain.agwswebconsulting.it/v1/status` (GET only).

| Parameter | Value |
|---|---|
| `chain_id_hex` | `76697065722d746573746e65742d33` |
| block time | 6000 ms |
| validators | 1 (proof of authority, operator-run) |
| signatures | ML-DSA-65 (FIPS 204) |

A node must never be started against a genesis that does not match the published digest;
the join script checks it before anything else.

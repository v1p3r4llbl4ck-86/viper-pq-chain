# genesis/

| Network | Chain id | Genesis | SHA-256 | Born |
|---|---|---|---|---|
| viper-testnet-2 | `viper-testnet-2` | [`viper-testnet-2.json`](viper-testnet-2.json) | `69ccf1bfab72ec8a2009ee2987d9584a3c3a6bb2e626f843ca5d9199b07681e0` | 2026-08-25 |
| viper-testnet-1 | `viper-testnet-1` | [`viper-testnet-1.json`](viper-testnet-1.json) | `0f020abf40f7a589e1d7ea312a8f5607168df7c998cdde119202c93654cf8eaf` | 2026-08-25 — **retired the same day**: replaced by viper-testnet-2, whose genesis funds the operator's service accounts (notary) — nothing could be funded after genesis on a tokenless network |

Bootstrap peers (the author's sentries, behind `boot1.pqchain.agwswebconsulting.it:26656`):

```
/dns4/boot1.pqchain.agwswebconsulting.it/tcp/26656/p2p/12D3KooWQEutUYtSiG1VCxDibHkrW15gU91oqRLoWCzkhhu8EYCj
/dns4/boot1.pqchain.agwswebconsulting.it/tcp/26656/p2p/12D3KooWPK3unHbQBxy2mKDVbLQUVYYu6rccZgCndzyXyTpTaZsh
```

Read API and explorer: `https://pqchain.agwswebconsulting.it` (`/v1/status`, `/v1/blocks/latest`, `/docs`).

A node must never be started against a genesis that does not match the published digest;
the same digest is attached to the release that shipped it.

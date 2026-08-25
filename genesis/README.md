# genesis/

| Network | Chain id | Genesis | SHA-256 | Born |
|---|---|---|---|---|
| viper-testnet-1 | `viper-testnet-1` | [`viper-testnet-1.json`](viper-testnet-1.json) | `0f020abf40f7a589e1d7ea312a8f5607168df7c998cdde119202c93654cf8eaf` | 2026-08-25 |

Bootstrap peers (the author's sentries, behind `boot1.pqchain.agwswebconsulting.it:26656`):

```
/dns4/boot1.pqchain.agwswebconsulting.it/tcp/26656/p2p/12D3KooWBzaTFqtoBrd8gtwP2sdumxd5pTPh3kzMrngv3uJ68VW8
/dns4/boot1.pqchain.agwswebconsulting.it/tcp/26656/p2p/12D3KooWJfoEZUGfk75dyvgUUpJnATtoeWsiA1vVDYRHgR6LE7ck
/dns4/boot1.pqchain.agwswebconsulting.it/tcp/26656/p2p/12D3KooWJSSmZNzJE7ikxCfLzhnsHQbMVioSWemngABDwduq9A3D
```

Read API and explorer: `https://pqchain.agwswebconsulting.it` (`/v1/status`, `/v1/blocks/latest`, `/docs`).

A node must never be started against a genesis that does not match the published digest;
the same digest is attached to the release that shipped it.

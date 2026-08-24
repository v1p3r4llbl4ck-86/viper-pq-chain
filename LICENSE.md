# Licensing

Viper PQ Chain is released under **three licences**, chosen by what a file is for
(ADR-070). Every source file carries an `SPDX-License-Identifier` header, every
crate declares its licence in `Cargo.toml`, and `REUSE.toml` covers the files that
have no header. `scripts/check-licenses.sh` verifies all of it.

| What | Licence | Where the text is |
|---|---|---|
| **The verification path** — everything an external party needs to verify the chain without running a node: `crates/pqc-crypto`, `pqc-types`, `pqc-tx`, `pqc-tsa`, `pqc-light-client`, `pqc-keystore`; `sdk/typescript`, `sdk/python`; `tests/acvp` | [Apache-2.0](LICENSES/Apache-2.0.txt) | `LICENSES/Apache-2.0.txt` |
| **The node** — `crates/pqc-consensus`, `pqc-state`, `pqc-mempool`, `pqc-p2p`, `pqc-hsm`, `pqcd`, `viper-archival-sidecar`; `fuzz/`; `charts/`, `deploy/`, `docker/`, `scripts/` | [BUSL-1.1](LICENSES/BUSL-1.1.txt) — see parameters below | `LICENSES/BUSL-1.1.txt` |
| **Specifications and prose** — `specs/`, `docs/`, `WHITEPAPER.md`, `ARCHITECTURE.md`, `ROADMAP.md`, `API.md`, `DECISIONS.md` and the other root documents | [CC BY 4.0](LICENSES/CC-BY-4.0.txt) | `LICENSES/CC-BY-4.0.txt` |
| **Vendored third-party code** — `vendor/` | upstream licences, unchanged (MIT; Apache-2.0 OR MIT) | `vendor/*/LICENSE*`, [NOTICE](NOTICE) |
| Product code that is not part of the public release (`notary/`) | proprietary, private repository only | `LICENSES/LicenseRef-Proprietary.txt` |

## Business Source License 1.1 — parameters

- **Licensor:** Alberto Galassi
- **Licensed Work:** the BUSL-1.1 files above, at the version tagged in this repository
- **Additional Use Grant:** production use of the Licensed Work to operate nodes, in any
  role, of a Viper PQ Chain network whose genesis is published by the Licensor, and to
  build and run software that interoperates with such a network, is permitted. Offering
  the Licensed Work — or a service whose primary value derives from it — to third parties
  as a hosted or managed service, or using it to operate a network that is not a Viper PQ
  Chain network, is not.
- **Change Date:** four years from the first public release of the version you are using
  (for the first public release, 2030-09-30)
- **Change License:** Apache-2.0

In plain words: read, audit, build on and run the node for the network as much as you
like; do not resell it as a service or fork a competing chain with it before the Change
Date. After the Change Date every version becomes Apache-2.0.

## Contributions

Contributions to Apache-2.0 files are accepted under Apache-2.0; contributions to BUSL-1.1
files are accepted under BUSL-1.1 with the same parameters. See CONTRIBUTING.md.

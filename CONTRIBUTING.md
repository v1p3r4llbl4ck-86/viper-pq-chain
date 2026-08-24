# Contributing

Thank you for looking at Viper PQ Chain closely enough to want to change it.

## Ground rules

- **The specifications are the contract.** `specs/` is normative; code conforms to it. If code
  reveals that a spec is wrong, the change is a spec amendment or an ADR first, then code —
  never a silent fix in code.
- **Decisions are written down.** Anything that changes consensus material, `state_root`,
  block encoding, the fee model, an algorithm's status or a public interface needs an entry
  in [DECISIONS.md](DECISIONS.md) (ADR) with the status vocabulary from
  [CONVENTIONS.md](CONVENTIONS.md), and the mandatory updates listed in [AGENTS.md](AGENTS.md)
  (CHANGELOG, TASKS, the affected spec).
- **No resets, no forks of history.** Compatibility rules (Policy P-COMPAT-001, ADR-052)
  apply to every change that lands after `viper-testnet-1` genesis: activation heights,
  dual-path decoders, explicit migrations.
- **Licences follow the file.** Contributions to Apache-2.0 files are accepted under
  Apache-2.0; contributions to BUSL-1.1 files under BUSL-1.1 with the parameters in
  [LICENSE.md](LICENSE.md); contributions to `specs/` and `docs/` under CC BY 4.0. By opening
  a pull request you state that you have the right to contribute the change under that
  licence. Every new Rust file starts with the `// SPDX-License-Identifier:` line of its crate
  (`scripts/check-licenses.sh` checks it).
- **Attribution.** Commits carry the name and e-mail of the person who wrote them; no
  `Co-Authored-By` trailers. Public-facing prose is in English and free of hype.

## Before you open a pull request

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo deny check
cargo test --workspace --all-features        # add `-- --test-threads=1` on small machines
scripts/check-licenses.sh
```

The malicious-node scenarios run only with `--features attack-modes`; if you touch consensus,
run them. Security-critical crates (`pqc-crypto`, `pqc-state::apply`, mempool admission,
`pqc-light-client`) forbid `unwrap`/`expect`/unchecked indexing outside tests — the workspace
lints are the rule, not a suggestion.

## What a good change looks like

1. A short problem statement in the pull request: what is wrong or missing, how you noticed.
2. The spec or ADR change, if the behaviour is specified.
3. The code change, small enough to review in one sitting, with tests that fail without it.
4. `CHANGELOG.md` entry under *Unreleased*; `TASKS.md` if the work was tracked.

Pull requests that only touch documentation are welcome and follow the same path minus the
cargo gates.

## Reporting problems

- Bugs and questions: GitHub issues on the public repository.
- Vulnerabilities: privately, as described in [SECURITY.md](SECURITY.md). Never in a public issue.

## Running a node, joining the network

That is not a contribution but it is the most useful thing you can do while the network is
young: [docs/operators/RUNBOOK.md](docs/operators/RUNBOOK.md) and
[docs/validator-onboarding.md](docs/validator-onboarding.md).

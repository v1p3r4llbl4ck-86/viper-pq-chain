# genesis/

The genesis artefact of the public chain lands here at the genesis ceremony:

- `viper-testnet-1.json` — produced by `pqcd ceremony`, carrying the chain id, the
  validator set with its root, the fee parameters and the anchor hash.
- `viper-testnet-1.sha256` — its digest, also published with the release that ships it.

Until the ceremony this directory is intentionally empty. A node must never be
started against a genesis that does not match the published digest.

"""
genesis_to_validators — Ansible Jinja2 filter plugin.

Projects the `genesis_validators[]` array from
`deploy/ansible/files/genesis-viper-pq-1.json` onto the shape the
`configure` role's `node-config.json.j2` template expects.

Why this exists
---------------
The template at
`deploy/ansible/roles/configure/templates/node-config.json.j2:39` iterates
over `viper_validators` and reads `v.node_id`, `v.address_hex`,
`v.sig_alg_id`, `v.public_key_hex`. The genesis file stores the same
data under the on-chain field names: `node_id`, `address`,
`consensus_alg_id`, `consensus_pk`. The two sets of names diverge for
historical reasons (ansible was written before the on-chain field
names were finalised). Rather than rename either side and risk
breaking auditing scripts that grep for the field names, this filter
performs the rename at play-time so the genesis file stays the
single source of truth.

Closes the `viper_validators is undefined` blocker that flipped
`make deploy-config` red on the 2026-05-09 deploy attempt
(review finding HIGH-2 of the 2026-05-09 deploy attempt).
"""


def genesis_to_validators(genesis_validators):
    """Map genesis_validators[] entries to the template's viper_validators shape.

    Input: list of dicts with keys node_id, address, consensus_alg_id,
    consensus_pk (the on-chain canonical field names).

    Output: list of dicts with keys node_id, address_hex, sig_alg_id,
    public_key_hex (the template's historical field names).

    Defensive: skips entries whose required fields are missing — caller
    is expected to feed an already-validated genesis file (the Phase 0
    grep gate in launch-viper-pq-1.yml refuses placeholder pubkeys), so
    this is belt-and-braces rather than primary validation.
    """
    required = ("node_id", "address", "consensus_alg_id", "consensus_pk")
    result = []
    for v in genesis_validators:
        if not all(k in v for k in required):
            continue
        result.append({
            "node_id":        v["node_id"],
            "address_hex":    v["address"],
            "sig_alg_id":     v["consensus_alg_id"],
            "public_key_hex": v["consensus_pk"],
        })
    return result


def genesis_to_accounts(genesis_accounts):
    """Pass-through for genesis_accounts[].

    The genesis file's `genesis_accounts[]` field already matches the
    `node-config.json.j2` template's expected shape exactly
    (`address_hex`, `balance`, `nonce`, `keys[]` with `alg_id`,
    `pk_hex`, `key_version`, `valid_from_height`, `status`,
    `allowed_tx_types`). This filter exists for parity with
    `genesis_to_validators` and to give us a single place to hang
    future shape changes without forcing a re-edit of the configure
    role's task list.

    Defensive: drops entries with empty `keys[]` since the template
    requires at least one key per account.
    """
    result = []
    for a in genesis_accounts:
        if not a.get("keys"):
            continue
        result.append(a)
    return result


class FilterModule:
    """Ansible expects a `FilterModule` class with a `filters()` method
    returning a dict of {filter_name: callable}."""

    def filters(self):
        return {
            "genesis_to_validators": genesis_to_validators,
            "genesis_to_accounts": genesis_to_accounts,
        }

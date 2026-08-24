# viper-pqchain — Python SDK

> **Pre-pivot SDK version (2026-05-15 note)**: this SDK is `0.2.0`, published 2026-04-25 against `viper-pq-1` which has since been archived (height 33,976 on 2026-05-12). The live chain is now `viper-research-1` — a tokenless permissioned PoA research substrate. `POST /v1/txs` is disabled by runtime config on the live nodes, so the VPR-token helpers shown below (`amount_venom=10**18`, `vpr_to_venom`, etc.) are **NOT functional against the live chain**. Read-only helpers (network status, block fetch, validator lookups) still work. A re-published SDK aligned to viper-research-1 is not yet shipped — see the private planning notes.

Python SDK for [Viper PQ Chain](https://viper-pqchain.io) — post-quantum trust infrastructure.

Requires **Python 3.9+**. Zero external dependencies (uses only `urllib` from the standard library).

## Installation

```bash
pip install viper-pqchain
```

Or from source:

```bash
cd sdk/python
pip install -e .
```

## Quick start

```python
from viper_pqchain import ViperClient

client = ViperClient("http://localhost:9000")

# Chain status
status = client.get_status()
print(f"Height: {status.height}  chain: {status.chain_id}")

# Fetch an account
account = client.get_account("01" * 32)
print(f"Balance: {account.balance} venom  nonce: {account.nonce}")

# Fetch a block
block = client.get_block(1)
print(f"Block 1 proposer: {block.header.proposer_address}")

# List validators
validators = client.get_validators()
for v in validators:
    print(f"  {v.address}  status={v.status}  stake={v.stake} venom")
```

## Fee estimation

```python
from viper_pqchain import ViperClient

client = ViperClient("http://localhost:9000")
calc = client.get_fee_calculator()

est = calc.estimate("vault_create", payload_bytes=256)
print(f"Estimated fee: {est.total_venom} venom")
print(f"  base:      {est.breakdown.base_fee_venom}")
print(f"  bytes:     {est.breakdown.byte_fee_venom}")
print(f"  sigverify: {est.breakdown.sigverify_fee_venom}")
print(f"  execution: {est.breakdown.execution_fee_venom}")
```

## Building unsigned transactions

```python
from viper_pqchain.tx import build_vault_create, build_vault_transfer, build_attestation_create
from viper_pqchain.types import VaultCreateParams, VaultTransferParams, AttestationCreateParams
import json

# Vault creation
tx = build_vault_create(
    VaultCreateParams(
        sender="01" * 32,
        nonce=0,
        alg_id="ml-dsa-65",
        public_key="<hex-encoded-ml-dsa-65-public-key>",
    ),
    fee_budget_venom=20_000,
)
print(json.dumps(tx, indent=2))

# Token transfer
tx = build_vault_transfer(
    VaultTransferParams(
        sender="01" * 32,
        nonce=1,
        recipient="02" * 32,
        amount_venom=10**18,  # 1 VPR
    ),
    fee_budget_venom=15_500,
)

# Attestation
tx = build_attestation_create(
    AttestationCreateParams(
        sender="01" * 32,
        nonce=2,
        subject="03" * 32,
        schema_id="aa" * 32,
        payload_hex="deadbeef",
    ),
    fee_budget_venom=18_512,
)
```

## Signing workflow

**ML-DSA (FIPS 204) has no mature Python implementation as of 2026.** Signing must
be performed externally:

```bash
# 1. Build the unsigned tx JSON (as above) and save it
python my_script.py > unsigned_tx.json

# 2. Sign with the pqcd CLI
pqcd sign-tx --tx-json unsigned_tx.json --key-file my_key.pem > signed_tx.hex

# 3. Submit
```

```python
from viper_pqchain import ViperClient

client = ViperClient("http://localhost:9000")
cbor_hex = open("signed_tx.hex").read().strip()
result = client.submit_tx(cbor_hex)
print(result.status, result.tx_hash)
```

## VPR / venom conversion

```python
from viper_pqchain.utils import venom_to_vpr, vpr_to_venom

print(venom_to_vpr(10**18))          # "1.000000000000000000"
print(vpr_to_venom("1.5"))           # 1500000000000000000
```

## Error handling

```python
from viper_pqchain import ViperClient, ViperError

client = ViperClient("http://localhost:9000")
try:
    account = client.get_account("00" * 32)
except ViperError as e:
    print(e.status_code, e.code, str(e))
```

## API reference

| Method | Endpoint | Returns |
|--------|----------|---------|
| `get_status()` | `GET /v1/status` | `ChainStatus` |
| `get_block(height)` | `GET /v1/blocks/:height` | `Block` |
| `get_block_by_hash(hash)` | `GET /v1/blocks/:hash` | `Block` |
| `get_transaction(tx_hash)` | `GET /v1/txs/:hash` | `Transaction` |
| `submit_tx(cbor_hex)` | `POST /v1/txs` | `SubmitTxResponse` |
| `get_account(address)` | `GET /v1/accounts/:address` | `Account` |
| `get_attestation(id)` | `GET /v1/attestations/:id` | `Attestation` |
| `get_account_attestations(address)` | `GET /v1/accounts/:address/attestations` | `list[Attestation]` |
| `get_validators()` | `GET /v1/validators` | `list[Validator]` |
| `get_validator(address)` | `GET /v1/validators/:address` | `Validator` |
| `get_governance_parameters()` | `GET /v1/governance/parameters` | `GovernanceParameters` |
| `get_fee_calculator()` | fetches params, returns calculator | `FeeCalculator` |

## Running tests

```bash
cd sdk/python
python -m pytest tests/ -v
```

26 tests, 0 failures.

# viper-pqchain — Python SDK

> **Status**: version 0.3.0 (published 2026-04-25) targets the retired `viper-pq-1` API and has not been re-tested against `viper-testnet-4`. The chain has no token: the VPR/venom helpers below do not apply, and the public read API serves GET only (no `/v1/accounts`, no `POST /v1/txs`). Read-only helpers (status, blocks, validators) work against https://pqchain.agwswebconsulting.it.

Python SDK for [Viper PQ Chain](https://github.com/v1p3r4llbl4ck-86/viper-pq-chain) — post-quantum trust infrastructure.

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

client = ViperClient("http://localhost:26657")

# Chain status
status = client.get_status()
print(f"Height: {status.height}  chain: {status.chain_id}")

# Fetch an account
account = client.get_account("01" * 32)
print(f"Balance: {account.balance} venom  nonce: {account.nonce}")  # not available on the public host: expose_token_state is off

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

client = ViperClient("http://localhost:26657")
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

client = ViperClient("http://localhost:26657")
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

client = ViperClient("http://localhost:26657")
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

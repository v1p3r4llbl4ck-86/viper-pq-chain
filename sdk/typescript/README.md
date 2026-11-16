# @v1p3r4llbl4ck/sdk

> **Status**: version 0.3.0 (published 2026-04-25) targets the retired `viper-pq-1` API and has not been re-tested against `viper-testnet-4`. The chain has no token: the VPR/venom helpers below do not apply, and the public read API serves GET only (no `/v1/accounts`, no `POST /v1/txs`). Read-only helpers (status, blocks, validators) work against https://pqchain.agwswebconsulting.it.

TypeScript SDK for [Viper PQ Chain](../../README.md) — post-quantum-native blockchain.

## Installation

```bash
npm install @v1p3r4llbl4ck/sdk
```

Requires Node.js 18+ (uses native `fetch`).

## Quick start

```typescript
import { ViperClient, venomToVpr } from "@v1p3r4llbl4ck/sdk";

const client = new ViperClient({ baseUrl: "http://localhost:26657" });

// Chain status
const status = await client.getStatus();
console.log(`Height: ${status.height}, chain: ${status.chain_id}`);

// Account balance (not available on the public host: `expose_token_state` is off)
const account = await client.getAccount("<32-byte-address-hex>");
console.log(`Balance: ${venomToVpr(BigInt(account.balance_venom))} VPR`);

// Fee estimation
const calc = await client.getFeeCalculator();
const fee = calc.estimate("vault_create", 256);
console.log(`Estimated fee: ${fee.total_venom} venom`);
```

## Signing limitation

ML-DSA-65 and SLH-DSA (FIPS 204/205) have no mature JavaScript implementation as of 2026. **This SDK does not sign transactions.** Use the workflow below:

```bash
# 1. Build unsigned tx (this SDK)
const unsigned = buildVaultCreate({ sender, nonce, alg_id, public_key }, feeBudget);
fs.writeFileSync("tx.json", JSON.stringify(unsigned));

# 2. Sign with pqcd CLI
pqcd sign-tx --tx-json tx.json --key-file validator.key --out tx.cbor.hex

# 3. Submit (this SDK)
const result = await client.submitTx(fs.readFileSync("tx.cbor.hex", "utf8").trim());
console.log(result.tx_hash);
```

## API reference

### `ViperClient`

| Method | Endpoint | Description |
|--------|----------|-------------|
| `getStatus()` | GET /v1/status | Chain height, tip hash, state root |
| `getBlock(height)` | GET /v1/blocks/:height | Block by height |
| `getBlockByHash(hash)` | GET /v1/blocks/:hash | Block by hash |
| `getTransaction(txHash)` | GET /v1/txs/:hash | Transaction by hash |
| `submitTx(cborHex)` | POST /v1/txs | Submit signed CBOR tx |
| `getAccount(address)` | GET /v1/accounts/:address | Account state + keys |
| `getAttestation(id)` | GET /v1/attestations/:id | Attestation record |
| `getAccountAttestations(addr)` | GET /v1/accounts/:addr/attestations | Attestations by address |
| `getValidators()` | GET /v1/validators | Active validator set |
| `getValidator(address)` | GET /v1/validators/:address | Single validator |
| `getGovernanceParameters()` | GET /v1/governance/parameters | Current governance params |
| `getFeeCalculator()` | GET /v1/governance/parameters | Returns `FeeCalculator` |

### Transaction builders

| Function | Op type | Description |
|----------|---------|-------------|
| `buildVaultCreate(params, fee)` | vault_create | Open a new vault account |
| `buildVaultTransfer(params, fee)` | vault_transfer | Transfer VPR between vaults |
| `buildAttestationCreate(params, fee)` | attestation_create | Anchor an attestation |
| `buildValidatorRegister(params, fee)` | validator_register | Register as validator |
| `buildValidatorExit(sender, nonce, fee)` | validator_exit | Initiate validator exit |

### Utilities

| Function | Description |
|----------|-------------|
| `venomToVpr(bigint)` | Convert venom to VPR string (e.g. `"1.5"`) |
| `vprToVenom(string)` | Parse VPR string to venom bigint |
| `parseVenom(string)` | Parse decimal string to bigint |
| `bytesToHex(Uint8Array)` | Encode bytes to hex |
| `hexToBytes(string)` | Decode hex to Uint8Array |
| `isValidAddress(string)` | Returns true if 32-byte hex address |

## Token units

- 1 VPR = 10¹⁸ venom
- Use `bigint` for all arithmetic to avoid precision loss
- API returns venom amounts as decimal strings; parse with `BigInt(value)` or `parseVenom(value)`

## Error handling

All methods throw `ViperError` on network failures or non-2xx responses:

```typescript
import { ViperError } from "@v1p3r4llbl4ck/sdk";

try {
  const account = await client.getAccount(address);
} catch (err) {
  if (err instanceof ViperError) {
    console.error(`HTTP ${err.statusCode}: ${err.message} (code: ${err.code})`);
  }
}
```

## License

Apache-2.0. See [LICENSE](../../LICENSE.md).

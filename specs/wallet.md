# SPEC-WALLET-001: Wallet Keystore and Key Management

**Status**: Proposed
**Date**: 2026-04-16
**References**: SPEC-ADDRESS-001, SPEC-TX-001, SPEC-ACCOUNT-001, ADR-033

---

## 1 Purpose

This specification defines the CLI-first wallet for Viper PQ Chain. The wallet provides key generation, mnemonic-based recovery, encrypted keystore storage, transaction signing, and transaction submission. It is accessed via `pqcd wallet` subcommands.

The wallet is the primary interface for individual users and operators to manage keys and sign transactions locally. SDKs (Python, TypeScript) build unsigned transactions; the wallet provides the signing step.

---

## 2 Key Derivation from Mnemonic

### 2.1 BIP39 Mnemonic Generation

The wallet generates a BIP39 mnemonic using the 2048-word English wordlist:

- **12-word mnemonic**: 128 bits of entropy (default)
- **24-word mnemonic**: 256 bits of entropy (recommended for high-value accounts)

Entropy is drawn from the operating system's cryptographically secure random number generator (`getrandom` / `OsRng`).

### 2.2 BIP39 Seed Derivation

The mnemonic is converted to a 512-bit (64-byte) seed using the standard BIP39 procedure:

```
bip39_seed = PBKDF2-HMAC-SHA512(
    password  = mnemonic_words (space-separated, UTF-8 NFKD normalized),
    salt      = "mnemonic" || passphrase,
    rounds    = 2048,
    dkLen     = 64
)
```

The `passphrase` is optional (empty string if not provided). It serves as an additional layer of protection: the same mnemonic with a different passphrase produces a completely different seed and keypair.

### 2.3 ML-DSA Seed Derivation via HKDF-SHAKE256

The 64-byte BIP39 seed is reduced to a 32-byte ML-DSA signing seed using HKDF with SHAKE-256 as the underlying hash:

```
xi = HKDF-SHAKE256(
    ikm  = bip39_seed,          // 64 bytes
    salt = "VIPER-ML-DSA-V1",   // ASCII, fixed
    info = sig_alg_id_be16,     // 2 bytes, big-endian AlgId
    L    = 32                   // output length in bytes
)
```

Where HKDF-SHAKE256 follows the HKDF construction (RFC 5869) with SHAKE-256 replacing HMAC-SHA256:
- **Extract**: `prk = HMAC-SHAKE256(salt, ikm)` where `HMAC-SHAKE256` uses SHAKE-256 as the hash function with 32-byte output.
- **Expand**: `okm = HMAC-SHAKE256(prk, info || 0x01)` truncated to `L` bytes.

The output `xi` (the Greek letter xi, representing the 32-byte signing seed) is the deterministic input to ML-DSA key generation.

### 2.4 Keypair Derivation

From the 32-byte seed `xi`:

```
(pk, sk) = ml_dsa_keygen_from_seed(alg_id, xi)
address  = SHAKE-256(sig_alg_id_be16 || pk, 32)   // per SPEC-ADDRESS-001
```

### 2.5 Determinism Guarantee

The derivation is fully deterministic: the same mnemonic + same passphrase + same `alg_id` always produces the same `xi`, the same keypair `(pk, sk)`, and the same address. This enables wallet recovery on any machine with only the mnemonic words (and passphrase, if set).

### 2.6 Algorithm Scope

The default algorithm is ML-DSA-65 (`alg_id = 0x0202`). The derivation procedure works for any algorithm in the Algorithm Registry by changing the `info` parameter. However, only ML-DSA variants (ML-DSA-44, ML-DSA-65, ML-DSA-87) use 32-byte seeds; other algorithms may require different seed lengths. Derivation for non-ML-DSA algorithms (SLH-DSA, FN-DSA) is out of scope for this spec and will be defined per algorithm when needed.

---

## 3 Direct Seed Import

### 3.1 Use Case

Power users, automated systems, and migration tools may have a raw 32-byte signing seed without a mnemonic. The wallet supports importing this seed directly.

### 3.2 Input Format

The seed is provided as a 64-character hexadecimal string (lowercase or uppercase). The wallet decodes it to 32 raw bytes.

### 3.3 Derivation

From the imported seed `xi`, the derivation follows the same path as Section 2.4:

```
(pk, sk) = ml_dsa_keygen_from_seed(alg_id, xi)
address  = SHAKE-256(sig_alg_id_be16 || pk, 32)
```

### 3.4 No Mnemonic Recovery

A wallet created via direct seed import cannot be recovered from a mnemonic. The user is responsible for backing up the raw seed or the keystore file.

---

## 4 Keystore File Format

### 4.1 Structure

The keystore file is a JSON document with the following schema:

```json
{
  "version": 1,
  "address": "<bech32m or hex>",
  "alg_id": "0x0202",
  "public_key": "<hex-encoded public key>",
  "crypto": {
    "kdf": "argon2id",
    "kdf_params": {
      "m_cost": 65536,
      "t_cost": 3,
      "p_cost": 1,
      "salt": "<32 bytes, hex-encoded>"
    },
    "cipher": "xchacha20-poly1305",
    "nonce": "<24 bytes, hex-encoded>",
    "ciphertext": "<encrypted seed + 16-byte Poly1305 tag, hex-encoded>"
  }
}
```

### 4.2 Encrypted Payload

The encrypted payload is the 32-byte seed `xi` — NOT the full expanded private key. On unlock, the wallet re-derives the keypair from `xi` using `ml_dsa_keygen_from_seed`. This keeps the ciphertext small (32 bytes + 16-byte authentication tag = 48 bytes) and avoids storing algorithm-specific key structures that may change between library versions.

### 4.3 KDF Parameters

The Argon2id parameters follow OWASP recommendations for password hashing:

| Parameter | Value | Description |
|-----------|-------|-------------|
| `m_cost` | 65536 | Memory usage: 64 MiB |
| `t_cost` | 3 | Time cost: 3 iterations |
| `p_cost` | 1 | Parallelism: 1 lane |

These parameters produce a ~0.5 second derivation on modern hardware, balancing security against usability. The KDF output is 32 bytes, used as the XChaCha20-Poly1305 encryption key.

### 4.4 Salt and Nonce

- `salt`: 32 bytes, generated randomly per keystore file creation. Used as the Argon2id salt.
- `nonce`: 24 bytes, generated randomly per keystore file creation. Used as the XChaCha20-Poly1305 nonce.

Both are stored in plaintext in the keystore file — this is standard practice; the security relies on the passphrase and KDF, not on salt/nonce secrecy.

### 4.5 Encryption Procedure

```
1. Generate salt (32 random bytes) and nonce (24 random bytes).
2. Prompt user for passphrase.
3. encryption_key = Argon2id(passphrase, salt, m_cost, t_cost, p_cost, output_len=32)
4. ciphertext_with_tag = XChaCha20-Poly1305.encrypt(encryption_key, nonce, xi)
5. Zeroize passphrase, encryption_key, and xi from memory.
6. Write keystore JSON to file.
7. Set file permissions to 0600 (owner read/write only).
```

### 4.6 Decryption Procedure

```
1. Read keystore JSON from file.
2. Prompt user for passphrase.
3. encryption_key = Argon2id(passphrase, salt, m_cost, t_cost, p_cost, output_len=32)
4. xi = XChaCha20-Poly1305.decrypt(encryption_key, nonce, ciphertext_with_tag)
   → If authentication fails, abort with "invalid passphrase" error.
5. Zeroize passphrase and encryption_key from memory.
6. Return xi (caller is responsible for zeroizing after use).
```

### 4.7 File Naming

Default keystore file path: `~/.viper/keystore/<hex_address>.json`

The `--output <path>` flag overrides the default location. If the output directory does not exist, the wallet creates it with permissions 0700.

### 4.8 Version Field

The `version` field is `1` for the initial keystore format. Future format changes (e.g. adding HD derivation path metadata) will increment this field. The wallet MUST reject keystore files with `version > 1` and print an error suggesting a binary upgrade.

---

## 5 CLI Interface

### 5.1 Commands

```
pqcd wallet create [--alg <algorithm>] [--output <path>]
```
Generate a new BIP39 mnemonic, derive a keypair, encrypt the seed, and write a keystore file. Prints the mnemonic to the terminal (once only — the user must record it). Prompts for a passphrase to encrypt the keystore. Default algorithm: `ml-dsa-65`.

```
pqcd wallet import-mnemonic [--alg <algorithm>] [--output <path>]
```
Prompt for a BIP39 mnemonic (12 or 24 words) and optional passphrase. Derive the keypair, encrypt the seed, and write a keystore file. Used for wallet recovery.

```
pqcd wallet import-seed <hex-seed> [--alg <algorithm>] [--output <path>]
```
Import a raw 32-byte seed (64 hex characters). Derive the keypair, encrypt the seed, and write a keystore file.

```
pqcd wallet address <keystore-path>
```
Print the address from the keystore file. Does not require the passphrase (the address is stored in plaintext in the keystore). Prints both Bech32m and hex formats.

```
pqcd wallet public-key <keystore-path>
```
Print the hex-encoded public key from the keystore file. Does not require the passphrase.

```
pqcd wallet sign <keystore-path> <unsigned-tx-cbor-hex>
```
Decrypt the keystore (prompts for passphrase), derive the keypair, sign the transaction, and print the signed transaction as CBOR hex. See Section 8 for the signing flow.

```
pqcd wallet send <keystore-path> --to <address> --amount <venom> --node <url>
```
Build a transfer transaction, sign it, and submit to the specified node's `/v1/txs` endpoint. Prompts for passphrase. The `--to` address accepts both Bech32m and hex formats. The `--amount` is in venom (atomic units). The wallet fetches the sender's current nonce from `/v1/accounts/{address}` before building the transaction. Prints the transaction hash on success.

```
pqcd wallet export-seed <keystore-path>
```
Decrypt the keystore (prompts for passphrase) and print the raw 32-byte seed as 64 hex characters. Prints a warning before displaying: `WARNING: This seed controls your account. Anyone with this seed can spend your funds. Do not share it.`

### 5.2 Algorithm Flag

The `--alg` flag accepts the following values:

| Flag value | `AlgId` |
|------------|---------|
| `ml-dsa-44` | `0x0101` |
| `ml-dsa-65` | `0x0202` (default) |
| `ml-dsa-87` | `0x0303` |

SLH-DSA and FN-DSA are not supported for wallet creation in this spec (SLH-DSA is restricted to recovery/emergency flows per ADR-006; FN-DSA FIPS is not yet final).

### 5.3 Backend Flag

The `--backend` flag selects the signing backend (see Section 6). Default: `local-rust`. Can also be set via the `VIPER_SIGNER_BACKEND` environment variable (CLI flag takes precedence).

### 5.4 Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Invalid arguments or usage error |
| 2 | Keystore file not found or unreadable |
| 3 | Invalid passphrase (decryption authentication failed) |
| 4 | Transaction rejected by node (non-2xx HTTP response) |
| 5 | Network error (node unreachable) |

---

## 6 Signing Backends

### 6.1 Architecture

The wallet uses a trait-based signing backend architecture. The signing operation is abstracted behind a `WalletSigner` trait:

```
trait WalletSigner {
    fn sign(&self, alg_id: AlgId, seed: &[u8; 32], message: &[u8]) -> Result<Vec<u8>, SignError>;
}
```

The wallet instantiates the appropriate backend based on the `--backend` flag or `VIPER_SIGNER_BACKEND` environment variable.

### 6.2 `local-rust` Backend (In Scope)

The default backend. Uses `pqc_crypto::ml_dsa_sign_with_seed(alg_id, seed, message)` directly. No external dependencies beyond the existing `pqc-crypto` crate.

### 6.3 Future Backends (Out of Scope)

The following backends are planned but not specified here. Each will require its own ADR when implemented:

| Backend | Description | Key storage |
|---------|-------------|-------------|
| `openssl` | Delegate to OpenSSL 3.5+ ML-DSA provider | Seed in keystore, signing via OpenSSL API |
| `aws-kms` | Delegate to AWS KMS ML-DSA keys | Key in AWS KMS, seed never on disk |
| `pkcs11` | Delegate to PKCS#11 3.2 HSM | Key in HSM, seed never on disk |

### 6.4 Backend Discovery

The wallet validates the backend name at startup. If an unsupported backend is requested, the wallet prints an error listing available backends and exits with code 1.

---

## 7 Security Considerations

### 7.1 Seed Zeroization

All seed material (`xi`, expanded private key `sk`, BIP39 seed, HKDF intermediate values) MUST be zeroized from memory immediately after use. The implementation MUST use the `zeroize` crate (or equivalent) which overwrites memory with zeros and prevents compiler optimizations from eliding the write.

Zeroization points:
- After keystore encryption (Section 4.5, step 5)
- After signing (Section 8, step 6)
- After seed export (immediately after printing)
- On any error path that has already decrypted the seed

### 7.2 Passphrase Handling

The passphrase MUST be read interactively from the terminal (e.g. via `rpassword` crate). It MUST NOT be accepted as a command-line argument — command-line arguments are visible in the process list (`ps aux`), shell history, and audit logs.

The passphrase is zeroized from memory immediately after the KDF computation.

### 7.3 File Permissions

Keystore files MUST be created with permissions `0600` (owner read/write only) on Unix systems. The wallet SHOULD warn if an existing keystore file has permissions more permissive than `0600`.

On Windows, the wallet SHOULD set the file ACL to restrict access to the current user only.

### 7.4 Mnemonic Display

The `wallet create` command displays the mnemonic exactly once, immediately after generation. It is NOT stored in the keystore file. The wallet prints a warning:

```
IMPORTANT: Write down these words and store them safely.
This is the ONLY time they will be displayed.
If you lose them, you cannot recover your account.
```

### 7.5 Export Seed Warning

The `wallet export-seed` command prints a prominent warning before displaying the seed (see Section 5.1). The wallet SHOULD require the user to type `YES` to confirm before revealing the seed.

### 7.6 Timing Side Channels

The Argon2id KDF is not constant-time with respect to the passphrase, but this is acceptable because the KDF is intentionally slow (the timing reveals nothing beyond "the KDF ran"). The XChaCha20-Poly1305 decryption and ML-DSA signing operations MUST use constant-time implementations (provided by the underlying cryptographic libraries).

### 7.7 No Plaintext Seed on Disk

The seed `xi` MUST never be written to disk in plaintext — not in temporary files, log files, core dumps, or swap. The wallet SHOULD advise operators to disable core dumps (`ulimit -c 0`) and use encrypted swap on machines that handle signing.

---

## 8 Transaction Signing Flow

### 8.1 Full Procedure

The `wallet sign` command executes the following steps:

```
1. Parse <keystore-path> and <unsigned-tx-cbor-hex> from arguments.
2. Read the keystore file.
3. Prompt for passphrase (interactive).
4. Decrypt xi from keystore (Section 4.6).
5. Derive keypair: (pk, sk) = ml_dsa_keygen_from_seed(alg_id, xi).
6. Decode the unsigned transaction: tx = decode_tx(cbor_bytes).
7. Build the signing preimage: preimage = build_preimage(&tx)  // per SPEC-TX-001
8. Sign: signature = ml_dsa_sign_with_seed(alg_id, xi, &preimage).
9. Set tx.signature = signature.
10. Set tx.sig_alg_id = alg_id (from keystore).
11. Encode: signed_cbor = encode_tx(&tx).
12. Zeroize xi, sk, and preimage from memory.
13. Print hex::encode(signed_cbor) to stdout.
```

### 8.2 Verification Check

After signing, the wallet MAY verify the signature locally before printing the output. This catches implementation bugs early and ensures the signed transaction will pass mempool admission. The verification uses the public key from step 5.

### 8.3 The `send` Flow

The `wallet send` command is a convenience wrapper:

```
1. Decrypt keystore and derive keypair (steps 1-5 above).
2. Fetch sender nonce: GET /v1/accounts/{sender_address} from --node.
3. Build an unsigned transfer transaction:
   - tx_version: 1
   - chain_id: from node's /v1/status response
   - msg_type: 0x0101 (Transfer)
   - sender: address from keystore
   - nonce: fetched nonce + 1
   - fee: estimated from /v1/fee-market or a sensible default
   - payload: CBOR { recipient: <--to address>, amount: <--amount> }
   - sig_alg_id: from keystore
   - sig_key_version: 1 (initial key)
4. Sign the transaction (steps 7-10 above).
5. Submit: POST /v1/txs with the signed CBOR.
6. Print the transaction hash.
7. Zeroize all sensitive material.
```

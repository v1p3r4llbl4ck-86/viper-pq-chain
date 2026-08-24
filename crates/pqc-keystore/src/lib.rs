// SPDX-License-Identifier: Apache-2.0
//! Wallet keystore and key management — SPEC-WALLET-001.
//!
//! Provides:
//! - BIP39 mnemonic generation and seed derivation
//! - HKDF-SHAKE256 ML-DSA seed derivation
//! - Argon2id + XChaCha20-Poly1305 encrypted keystore format
//! - Transaction signing with seed zeroization
//!
//! Audit-scope: address derivation, keystore encryption/decryption, signing flow.

use anyhow::{bail, Context, Result};
use pqc_crypto::alg::AlgId;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

// ── HKDF-SHAKE256 (SPEC-WALLET-001 §2.3) ────────────────────────────────────

/// HKDF-SHAKE256 extract step: PRK = HMAC-SHAKE256(salt, ikm).
///
/// HMAC-SHAKE256 follows the standard HMAC construction (RFC 2104) with
/// SHAKE-256 as the hash function producing 32-byte output.
/// Block size for SHAKE-256 (Keccak with rate 1088 bits) = 136 bytes.
fn hmac_shake256(key: &[u8], data: &[u8]) -> [u8; 32] {
    use sha3::{
        digest::{ExtendableOutput, Update, XofReader},
        Shake256,
    };
    const BLOCK_SIZE: usize = 136;

    // If key > block size, hash it first.
    let mut key_block = [0u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        let mut hasher = Shake256::default();
        hasher.update(key);
        let mut reader = hasher.finalize_xof();
        let mut hashed = [0u8; 32];
        reader.read(&mut hashed);
        key_block[..32].copy_from_slice(&hashed);
    } else {
        // `key.len() <= BLOCK_SIZE` here, so `zip` copies the whole key.
        for (dst, src) in key_block.iter_mut().zip(key) {
            *dst = *src;
        }
    }

    // ipad = key XOR 0x36, opad = key XOR 0x5c
    let mut ipad = [0x36u8; BLOCK_SIZE];
    let mut opad = [0x5cu8; BLOCK_SIZE];
    for ((i, o), k) in ipad.iter_mut().zip(opad.iter_mut()).zip(key_block.iter()) {
        *i ^= *k;
        *o ^= *k;
    }

    // inner = SHAKE-256(ipad || data)
    let mut inner_hasher = Shake256::default();
    inner_hasher.update(&ipad);
    inner_hasher.update(data);
    let mut inner_reader = inner_hasher.finalize_xof();
    let mut inner_hash = [0u8; 32];
    inner_reader.read(&mut inner_hash);

    // outer = SHAKE-256(opad || inner)
    let mut outer_hasher = Shake256::default();
    outer_hasher.update(&opad);
    outer_hasher.update(&inner_hash);
    let mut outer_reader = outer_hasher.finalize_xof();
    let mut result = [0u8; 32];
    outer_reader.read(&mut result);

    key_block.zeroize();
    ipad.zeroize();
    opad.zeroize();
    inner_hash.zeroize();

    result
}

/// HKDF-SHAKE256 per SPEC-WALLET-001 §2.3.
///
/// Extract: `prk = HMAC-SHAKE256(salt, ikm)`
/// Expand:  `okm = HMAC-SHAKE256(prk, info || 0x01)` truncated to `length` bytes.
fn hkdf_shake256(ikm: &[u8], salt: &[u8], info: &[u8], length: usize) -> Vec<u8> {
    // Extract
    let prk = hmac_shake256(salt, ikm);

    // Expand — for length <= 32, a single HMAC invocation suffices (counter = 0x01).
    assert!(length <= 32, "HKDF-SHAKE256 expand: length must be <= 32");
    let mut expand_input = Vec::with_capacity(info.len() + 1);
    expand_input.extend_from_slice(info);
    expand_input.push(0x01);
    let mut okm = hmac_shake256(&prk, &expand_input).to_vec();
    okm.truncate(length);
    okm
}

// ── BIP39 seed derivation ────────────────────────────────────────────────────

/// Derive the 64-byte BIP39 seed from a mnemonic and optional passphrase.
///
/// Uses PBKDF2-HMAC-SHA512 with 2048 rounds per BIP39 specification.
fn bip39_seed_from_mnemonic(mnemonic: &str, passphrase: &str) -> [u8; 64] {
    use sha2::Sha512;

    let salt = format!("mnemonic{passphrase}");
    pbkdf2::pbkdf2_hmac_array::<Sha512, 64>(mnemonic.as_bytes(), salt.as_bytes(), 2048)
}

/// Derive the 32-byte ML-DSA signing seed from a BIP39 seed.
///
/// HKDF-SHAKE256(ikm=bip39_seed, salt="VIPER-ML-DSA-V1", info=alg_id_be16, L=32)
fn derive_ml_dsa_seed(bip39_seed: &[u8; 64], alg_id: AlgId) -> [u8; 32] {
    let info = alg_id.as_u16().to_be_bytes();
    let okm = hkdf_shake256(bip39_seed, b"VIPER-ML-DSA-V1", &info, 32);
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&okm);
    seed
}

// ── Keystore types (SPEC-WALLET-001 §4) ─────────────────────────────────────

/// KDF parameters for Argon2id.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KdfParams {
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
    pub salt: String, // hex-encoded 32 bytes
}

/// Cryptographic envelope for the encrypted seed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeystoreCrypto {
    pub kdf: String,
    pub kdf_params: KdfParams,
    pub cipher: String,
    pub nonce: String,      // hex-encoded 24 bytes
    pub ciphertext: String, // hex-encoded 48 bytes (32 seed + 16 tag)
}

/// Encrypted keystore file per SPEC-WALLET-001 §4.
///
/// The `chain_id` + `address` pair is chain-specific: per ADR-053 §T1.3 the
/// address is derived as `SHAKE-256("VIPER-ADDR-V1" || chain_id || alg_id_be16
/// || pk_bytes)`, so the same pk on a different chain resolves to a different
/// address. A keystore is therefore bound to one host chain at creation time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Keystore {
    pub version: u16,
    pub chain_id: String,   // hex-encoded chain_id bytes (ADR-053 §T1.3)
    pub address: String,    // hex-encoded 32-byte address
    pub alg_id: String,     // e.g. "0x0002"
    pub public_key: String, // hex-encoded public key
    pub crypto: KeystoreCrypto,
}

impl Keystore {
    /// Create a new keystore from a BIP39 mnemonic.
    ///
    /// Returns `(keystore, mnemonic_words)`. The `chain_id` binds the derived
    /// address to one host chain (ADR-053 §T1.3).
    pub fn create(chain_id: &[u8], alg_id: AlgId, passphrase: &str) -> Result<(Self, String)> {
        use bip39::Mnemonic;
        use rand::RngCore;

        // Generate 256 bits of entropy for 24-word mnemonic.
        let mut entropy = [0u8; 32];
        rand::rng().fill_bytes(&mut entropy);
        let mnemonic = Mnemonic::from_entropy(&entropy)
            .map_err(|e| anyhow::anyhow!("BIP39 mnemonic generation failed: {e}"))?;
        entropy.zeroize();
        let mnemonic_words = mnemonic.to_string();

        // BIP39 seed derivation (passphrase for the mnemonic is empty per SPEC-WALLET-001).
        let mut bip39_seed = bip39_seed_from_mnemonic(&mnemonic_words, "");
        let mut xi = derive_ml_dsa_seed(&bip39_seed, alg_id);
        bip39_seed.zeroize();

        let keystore = Self::create_from_seed(chain_id, alg_id, &xi, passphrase)?;
        xi.zeroize();

        Ok((keystore, mnemonic_words))
    }

    /// Create a keystore from a raw 32-byte signing seed. `chain_id` binds the
    /// derived address to one host chain (ADR-053 §T1.3).
    pub fn create_from_seed(
        chain_id: &[u8],
        alg_id: AlgId,
        seed: &[u8; 32],
        passphrase: &str,
    ) -> Result<Self> {
        // Derive public key and address from seed.
        let pk_bytes = pqc_crypto::ml_dsa_public_key_from_seed(alg_id, seed)
            .map_err(|e| anyhow::anyhow!("key derivation failed: {e}"))?;
        let address = pqc_crypto::derive_address(chain_id, alg_id, &pk_bytes);

        // Encrypt the seed.
        let crypto = encrypt_seed(seed, passphrase)?;

        Ok(Keystore {
            version: 1,
            chain_id: hex::encode(chain_id),
            address: hex::encode(address),
            alg_id: format!("0x{:04x}", alg_id.as_u16()),
            public_key: hex::encode(&pk_bytes),
            crypto,
        })
    }

    /// Create a keystore from a BIP39 mnemonic string. `chain_id` binds the
    /// derived address to one host chain (ADR-053 §T1.3).
    pub fn create_from_mnemonic(
        chain_id: &[u8],
        alg_id: AlgId,
        mnemonic: &str,
        passphrase: &str,
    ) -> Result<Self> {
        use bip39::Mnemonic;

        // Validate mnemonic
        let _m: Mnemonic = mnemonic
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid mnemonic: {e}"))?;

        let mut bip39_seed = bip39_seed_from_mnemonic(mnemonic, "");
        let mut xi = derive_ml_dsa_seed(&bip39_seed, alg_id);
        bip39_seed.zeroize();

        let keystore = Self::create_from_seed(chain_id, alg_id, &xi, passphrase)?;
        xi.zeroize();

        Ok(keystore)
    }

    /// Load a keystore from a JSON file on disk.
    pub fn load(path: &std::path::Path) -> Result<Self> {
        let data = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read keystore from {}", path.display()))?;
        let ks: Keystore = serde_json::from_str(&data)
            .with_context(|| format!("failed to parse keystore JSON from {}", path.display()))?;
        if ks.version > 1 {
            bail!(
                "keystore version {} is not supported by this binary — upgrade pqcd",
                ks.version
            );
        }
        Ok(ks)
    }

    /// Save the keystore as JSON to disk.
    ///
    /// Creates parent directories if they don't exist.
    pub fn save(&self, path: &std::path::Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed to create directory {}", parent.display()))?;
        }
        let json =
            serde_json::to_string_pretty(self).context("failed to serialize keystore to JSON")?;
        std::fs::write(path, json.as_bytes())
            .with_context(|| format!("failed to write keystore to {}", path.display()))?;
        // On Unix, set file permissions to 0600. On Windows, skip (ACL is different).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                .with_context(|| format!("failed to set permissions on {}", path.display()))?;
        }
        Ok(())
    }

    /// Decrypt the 32-byte signing seed from this keystore.
    pub fn decrypt_seed(&self, passphrase: &str) -> Result<[u8; 32]> {
        decrypt_seed(&self.crypto, passphrase)
    }

    /// Return the 32-byte raw address from the stored hex address.
    pub fn address(&self) -> Result<[u8; 32]> {
        let bytes = hex::decode(&self.address).context("invalid hex address in keystore")?;
        if bytes.len() != 32 {
            bail!("address must be 32 bytes, got {}", bytes.len());
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        Ok(out)
    }

    /// Return the raw chain_id bytes this keystore is bound to (ADR-053 §T1.3).
    pub fn chain_id_bytes(&self) -> Result<Vec<u8>> {
        hex::decode(&self.chain_id).context("invalid hex chain_id in keystore")
    }

    /// Return the raw public key bytes from the keystore (no passphrase needed).
    pub fn public_key_bytes(&self) -> Result<Vec<u8>> {
        hex::decode(&self.public_key).context("invalid hex public_key in keystore")
    }

    /// Parse the AlgId from the stored hex string.
    pub fn parsed_alg_id(&self) -> Result<AlgId> {
        let s = self.alg_id.strip_prefix("0x").unwrap_or(&self.alg_id);
        let raw = u16::from_str_radix(s, 16)
            .with_context(|| format!("invalid alg_id: {}", self.alg_id))?;
        AlgId::from_u16(raw).with_context(|| format!("unknown algorithm id: 0x{raw:04x}"))
    }

    /// Sign an unsigned transaction (CBOR bytes).
    ///
    /// Decrypts the seed, derives the keypair, builds the preimage,
    /// signs, and assembles the signed transaction CBOR.
    /// Zeroizes all sensitive material after use.
    pub fn sign_transaction(&self, passphrase: &str, unsigned_tx_cbor: &[u8]) -> Result<Vec<u8>> {
        let alg_id = self.parsed_alg_id()?;
        let mut xi = self.decrypt_seed(passphrase)?;

        // Decode the unsigned transaction.
        let mut tx = pqc_tx::codec::decode_tx(unsigned_tx_cbor)
            .map_err(|e| anyhow::anyhow!("failed to decode unsigned tx: {e}"))?;

        // Build the signing preimage (SPEC-TX-001 §9 + ADR-053 §T1.2).
        let fork_digest = pqc_types::ForkDigest::viper_research_1();
        let preimage = pqc_tx::preimage::build_preimage(&fork_digest, &tx)
            .map_err(|e| anyhow::anyhow!("failed to build preimage: {e}"))?;

        // Sign.
        let signature = pqc_crypto::ml_dsa_sign_with_seed(alg_id, &xi, &preimage)
            .map_err(|e| anyhow::anyhow!("signing failed: {e}"))?;

        xi.zeroize();

        // Set signature fields on the transaction.
        tx.signature = signature;
        tx.sig_alg_id = alg_id;

        // Re-encode as signed CBOR.
        let signed_cbor = pqc_tx::codec::encode_tx(&tx)
            .map_err(|e| anyhow::anyhow!("failed to encode signed tx: {e}"))?;

        Ok(signed_cbor)
    }
}

// ── Encryption / Decryption helpers ──────────────────────────────────────────

/// Encrypt a 32-byte seed using Argon2id + XChaCha20-Poly1305.
fn encrypt_seed(seed: &[u8; 32], passphrase: &str) -> Result<KeystoreCrypto> {
    use argon2::Argon2;
    use chacha20poly1305::{
        aead::{Aead, KeyInit},
        XChaCha20Poly1305, XNonce,
    };
    use rand::RngCore;

    // Generate random salt (32 bytes) and nonce (24 bytes).
    let mut salt = [0u8; 32];
    let mut nonce_bytes = [0u8; 24];
    rand::rng().fill_bytes(&mut salt);
    rand::rng().fill_bytes(&mut nonce_bytes);

    // Argon2id KDF: passphrase → 32-byte encryption key.
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(65536, 3, 1, Some(32))
            .map_err(|e| anyhow::anyhow!("argon2 params error: {e}"))?,
    );
    let mut encryption_key = [0u8; 32];
    argon2
        .hash_password_into(passphrase.as_bytes(), &salt, &mut encryption_key)
        .map_err(|e| anyhow::anyhow!("argon2 hashing failed: {e}"))?;

    // XChaCha20-Poly1305 encrypt.
    let cipher = XChaCha20Poly1305::new((&encryption_key).into());
    let nonce = XNonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, seed.as_ref())
        .map_err(|e| anyhow::anyhow!("encryption failed: {e}"))?;

    encryption_key.zeroize();

    Ok(KeystoreCrypto {
        kdf: "argon2id".to_string(),
        kdf_params: KdfParams {
            m_cost: 65536,
            t_cost: 3,
            p_cost: 1,
            salt: hex::encode(salt),
        },
        cipher: "xchacha20-poly1305".to_string(),
        nonce: hex::encode(nonce_bytes),
        ciphertext: hex::encode(ciphertext),
    })
}

/// Decrypt a 32-byte seed from keystore crypto fields.
fn decrypt_seed(crypto: &KeystoreCrypto, passphrase: &str) -> Result<[u8; 32]> {
    use argon2::Argon2;
    use chacha20poly1305::{
        aead::{Aead, KeyInit},
        XChaCha20Poly1305, XNonce,
    };

    let salt = hex::decode(&crypto.kdf_params.salt).context("invalid salt hex in keystore")?;
    let nonce_bytes = hex::decode(&crypto.nonce).context("invalid nonce hex in keystore")?;
    let ciphertext =
        hex::decode(&crypto.ciphertext).context("invalid ciphertext hex in keystore")?;

    if salt.len() != 32 {
        bail!("expected 32-byte salt, got {}", salt.len());
    }
    if nonce_bytes.len() != 24 {
        bail!("expected 24-byte nonce, got {}", nonce_bytes.len());
    }

    // Argon2id KDF.
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(
            crypto.kdf_params.m_cost,
            crypto.kdf_params.t_cost,
            crypto.kdf_params.p_cost,
            Some(32),
        )
        .map_err(|e| anyhow::anyhow!("argon2 params error: {e}"))?,
    );
    let mut encryption_key = [0u8; 32];
    argon2
        .hash_password_into(passphrase.as_bytes(), &salt, &mut encryption_key)
        .map_err(|e| anyhow::anyhow!("argon2 hashing failed: {e}"))?;

    // XChaCha20-Poly1305 decrypt.
    let cipher = XChaCha20Poly1305::new((&encryption_key).into());
    let nonce = XNonce::from_slice(&nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|_| anyhow::anyhow!("invalid passphrase (decryption authentication failed)"))?;

    encryption_key.zeroize();

    if plaintext.len() != 32 {
        bail!("decrypted seed has wrong length: {}", plaintext.len());
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&plaintext);
    Ok(seed)
}

// ── AlgId parsing helper ─────────────────────────────────────────────────────

/// Parse an algorithm name from CLI flag to AlgId.
pub fn parse_alg_flag(name: &str) -> Result<AlgId> {
    match name {
        "ml-dsa-44" => Ok(AlgId::MlDsa44),
        "ml-dsa-65" => Ok(AlgId::MlDsa65),
        "ml-dsa-87" => Ok(AlgId::MlDsa87),
        _ => bail!("unsupported algorithm: {name}. Supported: ml-dsa-44, ml-dsa-65, ml-dsa-87"),
    }
}

/// Default wallet directory (~/.viper/).
pub fn default_wallet_dir() -> Result<std::path::PathBuf> {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .context("could not determine home directory (set HOME or USERPROFILE)")?;
    Ok(std::path::PathBuf::from(home).join(".viper"))
}

/// Default keystore path for a given address.
pub fn default_keystore_path(address_hex: &str) -> Result<std::path::PathBuf> {
    Ok(default_wallet_dir()?
        .join("keystore")
        .join(format!("{address_hex}.json")))
}

// ── Unit tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;

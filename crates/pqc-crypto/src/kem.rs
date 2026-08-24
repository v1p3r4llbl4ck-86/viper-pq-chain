// SPDX-License-Identifier: Apache-2.0
//! ML-KEM-768 key encapsulation (FIPS 203) — P2P session key agreement.
//!
//! Used exclusively for the P2P transport handshake (ADR-010).
//! Every node generates a static ML-KEM-768 keypair at startup derived
//! deterministically from its node identifier. A connecting peer encapsulates
//! a 32-byte session key to the server's public key; the server decapsulates
//! to recover the same shared secret. All subsequent block transfers are
//! authenticated with a SHAKE-256–derived token over that shared secret.
//!
//! # Serialization
//!
//! The decapsulation key is stored as a 64-byte FIPS 203 seed (`d || z`),
//! the compact and preferred form in ml-kem 0.3.x. The expanded 2400-byte
//! form is deprecated upstream. Only the encapsulation key (1184 bytes) and
//! ciphertext (1088 bytes) are transmitted over the wire.
//!
//! # Sizes (ML-KEM-768, FIPS 203 Table 2)
//!
//! | Object             | Bytes |
//! |--------------------|-------|
//! | Encapsulation key  | 1184  |
//! | Seed (dk storage)  |   64  |
//! | Ciphertext         | 1088  |
//! | Shared secret      |   32  |
//!
//! # Feature flag
//!
//! Enabled by `kem-backend`. Without it the module is empty (no public items).

pub const KEM_PK_LEN: usize = 1184;
/// Decapsulation key stored as a 64-byte FIPS 203 seed (d || z).
pub const KEM_SK_LEN: usize = 64;
pub const KEM_CT_LEN: usize = 1088;
pub const KEM_SS_LEN: usize = 32;

/// ML-KEM-768 decapsulation seed (`d || z`, 64 bytes, FIPS 203 §5.1).
///
/// Wraps the raw seed bytes with `ZeroizeOnDrop` so memory is securely wiped
/// when the value goes out of scope. This is the defensible pattern for
/// long-lived secrets held in process memory: the producer (`kem_generate`)
/// returns a self-erasing newtype rather than a raw `[u8; 64]`, preventing
/// accidental leakage through `Clone`d copies that outlive the original.
///
/// `Clone` is still supported — each clone is independently zeroized on drop.
///
/// To obtain the raw bytes for APIs that take `&[u8; KEM_SK_LEN]`, call
/// [`KemSeed::as_bytes`]. To transfer ownership of the raw bytes (e.g. for
/// persistent storage that performs its own zeroization), use
/// [`KemSeed::into_bytes`] — the caller becomes responsible for wiping.
#[derive(Clone, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct KemSeed(pub [u8; KEM_SK_LEN]);

impl KemSeed {
    /// Borrow the raw 64-byte seed. Use with `kem_decapsulate`.
    #[inline]
    pub fn as_bytes(&self) -> &[u8; KEM_SK_LEN] {
        &self.0
    }

    /// Consume the wrapper and return the inner bytes WITHOUT zeroization.
    ///
    /// The caller takes ownership of the secret material and MUST ensure it
    /// is zeroized before drop (e.g. store in another `Zeroize` wrapper, or
    /// call `.zeroize()` manually). Prefer [`Self::as_bytes`] where possible.
    #[inline]
    pub fn into_bytes(mut self) -> [u8; KEM_SK_LEN] {
        // Take the bytes out, then forget `self` so the drop impl does NOT
        // zeroize the copy we are about to return.
        let out = self.0;
        self.0 = [0u8; KEM_SK_LEN];
        // Our own .0 is now zero; `ZeroizeOnDrop` re-zeros it harmlessly.
        out
    }
}

impl core::fmt::Debug for KemSeed {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Never print seed bytes — even truncated. Auditor-defensive.
        f.debug_struct("KemSeed").field("len", &KEM_SK_LEN).finish()
    }
}

#[cfg(feature = "kem-backend")]
mod backend {
    use ml_kem::array::Array;
    use ml_kem::ml_kem_768::{DecapsulationKey, EncapsulationKey};
    use ml_kem::{
        kem::{Ciphertext, FromSeed},
        Decapsulate, Key, KeyExport, MlKem768, Seed, B32,
    };

    use super::{KemSeed, KEM_CT_LEN, KEM_PK_LEN, KEM_SK_LEN};

    /// Generate a deterministic ML-KEM-768 keypair from two 32-byte seeds.
    ///
    /// `d` and `z` correspond to the FIPS 203 §5.1 key-generation seeds.
    /// The 64-byte seed `d || z` is passed to `from_seed`, which is the
    /// canonical deterministic constructor in ml-kem 0.3.x.
    ///
    /// Returns `(encapsulation_key_bytes, KemSeed)` where `KemSeed` is a
    /// `ZeroizeOnDrop` wrapper around the 64-byte decapsulation seed. The
    /// wrapper self-erases when dropped, preventing seed residue in memory.
    pub fn kem_generate(d: &[u8; 32], z: &[u8; 32]) -> ([u8; KEM_PK_LEN], KemSeed) {
        let mut seed_bytes = [0u8; 64];
        seed_bytes[..32].copy_from_slice(d);
        seed_bytes[32..].copy_from_slice(z);
        // SAFETY: seed_bytes is always exactly 64 bytes — built from two [u8; 32] copies above.
        let seed: Seed = Array::try_from(&seed_bytes[..])
            .expect("seed_bytes is exactly 64 bytes — statically guaranteed by caller");
        let (_, ek) = MlKem768::from_seed(&seed);
        let pk_key = ek.to_bytes();
        let pk_ref: &[u8] = pk_key.as_ref();
        // SAFETY: ML-KEM-768 encapsulation key is always 1184 bytes per FIPS 203 Table 2.
        let pk: [u8; KEM_PK_LEN] = pk_ref
            .try_into()
            .expect("ML-KEM-768 encapsulation key is always 1184 bytes per FIPS 203 Table 2");
        (pk, KemSeed(seed_bytes))
    }

    /// Encapsulate a 32-byte shared secret to the given ML-KEM-768 public key.
    ///
    /// `rand` must be 32 bytes of cryptographically secure randomness (FIPS 203 §6.2).
    /// The caller is responsible for supplying randomness — see `pqcd::devnet` for
    /// the production call site using `getrandom::fill`.
    ///
    /// Returns `Ok((ciphertext_bytes, shared_secret))` on success, or
    /// `Err(CryptoError::KemInvalidKey)` if `pk` fails ML-KEM mathematical
    /// validation. Returning an error instead of panicking ensures that an
    /// adversarial peer supplying a malformed KEM public key cannot crash the node.
    pub fn kem_encapsulate(
        pk: &[u8; KEM_PK_LEN],
        rand: &[u8; 32],
    ) -> Result<([u8; KEM_CT_LEN], [u8; 32]), crate::CryptoError> {
        let pk_key: Key<EncapsulationKey> =
            Array::try_from(&pk[..]).map_err(|_| crate::CryptoError::InvalidKeySize)?;
        let ek = EncapsulationKey::new(&pk_key).map_err(|_| crate::CryptoError::KemInvalidKey)?;
        let m: B32 = Array::try_from(&rand[..]).map_err(|_| crate::CryptoError::InvalidKeySize)?;
        let (ct, ss) = ek.encapsulate_deterministic(&m);
        let ct_ref: &[u8] = ct.as_ref();
        // FIPS 203 Table 2: ML-KEM-768 ciphertext is always exactly 1088 bytes.
        let ct_bytes: [u8; KEM_CT_LEN] = ct_ref
            .try_into()
            .expect("ML-KEM-768 ciphertext is always 1088 bytes per FIPS 203 Table 2");
        let ss_ref: &[u8] = ss.as_ref();
        // FIPS 203 §4.1: shared secret is always exactly 32 bytes.
        let ss_bytes: [u8; 32] = ss_ref
            .try_into()
            .expect("ML-KEM-768 shared secret is always 32 bytes per FIPS 203 §4.1");
        Ok((ct_bytes, ss_bytes))
    }

    /// Decapsulate a ciphertext with the ML-KEM-768 seed.
    ///
    /// ML-KEM decapsulation is infallible: an invalid ciphertext returns a
    /// pseudo-random key (implicit rejection — FIPS 203 §6.3) rather than an
    /// error. The caller cannot distinguish a bad ciphertext from a valid one
    /// by the return value alone; authentication of the session in higher layers
    /// catches injection attempts.
    ///
    /// Returns the 32-byte shared secret.
    pub fn kem_decapsulate(sk: &[u8; KEM_SK_LEN], ct: &[u8; KEM_CT_LEN]) -> [u8; 32] {
        // SAFETY: sk is typed as &[u8; KEM_SK_LEN] = &[u8; 64] — size is enforced by the type.
        let seed: Seed = Array::try_from(&sk[..])
            .expect("sk is exactly KEM_SK_LEN bytes — enforced by caller type signature");
        let (dk, _): (DecapsulationKey, _) = MlKem768::from_seed(&seed);
        // SAFETY: ct is typed as &[u8; KEM_CT_LEN] = &[u8; 1088] — size is enforced by the type.
        let ct_arr: Ciphertext<MlKem768> = Array::try_from(&ct[..])
            .expect("ct is exactly KEM_CT_LEN bytes — enforced by caller type signature");
        let ss = dk.decapsulate(&ct_arr);
        let ss_ref: &[u8] = ss.as_ref();
        // FIPS 203 §4.1: shared secret is always exactly 32 bytes.
        ss_ref
            .try_into()
            .expect("ML-KEM-768 shared secret is always 32 bytes per FIPS 203 §4.1")
    }
}

#[cfg(feature = "kem-backend")]
pub use backend::{kem_decapsulate, kem_encapsulate, kem_generate};
// `KemSeed` is exported unconditionally so downstream crates can type struct
// fields with the ZeroizeOnDrop wrapper even when `kem-backend` is disabled.

#[cfg(all(test, feature = "kem-backend"))]
mod tests {
    use super::*;

    const D: [u8; 32] = [0xD1; 32];
    const Z: [u8; 32] = [0xD2; 32];

    #[test]
    fn kem768_round_trip_shared_secret() {
        let (pk, sk) = kem_generate(&D, &Z);
        let rand = [0xE5; 32]; // deterministic encapsulation seed for test
        let (ct, ss_sender) = kem_encapsulate(&pk, &rand).expect("valid key from kem_generate");
        let ss_receiver = kem_decapsulate(sk.as_bytes(), &ct);
        assert_eq!(
            ss_sender, ss_receiver,
            "encapsulator and decapsulator must derive the same shared secret"
        );
    }

    #[test]
    fn kem768_wrong_sk_gives_different_secret() {
        let (pk, _sk1) = kem_generate(&D, &Z);
        let (_pk2, sk2) = kem_generate(&[0xAA; 32], &[0xBB; 32]);
        let rand = [0xE5; 32];
        let (ct, ss_sender) = kem_encapsulate(&pk, &rand).expect("valid key from kem_generate");
        // Decapsulate with wrong key — FIPS 203 implicit rejection: returns a
        // pseudo-random key, NOT the correct shared secret.
        let ss_wrong = kem_decapsulate(sk2.as_bytes(), &ct);
        assert_ne!(
            ss_sender, ss_wrong,
            "wrong decapsulation key must yield a different (pseudo-random) shared secret"
        );
    }

    #[test]
    fn kem768_deterministic_keypair() {
        let (pk1, sk1) = kem_generate(&D, &Z);
        let (pk2, sk2) = kem_generate(&D, &Z);
        assert_eq!(pk1, pk2, "same seeds must produce the same public key");
        assert_eq!(
            sk1.as_bytes(),
            sk2.as_bytes(),
            "same seeds must produce the same secret key"
        );
    }

    #[test]
    fn kem_seed_debug_does_not_leak_bytes() {
        let (_pk, sk) = kem_generate(&D, &Z);
        let rendered = format!("{sk:?}");
        // Debug must never contain the hex of any seed byte — auditor-defensive.
        // Check for the full-byte hex of the first seed byte (0xD1 → "d1"/"D1").
        let lower = rendered.to_lowercase();
        assert!(
            !lower.contains("d1") && !lower.contains("d2"),
            "KemSeed Debug leaked seed bytes: {rendered}"
        );
    }

    #[test]
    fn kem_seed_into_bytes_preserves_value() {
        let (_pk, sk) = kem_generate(&D, &Z);
        let expected = *sk.as_bytes();
        let raw = sk.into_bytes();
        assert_eq!(raw, expected, "into_bytes must return the seed unchanged");
    }
}

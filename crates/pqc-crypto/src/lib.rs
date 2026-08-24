// SPDX-License-Identifier: Apache-2.0
//! pqc-crypto — Post-quantum signature and KEM abstractions.
//!
//! This crate owns the boundary between PQ Chain protocol logic and the
//! underlying cryptographic implementations (liboqs, mldsa-native, etc.).
//! All other crates call into this crate; none import a crypto library directly.
//!
//! # Algorithm identifiers
//!
//! `AlgId` values are assigned in SPEC-ACCOUNT-001 §7 (Algorithm Registry).
//! The initial Phase 1 registry is defined in [`registry`].
//!
//! # Lifecycle
//!
//! Every algorithm has a [`Lifecycle`] status. The protocol rejects signatures
//! whose algorithm is not `Active` at mempool admission (SPEC-TX-001 §8, step 3).

pub mod address;
pub mod alg;
pub mod envelope;
pub mod error;
pub mod hash;
pub mod hash_registry;
pub mod kem;
pub mod registry;
pub mod sign;
pub mod verify;

pub use address::{address_to_bech32m, bech32m_to_address, derive_address, ADDRESS_DOMAIN_V1};
pub use alg::{AlgId, Lifecycle, SigClass};
pub use envelope::{
    decode_pk_envelope, decode_sig_envelope, encode_pk_envelope, encode_sig_envelope,
};
pub use error::CryptoError;
pub use hash::{
    binary_merkle_root, shake256_32, shake256_n, tagged_hash, Shake256Hasher, TaggedHasher,
};
pub use hash_registry::{
    phase1_hash_registry, HashEntry, HashId, HASH_CORE_RESERVED_MAX, HASH_ID_SENTINEL,
    HASH_ID_SHAKE_256,
};
pub use sign::{PublicKey, Signature, SignatureVerifier};

#[cfg(feature = "ml-dsa-backend")]
pub use verify::MlDsaVerifier;

#[cfg(feature = "ml-dsa-backend")]
pub use sign::{ml_dsa_public_key_from_seed, ml_dsa_sign_with_seed};

#[cfg(feature = "slh-dsa-backend")]
pub use sign::{
    slh_dsa_sha2_128s_generate, slh_dsa_sha2_128s_sign, slh_dsa_shake_128s_generate,
    slh_dsa_shake_128s_sign, slh_dsa_shake_192s_generate, slh_dsa_shake_192s_sign,
    slh_dsa_shake_256s_generate, slh_dsa_shake_256s_sign,
};

#[cfg(feature = "pq-verifier")]
pub use verify::PqVerifier;

#[cfg(feature = "kem-backend")]
pub use kem::{
    kem_decapsulate, kem_encapsulate, kem_generate, KemSeed, KEM_CT_LEN, KEM_PK_LEN, KEM_SK_LEN,
    KEM_SS_LEN,
};

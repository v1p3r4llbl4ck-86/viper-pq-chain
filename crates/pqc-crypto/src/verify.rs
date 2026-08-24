// SPDX-License-Identifier: Apache-2.0
//! Real post-quantum signature verifier — ML-DSA (FIPS 204).
//!
//! Enabled with feature `ml-dsa-backend`. The production node binary should
//! depend on `pqc-crypto` with this feature; test harnesses continue to use
//! `StubVerifier` (feature `stub-verifier`) to avoid real key generation overhead.
//!
//! `MlDsaVerifier` implements the `SignatureVerifier` trait and dispatches on
//! `AlgId` to ML-DSA-44, ML-DSA-65, or ML-DSA-87.

#[cfg(feature = "ml-dsa-backend")]
mod inner {
    use ml_dsa::{
        signature::Verifier, EncodedVerifyingKey, MlDsa44, MlDsa65, MlDsa87, Signature as MlDsaSig,
        VerifyingKey,
    };

    use crate::{
        sign::{PublicKey, Signature, SignatureVerifier},
        AlgId, CryptoError,
    };

    /// Production ML-DSA verifier backed by the RustCrypto `ml-dsa` crate (FIPS 204).
    ///
    /// Dispatches on `AlgId` to the appropriate ML-DSA parameter set.
    /// Rejects KEM identifiers, algorithm mismatches, and malformed keys/signatures.
    pub struct MlDsaVerifier;

    impl SignatureVerifier for MlDsaVerifier {
        fn verify(
            &self,
            public_key: &PublicKey,
            preimage: &[u8],
            signature: &Signature,
        ) -> Result<(), CryptoError> {
            if public_key.alg_id != signature.alg_id {
                return Err(CryptoError::NotASigningAlgorithm(signature.alg_id));
            }

            match signature.alg_id {
                AlgId::MlDsa44 => verify_ml_dsa_44(&public_key.bytes, preimage, &signature.bytes),
                AlgId::MlDsa65 => verify_ml_dsa_65(&public_key.bytes, preimage, &signature.bytes),
                AlgId::MlDsa87 => verify_ml_dsa_87(&public_key.bytes, preimage, &signature.bytes),
                other => Err(CryptoError::NotASigningAlgorithm(other)),
            }
        }
    }

    fn verify_ml_dsa_44(
        pk_bytes: &[u8],
        preimage: &[u8],
        sig_bytes: &[u8],
    ) -> Result<(), CryptoError> {
        let enc = EncodedVerifyingKey::<MlDsa44>::try_from(pk_bytes)
            .map_err(|_| CryptoError::InvalidKeySize)?;
        let vk = VerifyingKey::<MlDsa44>::decode(&enc);
        let sig = MlDsaSig::<MlDsa44>::try_from(sig_bytes)
            .map_err(|_| CryptoError::InvalidSignatureSize)?;
        vk.verify(preimage, &sig)
            .map_err(|_| CryptoError::VerificationFailed)
    }

    fn verify_ml_dsa_65(
        pk_bytes: &[u8],
        preimage: &[u8],
        sig_bytes: &[u8],
    ) -> Result<(), CryptoError> {
        let enc = EncodedVerifyingKey::<MlDsa65>::try_from(pk_bytes)
            .map_err(|_| CryptoError::InvalidKeySize)?;
        let vk = VerifyingKey::<MlDsa65>::decode(&enc);
        let sig = MlDsaSig::<MlDsa65>::try_from(sig_bytes)
            .map_err(|_| CryptoError::InvalidSignatureSize)?;
        vk.verify(preimage, &sig)
            .map_err(|_| CryptoError::VerificationFailed)
    }

    fn verify_ml_dsa_87(
        pk_bytes: &[u8],
        preimage: &[u8],
        sig_bytes: &[u8],
    ) -> Result<(), CryptoError> {
        let enc = EncodedVerifyingKey::<MlDsa87>::try_from(pk_bytes)
            .map_err(|_| CryptoError::InvalidKeySize)?;
        let vk = VerifyingKey::<MlDsa87>::decode(&enc);
        let sig = MlDsaSig::<MlDsa87>::try_from(sig_bytes)
            .map_err(|_| CryptoError::InvalidSignatureSize)?;
        vk.verify(preimage, &sig)
            .map_err(|_| CryptoError::VerificationFailed)
    }
}

#[cfg(feature = "ml-dsa-backend")]
pub use inner::MlDsaVerifier;

/// Production multi-algorithm verifier: ML-DSA (all parameter sets) + SLH-DSA-SHA2-128s.
///
/// FN-DSA-padded-512 returns `NotASigningAlgorithm` — FIPS 206 is not yet finalized (GAP-01,
/// AUDIT-SCOPE-001 §6). Transactions signed with FN-DSA are rejected at mempool admission
/// until TASK-063 is extended with the finalized standard.
///
/// This is the verifier used in the production node binary. Test harnesses continue to use
/// `StubVerifier` for fast iteration without real key material overhead.
#[cfg(feature = "pq-verifier")]
mod pq_inner {
    use slh_dsa::signature::Verifier as SlhVerifier;
    use slh_dsa::{Sha2_128s, Shake128s, Shake192s, Shake256s, VerifyingKey};

    use crate::{
        sign::{PublicKey, Signature, SignatureVerifier},
        verify::inner::MlDsaVerifier,
        AlgId, CryptoError,
    };

    pub struct PqVerifier;

    impl SignatureVerifier for PqVerifier {
        fn verify(
            &self,
            public_key: &PublicKey,
            preimage: &[u8],
            signature: &Signature,
        ) -> Result<(), CryptoError> {
            if public_key.alg_id != signature.alg_id {
                return Err(CryptoError::NotASigningAlgorithm(signature.alg_id));
            }

            match signature.alg_id {
                AlgId::MlDsa44 | AlgId::MlDsa65 | AlgId::MlDsa87 => {
                    MlDsaVerifier.verify(public_key, preimage, signature)
                }
                AlgId::SlhDsaSha2128s => {
                    verify_slh_dsa_128s(&public_key.bytes, preimage, &signature.bytes)
                }
                AlgId::SlhDsaShake128s => {
                    verify_slh_dsa_shake_128s(&public_key.bytes, preimage, &signature.bytes)
                }
                AlgId::SlhDsaShake192s => {
                    verify_slh_dsa_shake_192s(&public_key.bytes, preimage, &signature.bytes)
                }
                AlgId::SlhDsaShake256s => {
                    verify_slh_dsa_shake_256s(&public_key.bytes, preimage, &signature.bytes)
                }
                AlgId::FnDsaPadded512 => {
                    // GAP-01: FIPS 206 (FN-DSA) is not yet finalised. The
                    // algorithm registry reserves this slot (see
                    // registry.rs `phase1_registry` FN-DSA entry + its
                    // "RESERVED SLOT" comment), but no implementation
                    // exists. Returning NotASigningAlgorithm here means
                    // any tx signed with FnDsa is rejected before block
                    // inclusion, even if it makes it into the mempool.
                    //
                    // **Why this is honest, not a bug:** the registry
                    // entry exists so a future governance
                    // `ProposalEffect::AddAlgorithm` can flip on the
                    // implementation by adding the verifier branch (and
                    // pinning the standard's params) without an enum
                    // change. Until that happens, the verifier path is
                    // the source of truth: FnDsa is not a signing
                    // algorithm yet. See AUDIT-SCOPE-001 §6, GAP-01.
                    Err(CryptoError::NotASigningAlgorithm(AlgId::FnDsaPadded512))
                }
                other => Err(CryptoError::NotASigningAlgorithm(other)),
            }
        }
    }

    fn verify_slh_dsa_128s(
        pk_bytes: &[u8],
        preimage: &[u8],
        sig_bytes: &[u8],
    ) -> Result<(), CryptoError> {
        let vk = VerifyingKey::<Sha2_128s>::try_from(pk_bytes)
            .map_err(|_| CryptoError::InvalidKeySize)?;
        let sig = slh_dsa::Signature::<Sha2_128s>::try_from(sig_bytes)
            .map_err(|_| CryptoError::InvalidSignatureSize)?;
        vk.verify(preimage, &sig)
            .map_err(|_| CryptoError::VerificationFailed)
    }

    fn verify_slh_dsa_shake_128s(
        pk_bytes: &[u8],
        preimage: &[u8],
        sig_bytes: &[u8],
    ) -> Result<(), CryptoError> {
        let vk = VerifyingKey::<Shake128s>::try_from(pk_bytes)
            .map_err(|_| CryptoError::InvalidKeySize)?;
        let sig = slh_dsa::Signature::<Shake128s>::try_from(sig_bytes)
            .map_err(|_| CryptoError::InvalidSignatureSize)?;
        vk.verify(preimage, &sig)
            .map_err(|_| CryptoError::VerificationFailed)
    }

    fn verify_slh_dsa_shake_192s(
        pk_bytes: &[u8],
        preimage: &[u8],
        sig_bytes: &[u8],
    ) -> Result<(), CryptoError> {
        let vk = VerifyingKey::<Shake192s>::try_from(pk_bytes)
            .map_err(|_| CryptoError::InvalidKeySize)?;
        let sig = slh_dsa::Signature::<Shake192s>::try_from(sig_bytes)
            .map_err(|_| CryptoError::InvalidSignatureSize)?;
        vk.verify(preimage, &sig)
            .map_err(|_| CryptoError::VerificationFailed)
    }

    fn verify_slh_dsa_shake_256s(
        pk_bytes: &[u8],
        preimage: &[u8],
        sig_bytes: &[u8],
    ) -> Result<(), CryptoError> {
        let vk = VerifyingKey::<Shake256s>::try_from(pk_bytes)
            .map_err(|_| CryptoError::InvalidKeySize)?;
        let sig = slh_dsa::Signature::<Shake256s>::try_from(sig_bytes)
            .map_err(|_| CryptoError::InvalidSignatureSize)?;
        vk.verify(preimage, &sig)
            .map_err(|_| CryptoError::VerificationFailed)
    }
}

#[cfg(feature = "pq-verifier")]
pub use pq_inner::PqVerifier;

#[cfg(all(test, feature = "ml-dsa-backend"))]
mod tests {
    use getrandom::rand_core::UnwrapErr;
    use ml_dsa::{
        signature::{Keypair, SignatureEncoding, Signer},
        KeyGen, MlDsa65,
    };

    use crate::{
        sign::{PublicKey, Signature, SignatureVerifier},
        verify::MlDsaVerifier,
        AlgId,
    };

    fn gen_kp() -> ml_dsa::SigningKey<MlDsa65> {
        let mut rng = UnwrapErr(getrandom::SysRng);
        MlDsa65::key_gen(&mut rng)
    }

    /// Sign a preimage with a freshly generated ML-DSA-65 keypair and verify
    /// with MlDsaVerifier. This is the minimal KAT-style round-trip that
    /// confirms the real crypto backend is wired end-to-end.
    #[test]
    fn mldsa65_real_sign_and_verify_round_trip() {
        let kp = gen_kp();
        let vk = kp.verifying_key();
        let preimage = b"PQC-TX-V1\x00test-preimage";
        let sig: ml_dsa::Signature<MlDsa65> = kp.signing_key().sign(preimage);

        let pk = PublicKey {
            alg_id: AlgId::MlDsa65,
            bytes: vk.encode().to_vec(),
        };
        let signature = Signature {
            alg_id: AlgId::MlDsa65,
            bytes: sig.to_bytes().as_slice().to_vec(),
        };

        MlDsaVerifier
            .verify(&pk, preimage, &signature)
            .expect("valid ML-DSA-65 signature must verify");
    }

    #[test]
    fn mldsa65_tampered_preimage_is_rejected() {
        let kp = gen_kp();
        let vk = kp.verifying_key();
        let preimage = b"PQC-TX-V1\x00test-preimage";
        let sig: ml_dsa::Signature<MlDsa65> = kp.signing_key().sign(preimage);

        let pk = PublicKey {
            alg_id: AlgId::MlDsa65,
            bytes: vk.encode().to_vec(),
        };
        let signature = Signature {
            alg_id: AlgId::MlDsa65,
            bytes: sig.to_bytes().as_slice().to_vec(),
        };

        let result = MlDsaVerifier.verify(&pk, b"PQC-TX-V1\x00tampered", &signature);
        assert!(result.is_err(), "tampered preimage must not verify");
    }

    #[test]
    fn mldsa65_wrong_key_is_rejected() {
        let kp1 = gen_kp();
        let kp2 = gen_kp();
        let preimage = b"PQC-TX-V1\x00test-preimage";
        let sig: ml_dsa::Signature<MlDsa65> = kp1.signing_key().sign(preimage);

        // kp2's verifying key, kp1's signature
        let pk = PublicKey {
            alg_id: AlgId::MlDsa65,
            bytes: kp2.verifying_key().encode().to_vec(),
        };
        let signature = Signature {
            alg_id: AlgId::MlDsa65,
            bytes: sig.to_bytes().as_slice().to_vec(),
        };

        let result = MlDsaVerifier.verify(&pk, preimage, &signature);
        assert!(result.is_err(), "wrong key must not verify");
    }
}

#[cfg(all(test, feature = "pq-verifier"))]
mod pq_verifier_tests {
    use crate::{
        sign::{PublicKey, Signature, SignatureVerifier},
        slh_dsa_sha2_128s_generate, slh_dsa_sha2_128s_sign, slh_dsa_shake_192s_generate,
        slh_dsa_shake_192s_sign, slh_dsa_shake_256s_generate, slh_dsa_shake_256s_sign,
        verify::PqVerifier,
        AlgId,
    };

    /// Sign with SLH-DSA-SHA2-128s and verify with PqVerifier.
    /// This is the end-to-end path exercised by the post-rotation canary tx.
    #[test]
    fn slh_dsa_sha2_128s_sign_and_verify_round_trip() {
        let (pk_bytes, sk_bytes) =
            slh_dsa_sha2_128s_generate().expect("key generation must succeed");
        assert_eq!(pk_bytes.len(), 32, "pk must be 32 bytes");
        assert_eq!(sk_bytes.len(), 64, "sk must be 64 bytes");

        let preimage = b"PQC-TX-V1\x00test-slh-dsa-preimage";
        let sig_bytes = slh_dsa_sha2_128s_sign(&sk_bytes, preimage).expect("signing must succeed");
        assert_eq!(
            sig_bytes.len(),
            7856,
            "SLH-DSA-SHA2-128s sig must be 7856 bytes"
        );

        let pk = PublicKey {
            alg_id: AlgId::SlhDsaSha2128s,
            bytes: pk_bytes,
        };
        let sig = Signature {
            alg_id: AlgId::SlhDsaSha2128s,
            bytes: sig_bytes,
        };
        PqVerifier
            .verify(&pk, preimage, &sig)
            .expect("valid SLH-DSA-SHA2-128s signature must verify");
    }

    #[test]
    fn slh_dsa_sha2_128s_tampered_preimage_is_rejected() {
        let (pk_bytes, sk_bytes) =
            slh_dsa_sha2_128s_generate().expect("key generation must succeed");
        let preimage = b"PQC-TX-V1\x00test-slh-dsa-preimage";
        let sig_bytes = slh_dsa_sha2_128s_sign(&sk_bytes, preimage).expect("signing must succeed");

        let pk = PublicKey {
            alg_id: AlgId::SlhDsaSha2128s,
            bytes: pk_bytes,
        };
        let sig = Signature {
            alg_id: AlgId::SlhDsaSha2128s,
            bytes: sig_bytes,
        };
        let result = PqVerifier.verify(&pk, b"PQC-TX-V1\x00tampered", &sig);
        assert!(result.is_err(), "tampered preimage must not verify");
    }

    // ── SLH-DSA-SHAKE-192s (ADR-043, TASK-114) ─────────────────────────────
    //
    // The second PQ signature algorithm for Phase 8. Hash-based (vs
    // ML-DSA-65's lattice family) so a break in one family does not
    // compromise both. The backend bindings (`slh_dsa_shake_192s_*`
    // in sign.rs, `verify_slh_dsa_shake_192s` in verify.rs), the
    // AlgId variant, the verifier dispatch, the registry entry, and
    // the consensus-alg predicate were all plumbed earlier —
    // TASK-114 asked for end-to-end roundtrip test coverage to close
    // the acceptance criterion, which is what these two tests
    // provide.

    #[test]
    fn slh_dsa_shake_192s_sign_and_verify_round_trip() {
        let (pk_bytes, sk_bytes) =
            slh_dsa_shake_192s_generate().expect("key generation must succeed");
        assert_eq!(
            pk_bytes.len(),
            48,
            "SLH-DSA-SHAKE-192s pk must be 48 bytes (FIPS 205 §10.3)"
        );
        assert_eq!(
            sk_bytes.len(),
            96,
            "SLH-DSA-SHAKE-192s sk must be 96 bytes (FIPS 205 §10.3)"
        );

        let preimage = b"PQC-TX-V1\x00test-slh-dsa-shake-192s-preimage";
        let sig_bytes = slh_dsa_shake_192s_sign(&sk_bytes, preimage).expect("signing must succeed");
        assert_eq!(
            sig_bytes.len(),
            16_224,
            "SLH-DSA-SHAKE-192s sig must be 16 224 bytes (FIPS 205 §10.3 \
             — matches the registry entry in registry.rs:92–100 that \
             `verify_block_commit_quorum` relies on for size prefixing)"
        );

        let pk = PublicKey {
            alg_id: AlgId::SlhDsaShake192s,
            bytes: pk_bytes,
        };
        let sig = Signature {
            alg_id: AlgId::SlhDsaShake192s,
            bytes: sig_bytes,
        };
        PqVerifier
            .verify(&pk, preimage, &sig)
            .expect("valid SLH-DSA-SHAKE-192s signature must verify");
    }

    #[test]
    fn slh_dsa_shake_192s_tampered_preimage_is_rejected() {
        let (pk_bytes, sk_bytes) =
            slh_dsa_shake_192s_generate().expect("key generation must succeed");
        let preimage = b"PQC-TX-V1\x00test-slh-dsa-shake-192s-preimage";
        let sig_bytes = slh_dsa_shake_192s_sign(&sk_bytes, preimage).expect("signing must succeed");

        let pk = PublicKey {
            alg_id: AlgId::SlhDsaShake192s,
            bytes: pk_bytes,
        };
        let sig = Signature {
            alg_id: AlgId::SlhDsaShake192s,
            bytes: sig_bytes,
        };
        let result = PqVerifier.verify(&pk, b"PQC-TX-V1\x00tampered", &sig);
        assert!(
            result.is_err(),
            "tampered preimage MUST NOT verify — guards the PqVerifier \
             dispatch arm at verify.rs:136–138 against silently passing \
             a mismatched preimage through to `verify_slh_dsa_shake_192s`"
        );
    }

    #[test]
    fn slh_dsa_shake_192s_wrong_key_is_rejected() {
        let (_pk_a, sk_a) = slh_dsa_shake_192s_generate().expect("gen A");
        let (pk_b, _sk_b) = slh_dsa_shake_192s_generate().expect("gen B");
        let preimage = b"PQC-TX-V1\x00slh-dsa-shake-192s-wrong-key";
        let sig_bytes =
            slh_dsa_shake_192s_sign(&sk_a, preimage).expect("signing with A must succeed");

        // B's pk, A's signature — verify MUST fail.
        let pk = PublicKey {
            alg_id: AlgId::SlhDsaShake192s,
            bytes: pk_b,
        };
        let sig = Signature {
            alg_id: AlgId::SlhDsaShake192s,
            bytes: sig_bytes,
        };
        let result = PqVerifier.verify(&pk, preimage, &sig);
        assert!(
            result.is_err(),
            "SLH-DSA-SHAKE-192s verification with a wrong pk must fail"
        );
    }

    // ── SLH-DSA-SHAKE-256s (ADR-045, TASK-162) ─────────────────────────────
    //
    // NIST Category 5 (FIPS 205) hash-based signature for the M4 archival
    // signing path. The backend bindings (`slh_dsa_shake_256s_*` in sign.rs,
    // `verify_slh_dsa_shake_256s` in verify.rs), the AlgId variant, the
    // verifier dispatch arm, and the registry entry (pk 64 B, sig 29 792 B,
    // SigClass::Premium, benchmark_verify_per_sec 132) were all plumbed
    // earlier — TASK-162 adds end-to-end roundtrip coverage matching the
    // TASK-114 pattern used for the 192s fallback.

    #[test]
    fn slh_dsa_shake_256s_sign_and_verify_round_trip() {
        let (pk_bytes, sk_bytes) =
            slh_dsa_shake_256s_generate().expect("key generation must succeed");
        assert_eq!(
            pk_bytes.len(),
            64,
            "SLH-DSA-SHAKE-256s pk must be 64 bytes (FIPS 205 §10.3)"
        );
        assert_eq!(
            sk_bytes.len(),
            128,
            "SLH-DSA-SHAKE-256s sk must be 128 bytes (FIPS 205 §10.3)"
        );

        let preimage = b"PQC-TX-V1\x00test-slh-dsa-shake-256s-preimage";
        let sig_bytes = slh_dsa_shake_256s_sign(&sk_bytes, preimage).expect("signing must succeed");
        assert_eq!(
            sig_bytes.len(),
            29_792,
            "SLH-DSA-SHAKE-256s sig must be 29 792 bytes (FIPS 205 §10.3 \
             — matches the Cat 5 archival registry entry in registry.rs:137–146 \
             used by the M4 archival overlay per ADR-045)"
        );

        let pk = PublicKey {
            alg_id: AlgId::SlhDsaShake256s,
            bytes: pk_bytes,
        };
        let sig = Signature {
            alg_id: AlgId::SlhDsaShake256s,
            bytes: sig_bytes,
        };
        PqVerifier
            .verify(&pk, preimage, &sig)
            .expect("valid SLH-DSA-SHAKE-256s signature must verify");
    }

    #[test]
    fn slh_dsa_shake_256s_tampered_preimage_is_rejected() {
        let (pk_bytes, sk_bytes) =
            slh_dsa_shake_256s_generate().expect("key generation must succeed");
        let preimage = b"PQC-TX-V1\x00test-slh-dsa-shake-256s-preimage";
        let sig_bytes = slh_dsa_shake_256s_sign(&sk_bytes, preimage).expect("signing must succeed");

        let pk = PublicKey {
            alg_id: AlgId::SlhDsaShake256s,
            bytes: pk_bytes,
        };
        let sig = Signature {
            alg_id: AlgId::SlhDsaShake256s,
            bytes: sig_bytes,
        };
        let result = PqVerifier.verify(&pk, b"PQC-TX-V1\x00tampered", &sig);
        assert!(
            result.is_err(),
            "tampered preimage MUST NOT verify — guards the PqVerifier \
             dispatch arm at verify.rs SlhDsaShake256s arm against silently \
             passing a mismatched preimage through to `verify_slh_dsa_shake_256s`"
        );
    }

    #[test]
    fn slh_dsa_shake_256s_wrong_key_is_rejected() {
        let (_pk_a, sk_a) = slh_dsa_shake_256s_generate().expect("gen A");
        let (pk_b, _sk_b) = slh_dsa_shake_256s_generate().expect("gen B");
        let preimage = b"PQC-TX-V1\x00slh-dsa-shake-256s-wrong-key";
        let sig_bytes =
            slh_dsa_shake_256s_sign(&sk_a, preimage).expect("signing with A must succeed");

        // B's pk, A's signature — verify MUST fail.
        let pk = PublicKey {
            alg_id: AlgId::SlhDsaShake256s,
            bytes: pk_b,
        };
        let sig = Signature {
            alg_id: AlgId::SlhDsaShake256s,
            bytes: sig_bytes,
        };
        let result = PqVerifier.verify(&pk, preimage, &sig);
        assert!(
            result.is_err(),
            "SLH-DSA-SHAKE-256s verification with a wrong pk must fail"
        );
    }

    /// Pins the FN-DSA reserved-slot semantics: the algorithm is in the
    /// registry (so the alg_id codepoint is reserved against accidental
    /// reuse), but the verifier explicitly rejects every signature. A
    /// future regression that wires up a partial implementation would
    /// flip this from `NotASigningAlgorithm` to either `VerificationFailed`
    /// or a `Ok(())`, both of which would fail this test.
    ///
    /// See `registry.rs::phase1_registry` FN-DSA docstring and
    /// `verify.rs::PqVerifier::verify` GAP-01 arm for the full reasoning.
    #[test]
    fn fn_dsa_is_registered_but_verifier_rejects() {
        use crate::CryptoError;
        // Synthetic pk/sig — never decoded, the verifier rejects before
        // looking at the bytes (alg_id alone is the rejection signal).
        let pk = PublicKey {
            alg_id: AlgId::FnDsaPadded512,
            bytes: vec![0u8; 897],
        };
        let sig = Signature {
            alg_id: AlgId::FnDsaPadded512,
            bytes: vec![0u8; 666],
        };
        let preimage = b"PQC-TX-V1\x00fn-dsa-must-reject";
        match PqVerifier.verify(&pk, preimage, &sig) {
            Err(CryptoError::NotASigningAlgorithm(AlgId::FnDsaPadded512)) => {}
            Err(other) => {
                panic!("FN-DSA must reject with NotASigningAlgorithm, got Err({other:?})")
            }
            Ok(()) => {
                panic!("FN-DSA verify must NEVER succeed — reserved slot, FIPS 206 draft, no impl")
            }
        }
    }
}

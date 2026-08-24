// SPDX-License-Identifier: BUSL-1.1
//! Tests for `local`.

#![allow(clippy::unwrap_used, clippy::expect_used)]
use super::*;
use crate::canary::CANARY_PREIMAGE;
use pqc_crypto::sign::{PublicKey, Signature, SignatureVerifier};
use pqc_crypto::MlDsaVerifier;

/// Round-trip: build a signer, sign the canary preimage, verify
/// with the production `MlDsaVerifier`. This is the same path the
/// trait's default `self_test` exercises, but exposed here as an
/// explicit pin so a regression in `from_seed` surfaces directly.
#[test]
fn local_signer_round_trip_against_ml_dsa_verifier() {
    let addr = [0xAA; 32];
    let seed = [0x11; 32];
    let signer = LocalKeystoreSigner::from_seed(addr, AlgId::MlDsa65, seed).unwrap();

    // Identity check: the trait accessors return the bytes the
    // pre-trait LocalCommitSigner stored directly.
    assert_eq!(signer.validator_address(), &addr);
    assert_eq!(signer.alg_id(), AlgId::MlDsa65);
    assert_eq!(signer.kind(), SignerKind::LocalKeystore);
    assert_eq!(
        signer.public_key(),
        &ml_dsa_public_key_from_seed(AlgId::MlDsa65, &seed).unwrap()[..]
    );

    // Sign the canary; verify against the cached pubkey.
    let sig_bytes = signer.sign_commit(CANARY_PREIMAGE).unwrap();
    let pk = PublicKey {
        alg_id: AlgId::MlDsa65,
        bytes: signer.public_key().to_vec(),
    };
    let sig = Signature {
        alg_id: AlgId::MlDsa65,
        bytes: sig_bytes,
    };
    MlDsaVerifier
        .verify(&pk, CANARY_PREIMAGE, &sig)
        .expect("ML-DSA-65 round trip");
}

#[test]
fn self_test_passes_for_local_signer() {
    // The `CommitSigner::self_test` default impl signs the canary
    // and verifies via MlDsaVerifier. For a correctly-constructed
    // local signer this MUST succeed.
    let signer = LocalKeystoreSigner::from_seed([0xAA; 32], AlgId::MlDsa65, [0x22; 32]).unwrap();
    signer.self_test().expect("canary self-test must pass");
}

#[test]
fn from_keystore_entry_accepts_matching_pubkey() {
    let alg = AlgId::MlDsa65;
    let seed = [0x33; 32];
    let pk = ml_dsa_public_key_from_seed(alg, &seed).unwrap();
    let signer =
        LocalKeystoreSigner::from_keystore_entry([0x12; 32], alg, seed, pk.clone()).unwrap();
    assert_eq!(signer.public_key(), &pk[..]);
}

#[test]
fn from_keystore_entry_rejects_mismatched_pubkey() {
    // Cached pubkey doesn't derive from the seed → BackendMismatch.
    // This is the steady-state "keystore tampered" detector.
    let alg = AlgId::MlDsa65;
    let seed = [0x33; 32];
    let wrong_pk = ml_dsa_public_key_from_seed(alg, &[0x44; 32]).unwrap();
    let err =
        LocalKeystoreSigner::from_keystore_entry([0x12; 32], alg, seed, wrong_pk).unwrap_err();
    assert!(
        matches!(err, SignerError::BackendMismatch(_)),
        "got: {err:?}"
    );
}

#[test]
fn from_seed_rejects_non_ml_dsa_algorithm() {
    // The local signer dispatch only covers ML-DSA. Calling with a
    // KEM or SLH-DSA alg surfaces an InvalidPreimage (config bug).
    let err = LocalKeystoreSigner::from_seed([0; 32], AlgId::MlKem768, [0; 32]).unwrap_err();
    assert!(matches!(err, SignerError::InvalidPreimage(_)));
    let err = LocalKeystoreSigner::from_seed([0; 32], AlgId::SlhDsaShake192s, [0; 32]).unwrap_err();
    assert!(matches!(err, SignerError::InvalidPreimage(_)));
}

#[test]
fn local_signer_works_under_dyn_dispatch() {
    // Object-safety pin: the consensus loop carries
    // `Vec<Box<dyn CommitSigner>>`. Make sure the impl is callable
    // through that indirection.
    let signer: Box<dyn CommitSigner> =
        Box::new(LocalKeystoreSigner::from_seed([0xCC; 32], AlgId::MlDsa65, [0x55; 32]).unwrap());
    assert_eq!(signer.alg_id(), AlgId::MlDsa65);
    let sig = signer.sign_commit(CANARY_PREIMAGE).unwrap();
    assert!(!sig.is_empty(), "ML-DSA-65 signature must be non-empty");
    signer.self_test().expect("self-test through dyn dispatch");
}

#[test]
fn signing_distinct_preimages_yields_distinct_signatures() {
    // Sanity check that the underlying ML-DSA sign path actually
    // depends on the preimage — guards against a regression that
    // would silently sign a fixed value.
    let signer = LocalKeystoreSigner::from_seed([0; 32], AlgId::MlDsa65, [0x77; 32]).unwrap();
    let s1 = signer.sign_commit(b"alpha").unwrap();
    let s2 = signer.sign_commit(b"beta").unwrap();
    assert_ne!(s1, s2, "ML-DSA signatures over distinct preimages diverge");
}

#[test]
fn ml_dsa_44_and_87_round_trip_through_self_test() {
    for alg in [AlgId::MlDsa44, AlgId::MlDsa87] {
        let signer = LocalKeystoreSigner::from_seed([0; 32], alg, [0x99; 32]).unwrap();
        signer
            .self_test()
            .unwrap_or_else(|e| panic!("self-test failed for {alg:?}: {e:?}"));
    }
}

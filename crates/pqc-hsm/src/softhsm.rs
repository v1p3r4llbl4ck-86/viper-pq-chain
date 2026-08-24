// SPDX-License-Identifier: BUSL-1.1
//! `SoftHsmSigner` — PKCS#11-backed `CommitSigner` for SoftHSM2 dev/CI.
//!
//! # Why RSA-2048 (placeholder), not ML-DSA?
//!
//! **Investors / auditors will ask: "Your post-quantum chain is signing
//! commits with RSA-2048?!" The answer is: only on this dev/CI backend,
//! and only for wiring exercise.**
//!
//! Per the private design notes:
//!
//! > SoftHSM2 (current upstream as of 2026-05) implements PKCS#11 v3.0
//! > mechanisms. ML-DSA mechanisms (`CKM_ML_DSA_*`) were added in
//! > PKCS#11 v3.2 (2024) and SoftHSM2 has not yet shipped them.
//! > RSA-2048 is the *placeholder* mechanism used to exercise the
//! > PKCS#11 wiring path during integration. Real ML-DSA happens on
//! > AWS CloudHSM.
//!
//! The `CommitSigner` trait abstracts the algorithm. This SoftHSM impl
//! exists to exercise the load-bearing risks — module load, slot
//! discovery, login, key-handle lookup, sign round-trip, error
//! classification — none of which depend on whether the mechanism is
//! RSA-2048 or ML-DSA-65. When SoftHSM2 ships ML-DSA support, swap the
//! `Mechanism::Sha256RsaPkcs` constant in [`SoftHsmSigner::sign_commit`]
//! and the [`SoftHsmSigner::alg_id`] return value; the rest of the
//! plumbing is correct.
//!
//! **Production validators MUST NOT use this signer.** It is gated
//! behind the `softhsm` cargo feature (off by default) and the
//! `SignerKind::SoftHsm` config variant is documented as "CI-only —
//! never production".
//!
//! # Mechanism choice — `CKM_SHA256_RSA_PKCS` (RSA-PKCS#1 v1.5 + SHA-256)
//!
//! `cryptoki` exposes both `Mechanism::RsaPkcsPss` and
//! `Mechanism::Sha256RsaPkcs`. We pick the latter because:
//!
//!   1. `CKM_SHA256_RSA_PKCS` hashes inside the HSM — the host never
//!      sees the digest, matching the production posture where the
//!      operator's signing seed never leaves the device.
//!   2. PSS would require a `PkcsPssParams` struct and a salt-length
//!      decision; PKCS#1 v1.5 has zero parameters and produces
//!      deterministic signatures, which is friendlier for the canary
//!      verification path that compares against a fixed sig in tests.
//!   3. Every PKCS#11 v2.x+ module supports `CKM_SHA256_RSA_PKCS`;
//!      `CKM_RSA_PKCS_PSS` requires v2.20+. SoftHSM2 ships both, but
//!      AWS CloudHSM legacy clusters historically lacked PSS.
//!
//! # Public-key caching
//!
//! At construction we read `CKA_PUBLIC_KEY_INFO` (DER-encoded
//! `SubjectPublicKeyInfo`) from the public key handle and cache the
//! bytes. Subsequent `public_key()` calls return the cached value with
//! no PKCS#11 round-trip. If the HSM session dies later, sign attempts
//! will fail with `HsmUnavailable` — `public_key()` keeps working.
//!
//! # Self-test override
//!
//! The default `CommitSigner::self_test` impl uses the ML-DSA verifier
//! and would fail-closed for RSA. We override `self_test` here to
//! verify the canary signature using the RSA-PSS / RSA-PKCS path
//! through the host (cheaper than the full ML-DSA path) — see
//! [`SoftHsmSigner::self_test`] for details.

use std::sync::Mutex;

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, AttributeType, ObjectClass, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;

use crate::config::SignerKind;
use crate::error::SignerError;
use crate::signer::CommitSigner;
use pqc_crypto::AlgId;

/// PKCS#11-backed RSA-2048 placeholder commit signer.
///
/// **NOT FOR PRODUCTION** — see module-level docs for the rationale.
/// The signer holds an open `Session` and the resolved private/public
/// `ObjectHandle` pair for the configured key label. Concurrent
/// `sign_commit` calls serialise on the session mutex; PKCS#11 sessions
/// are not internally synchronised.
pub struct SoftHsmSigner {
    /// PKCS#11 module handle. Held to keep the dynamically loaded
    /// shared library alive for the signer's lifetime.
    _pkcs11: Pkcs11,
    /// Authenticated session against the slot. PKCS#11 sessions are
    /// single-threaded by spec; we serialise via `Mutex`.
    session: Mutex<Session>,
    /// Resolved private-key object handle for the configured label.
    private_key: ObjectHandle,
    /// 32-byte operator address. Same shape as `LocalKeystoreSigner` —
    /// derived from a SHA-256 hash of the cached SPKI bytes; SoftHSM
    /// has no native concept of "validator address" so we derive a
    /// stable one from the pubkey to keep the trait surface honest.
    validator_address: [u8; 32],
    /// Cached `SubjectPublicKeyInfo` DER bytes (CKA_PUBLIC_KEY_INFO).
    public_key: Vec<u8>,
}

/// `SoftHsmSigner` is `Send + Sync` because every interior-mutated
/// field (`session`) lives behind a `Mutex`. The `Pkcs11` handle is
/// itself `Send + Sync` per the cryptoki crate's impls. The
/// `ObjectHandle` is a plain `u64` newtype — trivially thread-safe.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<SoftHsmSigner>();
};

impl std::fmt::Debug for SoftHsmSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SoftHsmSigner")
            .field("validator_address", &hex::encode(self.validator_address))
            .field("public_key_len", &self.public_key.len())
            .field("private_key_handle", &"<opaque>")
            .finish()
    }
}

impl SoftHsmSigner {
    /// Open a PKCS#11 session, log in, resolve the key pair by label,
    /// and cache the SPKI bytes. Maps every PKCS#11 failure to a
    /// `SignerError` variant per the `is_transient` contract.
    ///
    /// `module_path` — absolute path to the PKCS#11 shared library
    /// (e.g. `/usr/lib/softhsm/libsofthsm2.so`).
    /// `slot_id` — numeric slot ID (NOT the slot label; PKCS#11 slot
    /// IDs are opaque u64s assigned by the module).
    /// `user_pin` — USER PIN for `C_Login`.
    /// `key_label` — `CKA_LABEL` to match against; both the public and
    /// private key objects MUST share this label.
    pub fn open(
        module_path: &str,
        slot_id: u64,
        user_pin: &str,
        key_label: &str,
    ) -> Result<Self, SignerError> {
        let pkcs11 = Pkcs11::new(module_path).map_err(|e| {
            SignerError::HsmUnavailable(format!("failed to load PKCS#11 module {module_path}: {e}"))
        })?;
        pkcs11
            .initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
            .map_err(|e| {
                SignerError::HsmUnavailable(format!("PKCS#11 C_Initialize failed: {e}"))
            })?;

        let slot = Slot::try_from(slot_id).map_err(|e| {
            SignerError::InvalidPreimage(format!("slot_id {slot_id} out of range: {e}"))
        })?;

        let session = pkcs11.open_ro_session(slot).map_err(|e| {
            SignerError::HsmUnavailable(format!("open_ro_session(slot={slot_id}) failed: {e}"))
        })?;
        session
            .login(UserType::User, Some(&AuthPin::new(user_pin.into())))
            .map_err(|e| {
                SignerError::HsmUnavailable(format!(
                    "C_Login(USER) on slot {slot_id} failed: {e} \
                     — is the PIN correct and the token initialised?"
                ))
            })?;

        let private_key = find_unique_object(
            &session,
            &[
                Attribute::Class(ObjectClass::PRIVATE_KEY),
                Attribute::Label(key_label.as_bytes().to_vec()),
            ],
            "private",
            key_label,
        )?;
        let public_key_handle = find_unique_object(
            &session,
            &[
                Attribute::Class(ObjectClass::PUBLIC_KEY),
                Attribute::Label(key_label.as_bytes().to_vec()),
            ],
            "public",
            key_label,
        )?;

        // Cache the SubjectPublicKeyInfo DER bytes. CKA_PUBLIC_KEY_INFO
        // is the standard PKCS#11 v3.0 attribute; SoftHSM2 supports it
        // for RSA keys.
        let attrs = session
            .get_attributes(public_key_handle, &[AttributeType::PublicKeyInfo])
            .map_err(|e| {
                SignerError::Other(anyhow::anyhow!(
                    "C_GetAttributeValue(CKA_PUBLIC_KEY_INFO) failed: {e}"
                ))
            })?;
        let spki_bytes = attrs
            .into_iter()
            .find_map(|a| match a {
                Attribute::PublicKeyInfo(b) => Some(b),
                _ => None,
            })
            .ok_or_else(|| {
                SignerError::BackendMismatch(format!(
                    "PKCS#11 public key object '{key_label}' did not return CKA_PUBLIC_KEY_INFO; \
                     SoftHSM2 must be built with PKCS#11 v3.0 attribute support"
                ))
            })?;

        // Derive the validator address from the SPKI bytes. SoftHSM has
        // no notion of an operator address, but downstream consumers
        // (`snapshot_block_signers`) need a stable 32-byte tag. SHA-256
        // of the SPKI is deterministic, collision-resistant, and unique
        // per key.
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&spki_bytes);
        let digest = hasher.finalize();
        let mut validator_address = [0u8; 32];
        validator_address.copy_from_slice(&digest);

        Ok(Self {
            _pkcs11: pkcs11,
            session: Mutex::new(session),
            private_key,
            validator_address,
            public_key: spki_bytes,
        })
    }
}

/// Find exactly one PKCS#11 object matching the template. Errors
/// (with backend-classified variants) on:
///
///   - zero matches → `BackendMismatch` (the configured label is wrong)
///   - >1 match → `BackendMismatch` (slot has duplicate labels — ambiguous)
///   - PKCS#11 RPC failure → `HsmUnavailable`
fn find_unique_object(
    session: &Session,
    template: &[Attribute],
    role: &str,
    key_label: &str,
) -> Result<ObjectHandle, SignerError> {
    let handles = session.find_objects(template).map_err(|e| {
        SignerError::HsmUnavailable(format!(
            "C_FindObjects (looking for {role} key '{key_label}') failed: {e}"
        ))
    })?;
    match handles.len() {
        0 => Err(SignerError::BackendMismatch(format!(
            "no {role} key with label '{key_label}' found in slot — \
             check `pkcs11-tool --list-objects` and the SoftHSM2 setup"
        ))),
        1 => {
            let h = handles.into_iter().next().ok_or_else(|| {
                SignerError::Other(anyhow::anyhow!("unreachable: len==1 but iter empty"))
            })?;
            Ok(h)
        }
        n => Err(SignerError::BackendMismatch(format!(
            "ambiguous {role} key lookup: {n} objects with label '{key_label}' \
             — slot has duplicates; remove or rename"
        ))),
    }
}

impl CommitSigner for SoftHsmSigner {
    fn validator_address(&self) -> &[u8] {
        &self.validator_address
    }

    fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// Sign `preimage` via `CKM_SHA256_RSA_PKCS`. The HSM hashes the
    /// preimage internally and returns a 256-byte RSA-2048 signature
    /// (PKCS#1 v1.5 padding).
    fn sign_commit(&self, preimage: &[u8]) -> Result<Vec<u8>, SignerError> {
        let session = self.session.lock().map_err(|_| {
            SignerError::Other(anyhow::anyhow!(
                "SoftHsmSigner session mutex poisoned — earlier panic in another thread"
            ))
        })?;
        session
            .sign(&Mechanism::Sha256RsaPkcs, self.private_key, preimage)
            .map_err(|e| {
                let msg = format!("PKCS#11 C_Sign(SHA256_RSA_PKCS) failed: {e}");
                // Cryptoki errors do not expose a stable kind enum we can
                // match on without depending on `Display` text. We
                // conservatively classify session/handle errors as
                // transient; the consensus loop's drop-from-set fallback
                // is safer than a permanent BackendMismatch on what is
                // typically a session timeout.
                SignerError::HsmUnavailable(msg)
            })
    }

    fn alg_id(&self) -> AlgId {
        // PLACEHOLDER — see module docs §"Why RSA-2048". The chain has
        // no `AlgId::Rsa2048` variant because RSA is not on the
        // post-quantum roadmap. We surface `MlDsa65` so the trait's
        // `consensus_alg_id` cross-check on validator records still
        // type-checks; the boot self-test override below handles the
        // mismatch by NOT using the ML-DSA verifier.
        //
        // Production deployments use AwsCloudHsmSigner with real
        // ML-DSA-65; this lie is only ever told to test code paths
        // that don't ultimately hit the chain.
        //
        // **Defense-in-depth (2026-05-11 audit follow-up)**: the
        // boot-bail in `pqcd::devnet::start_from_config_path` already
        // refuses to run `SignerKind::SoftHsm` against the live chain
        // (only `LocalKeystore` is admitted). The panic below is a
        // second line of defense: if a future maintainer adds a
        // `SoftHsm` arm to that match without realising `alg_id()`
        // lies, this `alg_id()` call will panic in any release build,
        // refusing to silently sign blocks under a forged PQ
        // algorithm tag. The `#[cfg(test)]` exemption keeps the test
        // suite functional. `debug_assertions` keeps the panic active
        // even in `cargo run` (debug) so the error surfaces at the
        // first cargo invocation that wires SoftHsm into the daemon,
        // not only at release.
        #[cfg(not(any(test, debug_assertions)))]
        panic!(
            "SoftHsmSigner::alg_id() returning AlgId::MlDsa65 is a documented placeholder \
             (see crates/pqc-hsm/src/softhsm.rs module docs). The underlying mechanism is \
             RSA-2048/SHA-256, NOT post-quantum ML-DSA. SoftHsm must not be wired into a \
             release build of pqcd — use `LocalKeystoreSigner` or a real `AwsCloudHsmSigner` \
             instead. If you reached this panic the boot-bail in \
             `pqcd::devnet::start_from_config_path` has been bypassed; restore it or remove \
             the SoftHsm arm before shipping."
        );
        #[allow(unreachable_code)]
        AlgId::MlDsa65
    }

    fn kind(&self) -> SignerKind {
        SignerKind::SoftHsm
    }

    /// Override of the trait default: the default uses
    /// `MlDsaVerifier` which would reject the RSA signature. We
    /// instead verify by signing the canary, then signing it AGAIN
    /// and confirming the same RSA-PKCS signature comes back
    /// (deterministic mechanism). This proves: (a) sign path works,
    /// (b) the cached pubkey handle still resolves, (c) the session
    /// is alive. It does NOT prove signature/pubkey cryptographic
    /// linkage — that requires a host-side RSA verifier, which we
    /// avoid pulling in to keep the dependency surface minimal.
    fn self_test(&self) -> Result<(), SignerError> {
        use crate::canary::CANARY_PREIMAGE;
        let s1 = self.sign_commit(CANARY_PREIMAGE)?;
        let s2 = self.sign_commit(CANARY_PREIMAGE)?;
        if s1 != s2 {
            return Err(SignerError::BackendMismatch(format!(
                "SoftHSM RSA-PKCS canary signatures differ across calls \
                 (len {} vs {}) — non-deterministic mechanism or session race",
                s1.len(),
                s2.len(),
            )));
        }
        if s1.is_empty() {
            return Err(SignerError::BackendMismatch(
                "SoftHSM canary signature was empty".to_string(),
            ));
        }
        // Sanity: RSA-2048 PKCS#1 v1.5 signatures are exactly 256 bytes.
        // A non-256 length means the slot has a non-2048-bit key or
        // SoftHSM is misconfigured.
        if s1.len() != 256 {
            return Err(SignerError::BackendMismatch(format!(
                "SoftHSM RSA-PKCS canary signature length {} != 256; \
                 expected RSA-2048 key but slot contained a different size",
                s1.len()
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;

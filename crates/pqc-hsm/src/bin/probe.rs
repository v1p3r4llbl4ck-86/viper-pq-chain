// SPDX-License-Identifier: BUSL-1.1
//! `viper-hsm-probe` — operator-facing CLI for HSM connectivity smoke tests.
//!
//! Per the private design notes binary": ships a
//! single executable an operator runs at deploy time to confirm the
//! HSM is reachable, the key label resolves, and a sign+self-verify
//! round-trip works end-to-end. Failure modes print the specific
//! `SignerError` variant so the operator can distinguish "wrong PIN"
//! from "module file missing" without tailing pqcd logs.
//!
//! # Backends
//!
//! - `--backend local` — synthesises a `LocalKeystoreSigner` from a
//!   user-supplied seed (or a deterministic dev seed). Useful as a
//!   "does the trait surface itself work on this host" check before
//!   the operator wires the real HSM.
//! - `--backend softhsm` — opens a `SoftHsmSigner` against the
//!   configured PKCS#11 module + slot + label + PIN. Requires the
//!   `softhsm` feature flag at build time.
//!
//! Adding a new backend (`aws-cloudhsm`, `yubihsm`, `thales`) is a
//! ~30-line addition: another arm of the `Backend` enum, a builder
//! function returning `Box<dyn CommitSigner>`, and the corresponding
//! flag set on `Args`. The probe loop itself is backend-agnostic.
//!
//! # Output
//!
//! On success: `OK` to stdout, exit 0.
//! On failure: structured failure message to stderr, exit 1.

use std::process::ExitCode;

use pqc_hsm::canary::CANARY_PREIMAGE;
use pqc_hsm::{AlgId, CommitSigner, LocalKeystoreSigner, SignerError};

/// CLI entry point. Returns the exit code via `ExitCode` instead of
/// panicking so help/error paths produce clean diagnostics.
fn main() -> ExitCode {
    match run(std::env::args().skip(1).collect()) {
        Ok(()) => {
            println!("OK");
            ExitCode::SUCCESS
        }
        Err(ProbeError::Usage(msg)) => {
            eprintln!("usage: {msg}");
            ExitCode::from(2)
        }
        Err(ProbeError::Signer(e)) => {
            eprintln!("FAIL [signer]: {e}");
            ExitCode::from(1)
        }
        Err(ProbeError::Other(msg)) => {
            eprintln!("FAIL [other]: {msg}");
            ExitCode::from(1)
        }
    }
}

#[derive(Debug)]
enum ProbeError {
    Usage(String),
    Signer(SignerError),
    Other(String),
}

impl From<SignerError> for ProbeError {
    fn from(e: SignerError) -> Self {
        Self::Signer(e)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Backend {
    Local,
    SoftHsm,
}

#[derive(Debug, Default)]
struct Args {
    backend: Option<Backend>,
    /// Common: key label / address tag.
    key_label: Option<String>,
    /// SoftHSM: module path. Default `/usr/lib/softhsm/libsofthsm2.so`.
    module_path: Option<String>,
    /// SoftHSM: slot id. Default 0.
    slot_id: Option<u64>,
    /// SoftHSM: USER PIN.
    pin: Option<String>,
    /// Local: 64-hex-char seed. Default deterministic dev seed.
    seed_hex: Option<String>,
}

fn parse_args(argv: Vec<String>) -> Result<Args, ProbeError> {
    let mut a = Args::default();
    let mut iter = argv.into_iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--help" | "-h" => {
                return Err(ProbeError::Usage(usage_text()));
            }
            "--backend" => {
                let v = iter
                    .next()
                    .ok_or_else(|| ProbeError::Usage("--backend requires a value".into()))?;
                a.backend = Some(match v.as_str() {
                    "local" => Backend::Local,
                    "softhsm" => Backend::SoftHsm,
                    other => {
                        return Err(ProbeError::Usage(format!(
                            "unknown backend '{other}' — try local|softhsm"
                        )))
                    }
                });
            }
            "--key-label" => {
                a.key_label = Some(
                    iter.next()
                        .ok_or_else(|| ProbeError::Usage("--key-label requires a value".into()))?,
                );
            }
            "--module-path" => {
                a.module_path =
                    Some(iter.next().ok_or_else(|| {
                        ProbeError::Usage("--module-path requires a value".into())
                    })?);
            }
            "--slot-id" => {
                let v = iter
                    .next()
                    .ok_or_else(|| ProbeError::Usage("--slot-id requires a value".into()))?;
                a.slot_id = Some(
                    v.parse()
                        .map_err(|e| ProbeError::Usage(format!("--slot-id parse: {e}")))?,
                );
            }
            "--pin" => {
                a.pin = Some(
                    iter.next()
                        .ok_or_else(|| ProbeError::Usage("--pin requires a value".into()))?,
                );
            }
            "--seed-hex" => {
                a.seed_hex = Some(
                    iter.next()
                        .ok_or_else(|| ProbeError::Usage("--seed-hex requires a value".into()))?,
                );
            }
            other => {
                return Err(ProbeError::Usage(format!("unknown flag: {other}")));
            }
        }
    }
    Ok(a)
}

fn usage_text() -> String {
    "viper-hsm-probe --backend {local|softhsm} --key-label <str> [backend-specific flags]\n\
     \n\
     Backend `local`:\n\
       --seed-hex <64hex>           (optional; default deterministic dev seed)\n\
     Backend `softhsm` (requires --features softhsm at build time):\n\
       --module-path <path>         (default /usr/lib/softhsm/libsofthsm2.so)\n\
       --slot-id <u64>              (default 0)\n\
       --pin <str>                  (USER PIN, required)\n\
     \n\
     Exits 0 on canary OK, 1 on signing failure, 2 on usage error."
        .to_string()
}

fn run(argv: Vec<String>) -> Result<(), ProbeError> {
    let args = parse_args(argv)?;
    let backend = args
        .backend
        .ok_or_else(|| ProbeError::Usage("--backend is required".into()))?;
    let key_label = args
        .key_label
        .ok_or_else(|| ProbeError::Usage("--key-label is required".into()))?;

    let signer: Box<dyn CommitSigner> = match backend {
        Backend::Local => build_local(&key_label, args.seed_hex.as_deref())?,
        Backend::SoftHsm => build_softhsm(
            &key_label,
            args.module_path.as_deref(),
            args.slot_id.unwrap_or(0),
            args.pin.as_deref(),
        )?,
    };

    eprintln!(
        "viper-hsm-probe: signer kind={:?} alg_id={:?} pubkey_len={} addr={}",
        signer.kind(),
        signer.alg_id(),
        signer.public_key().len(),
        hex::encode(signer.validator_address()),
    );

    // Sign canary, then run the backend's self_test (which also verifies
    // — for ML-DSA backends via the host MlDsaVerifier; for SoftHSM via
    // determinism + length sanity).
    let sig = signer.sign_commit(CANARY_PREIMAGE)?;
    if sig.is_empty() {
        return Err(ProbeError::Other(
            "canary signature was empty — backend produced 0 bytes".into(),
        ));
    }
    signer.self_test()?;
    eprintln!(
        "viper-hsm-probe: canary signed ({} bytes) and self_test passed",
        sig.len()
    );
    Ok(())
}

/// Synthesise a `LocalKeystoreSigner` from a 64-hex-char seed (or a
/// deterministic placeholder). The validator address is derived from
/// the key_label by SHA-256(label).
fn build_local(
    key_label: &str,
    seed_hex: Option<&str>,
) -> Result<Box<dyn CommitSigner>, ProbeError> {
    let seed_bytes = match seed_hex {
        Some(hex_str) => {
            let v = hex::decode(hex_str)
                .map_err(|e| ProbeError::Usage(format!("--seed-hex hex decode: {e}")))?;
            if v.len() != 32 {
                return Err(ProbeError::Usage(format!(
                    "--seed-hex must decode to 32 bytes, got {}",
                    v.len()
                )));
            }
            let mut s = [0u8; 32];
            s.copy_from_slice(&v);
            s
        }
        None => {
            // Deterministic dev seed — clearly recognisable in logs.
            let mut s = [0u8; 32];
            for (i, b) in s.iter_mut().enumerate() {
                *b = (i as u8) ^ 0xA5;
            }
            s
        }
    };

    // Derive validator address from key_label so the probe's identity
    // matches what an operator would see in logs.
    let mut addr = [0u8; 32];
    let label_bytes = key_label.as_bytes();
    let n = label_bytes.len().min(32);
    addr.get_mut(..n)
        .ok_or_else(|| ProbeError::Other("address slice OOB — unreachable".into()))?
        .copy_from_slice(
            label_bytes
                .get(..n)
                .ok_or_else(|| ProbeError::Other("label slice OOB — unreachable".into()))?,
        );

    let signer = LocalKeystoreSigner::from_seed(addr, AlgId::MlDsa65, seed_bytes)?;
    Ok(Box::new(signer))
}

#[cfg(feature = "softhsm")]
fn build_softhsm(
    key_label: &str,
    module_path: Option<&str>,
    slot_id: u64,
    pin: Option<&str>,
) -> Result<Box<dyn CommitSigner>, ProbeError> {
    use pqc_hsm::SoftHsmSigner;
    let module = module_path.unwrap_or("/usr/lib/softhsm/libsofthsm2.so");
    let pin = pin.ok_or_else(|| ProbeError::Usage("softhsm backend requires --pin".into()))?;
    let signer = SoftHsmSigner::open(module, slot_id, pin, key_label)?;
    Ok(Box::new(signer))
}

#[cfg(not(feature = "softhsm"))]
#[allow(clippy::unnecessary_wraps)]
fn build_softhsm(
    _key_label: &str,
    _module_path: Option<&str>,
    _slot_id: u64,
    _pin: Option<&str>,
) -> Result<Box<dyn CommitSigner>, ProbeError> {
    Err(ProbeError::Usage(
        "this binary was built without the `softhsm` cargo feature; \
         rebuild with `cargo build -p pqc-hsm --features softhsm` to enable"
            .into(),
    ))
}

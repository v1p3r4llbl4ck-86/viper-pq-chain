// SPDX-License-Identifier: BUSL-1.1
//! Sidecar-specific RFC 3161 helpers — TSA preimage construction and
//! the SHAKE-256 external_hash that lands in `ArchivalRecordAddAnchor`.
//!
//! The DER encoder for `TimeStampReq` itself was extracted to the
//! shared `pqc-tsa` crate on 2026-05-06 (closes ADR-060 D7) and is
//! re-exported here as `build_timestamp_request` for backward
//! compatibility. New callers should depend on `pqc_tsa` directly.
//!
//! The reply DER is forwarded opaquely — see SPEC §6.1: "the chain does
//! not verify the TST cryptographically on apply".

use pqc_crypto::TaggedHasher;

/// SPEC-ARCHIVAL-001 §6.1 domain separator for the TSA preimage.
pub const TSA_PREIMAGE_DOMAIN: &[u8] = b"VIPER-ARCHIVAL-TSA-V1";

/// Build the §6.1 TSA preimage bytes:
/// `domain || u64_be(epoch_number) || epoch_root`.
pub fn tsa_preimage(epoch_number: u64, epoch_root: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(TSA_PREIMAGE_DOMAIN.len() + 8 + 32);
    out.extend_from_slice(TSA_PREIMAGE_DOMAIN);
    out.extend_from_slice(&epoch_number.to_be_bytes());
    out.extend_from_slice(epoch_root);
    out
}

/// Compute `SHAKE-256(tst_bytes, 32)` — the on-chain `external_hash`
/// submitted alongside the DER bytes in `ArchivalRecordAddAnchor`.
///
/// The hash is independent of RFC 3161 semantics; it gives the chain a
/// 32-byte handle that never requires DER parsing during state-root
/// recompute (SPEC §7.5).
pub fn shake256_external_hash(tst_bytes: &[u8]) -> [u8; 32] {
    let mut d = TaggedHasher::new(b"VIPER-ARCHIVAL-TST-EXT-V1");
    d.push_u64(tst_bytes.len() as u64);
    d.push_chunk(tst_bytes);
    d.finish()
}

/// Backward-compat re-export of the shared encoder. New code should
/// depend on `pqc_tsa::build_timestamp_request` directly.
pub use pqc_tsa::build_timestamp_request;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tsa_preimage_is_byte_stable_and_domain_separated() {
        let root = [0xAA; 32];
        let p1 = tsa_preimage(5, &root);
        let p2 = tsa_preimage(5, &root);
        assert_eq!(p1, p2, "preimage must be byte-stable");

        let p_other_epoch = tsa_preimage(6, &root);
        assert_ne!(p1, p_other_epoch, "epoch number changes preimage");

        let mut root2 = root;
        root2[0] = 0xBB;
        let p_other_root = tsa_preimage(5, &root2);
        assert_ne!(p1, p_other_root, "epoch_root changes preimage");

        assert_eq!(&p1[..21], TSA_PREIMAGE_DOMAIN);
    }

    #[test]
    fn external_hash_is_domain_separated() {
        let tst = b"fake-TST-bytes-for-test";
        let h1 = shake256_external_hash(tst);
        let h2 = shake256_external_hash(tst);
        assert_eq!(h1, h2);
        let h3 = shake256_external_hash(b"other-TST");
        assert_ne!(h1, h3);
    }

    #[test]
    fn re_exported_encoder_matches_pqc_tsa_directly() {
        // Pin the re-export — a future refactor that drops the
        // `pub use` accidentally would break sidecar callers; this test
        // catches that drift before the call sites bit-rot.
        let digest = [0x37u8; 32];
        let via_reexport = build_timestamp_request(&digest);
        let via_direct = pqc_tsa::build_timestamp_request(&digest);
        assert_eq!(via_reexport, via_direct);
    }
}

// SPDX-License-Identifier: Apache-2.0
//! Fork digest — ADR-053 §T1.2.
//!
//! A 4-byte domain prefix scoped to `(fork_version, genesis_validators_root)`.
//! Prepended to every signing preimage — vote, proposal, transaction, archival
//! signature — to prevent cross-chain and cross-fork signature replay.
//!
//! ```text
//! ForkDigest = SHAKE-256(
//!     "VIPER-FORK-V1" || fork_version_u32_be || genesis_validators_root,
//!     output_len = 4,
//! )
//! ```
//!
//! The viper-pq-1 beacon-chain-style lesson (ADR-053 §T1.2, motivated by
//! Ethereum capella/deneb fork boundaries): without a genesis-scoped prefix, a
//! validator's signed vote on one chain is byte-identical to a signed vote on
//! any parallel chain that shares the same legacy domain tag. `ForkDigest`
//! closes that hole at signing time.
//!
//! At viper-pq-1 genesis the fork version is [`VIPER_FORK_VERSION_V1`]. Every
//! hard fork bumps the version and re-derives the digest; every signature made
//! after the fork therefore lives in a disjoint preimage space from every
//! signature made before.

use pqc_crypto::{shake256_n, AlgId, TaggedHasher};

use crate::account::Address;

/// Fork version for viper-pq-1 genesis. Bumped by every hard fork.
pub const VIPER_FORK_VERSION_V1: u32 = 1;

/// Domain-separation tag absorbed into the `ForkDigest` preimage.
pub const FORK_DIGEST_DOMAIN: &[u8] = b"VIPER-FORK-V1";

/// Domain-separation tag for the per-validator genesis leaf hash.
pub const GENESIS_VALIDATOR_LEAF_DOMAIN: &[u8] = b"VIPER-VALIDATOR-GENESIS-LEAF-V1";

/// Domain-separation tag for the genesis validator set aggregate root.
pub const GENESIS_VALIDATORS_ROOT_DOMAIN: &[u8] = b"VIPER-VALIDATORS-ROOT-V1";

/// 4-byte fork digest — the signing-domain prefix for a specific
/// `(fork_version, genesis_validators_root)` pair (ADR-053 §T1.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ForkDigest(pub [u8; 4]);

impl ForkDigest {
    /// Compute the fork digest from the fork version and the genesis validator
    /// set root.
    pub fn compute(fork_version: u32, genesis_validators_root: &[u8; 32]) -> Self {
        let fv_be = fork_version.to_be_bytes();
        Self(shake256_n::<4>(&[
            FORK_DIGEST_DOMAIN,
            &fv_be,
            genesis_validators_root,
        ]))
    }

    /// Raw 4-byte digest. Used as the preimage prefix by every signing path.
    pub fn as_bytes(&self) -> &[u8; 4] {
        &self.0
    }

    /// Fork digest for `viper-pq-1` — the canonical signing-domain prefix
    /// for the permanent development chain launched 2026-04-25.
    ///
    /// Computed from `(VIPER_FORK_VERSION_V1, VIPER_PQ_1_GENESIS_VALIDATORS_ROOT)`
    /// where the root is the deterministic commitment to the 3-validator
    /// genesis set in `deploy/ansible/files/genesis-viper-pq-1.json`.
    ///
    /// Every production signing path on `viper-pq-1` uses this digest. The
    /// computation is pinned by the unit test below so any change to the
    /// genesis validator set (which would require a chain reset under the
    /// pre-binding-window posture, per AGENTS.md §40) surfaces immediately.
    pub fn viper_pq_1() -> Self {
        Self::compute(VIPER_FORK_VERSION_V1, &VIPER_PQ_1_GENESIS_VALIDATORS_ROOT)
    }

    /// Fork digest for `viper-research-1` — the tokenless permissioned PoA
    /// research substrate that succeeds `viper-pq-1` at the 2026-05-11 pivot
    /// cutover (Fase 5).
    ///
    /// Computed from `(VIPER_FORK_VERSION_V1, VIPER_RESEARCH_1_GENESIS_VALIDATORS_ROOT)`
    /// where the root is the deterministic commitment to the 3-validator
    /// genesis set freshly generated at the Fase 5 keystore ceremony and
    /// committed in `deploy/ansible/files/genesis-viper-research-1.json`.
    ///
    /// **At the time of writing the constant is a sentinel placeholder
    /// (`[0xDE, 0xAD, …]`).** The real root is computed by
    /// a one-off migration script (private) from the live
    /// pubkeys of the freshly-generated keystores; the operator pins it
    /// here, runs `cargo test -p pqc-types fork::tests::viper_research_1_root_pin`
    /// to confirm, and rebuilds the production binary.
    ///
    /// **Cutover procedure (Fase 5):**
    /// 1. Generate fresh ML-DSA-65 keystores for the 3 validators.
    /// 2. Run `python3 a one-off migration script (private)
    ///    with the 3 pubkeys → it writes the final genesis JSON and prints
    ///    the computed root.
    /// 3. Replace `VIPER_RESEARCH_1_GENESIS_VALIDATORS_ROOT` below with the
    ///    printed bytes.
    /// 4. Run `cargo test -p pqc-types fork::tests::viper_research_1_root_pin`.
    /// 5. Sed-replace `ForkDigest::viper_pq_1` → `ForkDigest::viper_research_1`
    ///    across `crates/` (14 call sites as of 2026-05-11).
    /// 6. Build the production binary:
    ///    `cargo build -p pqcd --release --no-default-features`.
    pub fn viper_research_1() -> Self {
        Self::compute(
            VIPER_FORK_VERSION_V1,
            &VIPER_RESEARCH_1_GENESIS_VALIDATORS_ROOT,
        )
    }
}

/// Per-validator genesis leaf hash. Commits to immutable identity:
/// `(operator address, consensus algorithm, consensus public key)`. Bond and
/// runtime status are excluded — those mutate over the chain's life; the
/// genesis root names the launch *set*, not its dynamic state.
///
/// Format (absorbed into a [`TaggedHasher`] under
/// [`GENESIS_VALIDATOR_LEAF_DOMAIN`]):
///
/// ```text
/// address (32 bytes)
/// alg_id  (u16 big-endian, 2 bytes)
/// pk_len  (u64 big-endian, 8 bytes)
/// pk      (pk_len bytes)
/// ```
///
/// The length-prefix on `pk` prevents collision across algorithms whose
/// public-key sizes differ (ML-DSA-44/65/87, SLH-DSA variants, future PQ
/// schemes).
pub fn compute_genesis_validator_leaf(
    address: &Address,
    alg_id: AlgId,
    consensus_pk: &[u8],
) -> [u8; 32] {
    let mut h = TaggedHasher::new(GENESIS_VALIDATOR_LEAF_DOMAIN);
    h.push_chunk(address.as_bytes());
    h.push_chunk(&alg_id.as_u16().to_be_bytes());
    h.push_u64(consensus_pk.len() as u64);
    h.push_chunk(consensus_pk);
    h.finish()
}

/// Compute the canonical 32-byte commitment to a genesis validator set.
///
/// Algorithm (ADR-053 §T1.2 + genesis-viper-pq-1.json
/// `_genesis_validators_root_doc`):
///
/// 1. For each validator compute its leaf hash via
///    [`compute_genesis_validator_leaf`].
/// 2. Sort the leaf hashes by the validator's operator address ascending.
///    Sorting on the address (not the leaf) keeps the canonical order
///    interpretable to a human reading the genesis file alongside this code.
/// 3. Tagged-hash the concatenated sorted leaves under
///    [`GENESIS_VALIDATORS_ROOT_DOMAIN`].
///
/// Two validator sets that differ in identity bytes produce different roots;
/// two sets that differ only in administrative metadata (node_id strings,
/// initial bond amounts, ordering in the source file) produce the same root.
///
/// **Why a separate domain from the state-tree validator leaf**: the
/// state-tree leaf (`PQC-VALIDATOR-LEAF-V1` in `pqc-state`) commits to
/// runtime state (status, registered_height, tombstoned, bond). That moves
/// every time the validator's lifecycle changes. The genesis root must NOT
/// move — it pins the chain's identity for the life of the fork. Different
/// domains, different stability guarantees.
pub fn compute_genesis_validators_root(validators: &[(Address, AlgId, Vec<u8>)]) -> [u8; 32] {
    let mut entries: Vec<([u8; 32], [u8; 32])> = validators
        .iter()
        .map(|(addr, alg, pk)| {
            (
                *addr.as_bytes(),
                compute_genesis_validator_leaf(addr, *alg, pk),
            )
        })
        .collect();
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    let mut h = TaggedHasher::new(GENESIS_VALIDATORS_ROOT_DOMAIN);
    for (_, leaf) in &entries {
        h.push_chunk(leaf);
    }
    h.finish()
}

/// Canonical genesis validators root for `viper-pq-1`.
///
/// Computed deterministically from the 3 ML-DSA-65 validators in
/// `deploy/ansible/files/genesis-viper-pq-1.json` via
/// [`compute_genesis_validators_root`]. Pin-tested below.
///
/// **Update procedure** (only at chain reset / new launch):
/// 1. Edit the validator set in `genesis-viper-pq-1.json`.
/// 2. Run `cargo test -p pqc-types fork::tests::viper_pq_1_root_pin -- --nocapture`.
///    The test prints the new root on failure.
/// 3. Replace the bytes below.
/// 4. Re-run the test — it must pass.
/// 5. Update `genesis_validators_root` in `genesis-viper-pq-1.json` to match.
/// 6. Regenerate `crates/pqc-consensus/tests/cold_sync_replay.rs`
///    EXPECTED_STATE_ROOTS (every state_root depends on signed block bytes
///    which depend on this root via the fork digest).
pub const VIPER_PQ_1_GENESIS_VALIDATORS_ROOT: [u8; 32] = [
    // Pinned 2026-05-11 — computed via fork::tests::viper_pq_1_root_pin from
    // the 3 ML-DSA-65 validators in deploy/ansible/files/genesis-viper-pq-1.json.
    // Hex: 387fa6789229e9d930ee8d1cadee6c923def501a8dd4a21059a455a574be3cb2
    0x38, 0x7f, 0xa6, 0x78, 0x92, 0x29, 0xe9, 0xd9, //
    0x30, 0xee, 0x8d, 0x1c, 0xad, 0xee, 0x6c, 0x92, //
    0x3d, 0xef, 0x50, 0x1a, 0x8d, 0xd4, 0xa2, 0x10, //
    0x59, 0xa4, 0x55, 0xa5, 0x74, 0xbe, 0x3c, 0xb2, //
];

/// Genesis-validator-set commitment for the **planned** `viper-research-1`
/// chain (the tokenless permissioned PoA substrate that succeeds
/// `viper-pq-1` at the 2026-05-11 pivot cutover).
///
/// **CURRENT VALUE IS A SENTINEL PLACEHOLDER (`0xDE 0xAD …`)** — it MUST
/// be replaced with the real root before the Fase 5 cutover binary is
/// built. Use a one-off migration script (private) to
/// compute the real root from the freshly-generated validator keystores
/// (Fase 5 keystore ceremony), then update this constant and re-run
/// `cargo test -p pqc-types fork::tests::viper_research_1_root_pin`.
///
/// The `0xDE 0xAD` prefix is a deliberately recognisable mis-value: any
/// signing site that accidentally ships a binary with this placeholder
/// active will produce signatures that are clearly distinct from any
/// legitimate viper-research-1 signature, and the cold-sync replay test
/// will refuse the chain immediately.
pub const VIPER_RESEARCH_1_GENESIS_VALIDATORS_ROOT: [u8; 32] = [
    // Pinned 2026-05-12 by a one-off migration script (private)
    // from the Fase 5 keystore ceremony output (validator-1/2/3 ML-DSA-65
    // pubkeys in deploy/ansible/files/genesis-viper-research-1.json).
    // Hex: 61d6c7fe2f96604d57ed0caf3fe48aa190bb192069df8ecd75faa076e8de6d8d
    0x61, 0xd6, 0xc7, 0xfe, 0x2f, 0x96, 0x60, 0x4d, //
    0x57, 0xed, 0x0c, 0xaf, 0x3f, 0xe4, 0x8a, 0xa1, //
    0x90, 0xbb, 0x19, 0x20, 0x69, 0xdf, 0x8e, 0xcd, //
    0x75, 0xfa, 0xa0, 0x76, 0xe8, 0xde, 0x6d, 0x8d, //
];

#[cfg(test)]
mod tests {
    use super::*;
    use pqc_crypto::AlgId;

    #[test]
    fn compute_is_deterministic() {
        let root = [7u8; 32];
        let a = ForkDigest::compute(1, &root);
        let b = ForkDigest::compute(1, &root);
        assert_eq!(a, b);
    }

    #[test]
    fn compute_differs_by_fork_version() {
        let root = [7u8; 32];
        let v1 = ForkDigest::compute(1, &root);
        let v2 = ForkDigest::compute(2, &root);
        assert_ne!(v1, v2);
    }

    #[test]
    fn compute_differs_by_genesis_root() {
        let v1 = ForkDigest::compute(1, &[7u8; 32]);
        let v2 = ForkDigest::compute(1, &[8u8; 32]);
        assert_ne!(v1, v2);
    }

    /// Genesis validator set for `viper-pq-1` as committed in
    /// `deploy/ansible/files/genesis-viper-pq-1.json` at the 2026-04-25
    /// launch ceremony. Three ML-DSA-65 (alg_id=0x0002) validators.
    fn viper_pq_1_genesis_validators() -> Vec<(Address, AlgId, Vec<u8>)> {
        fn hex_decode(s: &str) -> Vec<u8> {
            (0..s.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
                .collect()
        }
        fn addr(s: &str) -> Address {
            let bytes = hex_decode(s);
            let mut out = [0u8; 32];
            out.copy_from_slice(&bytes);
            Address(out)
        }

        // Pulled verbatim from genesis-viper-pq-1.json::genesis_validators[].
        // address, consensus_alg_id, consensus_pk hex.
        let v1_pk = hex_decode(concat!(
            "b9512e5ec6b096a71b9f2c48566a7ccbc6a8c3b1b0dc3e017f9ee8bd1853882d",
            "96502902ccf89b0667a2f3719158cd77843d716971328b860c7d42f9c8d252ef",
            "924db48ef24df0b1791a176de60a77af0ac3462ff0e453e3116bfa9655f25529",
            "ef4d0e60e7b1412723c8c9d4a40630d8bdff6b792701cebc40eff7c1180804a8",
            "cb35feecf0d9fb04ece691de302bf295340230ec0d1d779bb89fcd0fd564140f",
            "07c40c548032be85f03903a1f4e3977591eafc9354705e606bd43daa065ca446",
            "817382c335255e2e8be75d264a240daf8caa9200db639d4a752ad09bb3156d9f",
            "ac9f714358b7cd14e31a7fc82459bc441aed2fe4d14b020077d1dc0b19d45ac4",
            "d18d23945b63d460f77af9f55c21a124b30787f83be7981652b2ab7adf83251a",
            "07fca2fd2dd6446e459ccf10b11f3999b21a4ccc763e5b89241282a456d8c8a2",
            "0fce402347714e4ee8ae92436e4bd3553f98a0286a90c5168ba6b68390042407",
            "832097c694b7596fa60b7c69750b4ca022910c41d5b90a9a5189a3f93af3d5c7",
            "48187b5e66edcc70297e32ae2833b4fd570e5c73d3e3259340ccb08144efb61a",
            "7c8fecb925700e86c7962145f14e2724caf755a6968a97c9f9b2596fe90857b9",
            "3ddfc517c9541fae9d116ca70fc5429876f75f1f6242dc822b4c980cec115f7e",
            "684f972fca7d991e2bc5f339c447a3526a64c7e94dd956f8497e8b77d8fd0a4a",
            "aa26aaf29891834707d0cf851fd1e1e6b6c81e026b860fa6525d606906f7966a",
            "a98b3ea2bbabf5a2e0d8368cc39ab9aa78bd293a5ddd973ef212aac4836d77c0",
            "792fb981b1a9cbf359d6ce98b635ba4251b6b1186256b5629c74a78650e12c54",
            "be2438fae877472af6bc7dca25f117f6b21b57b3624a64d720632beded121ad4",
            "df6c5af5374a6daae520250507ed7d3ab909257bb63c0a07fbd33151a4b7e100",
            "7429b3a1f58aefdb40c667ba7bfac15c1bab028aae127863325373372053d2bb",
            "b76b032a0fcc6e91b95d113264b7d02233859fc0f1e28db0ad0c9350f935e6d3",
            "d50633400177aab6d0d09de94e53cd192ae64ffb8de00092cc7131f805e3b221",
            "523c000bb3b170d3145a0279dc052b606dbc7487596b125bb119476569267c85",
            "cebffb2363d6aadd5ff004324cd788d4d74b73b5ed776b0c8c99a3f550a33d21",
            "0f3f284168ebcd6bbcb66b0b12a79825628d8587c4f329bc29f4fca586075cc8",
            "e65dda2906421fcf24a4511ca7baab48cd1d0b2d058a47d20947f1129944a212",
            "c2cdf61b4ee40833cefcbad67c858f8b9d706e9b356932c7912f8721bcdd2f1d",
            "f101b7a96aa68af6c1382d2fe1af257d5f1226820d3891c3e63805aa67f56ec8",
            "1116ee8fda12bb8b6ce8617906b58409d23c6ad8c81ef8205939651352f7e167",
            "7a54c7718423d5626a606f6a7e3f72f3ca387518a7a7244c47e16c7355b4a5d5",
            "c814ab5dd94ec1d824a926528387125a4db0b23739bd623a9dfd02434f9ae3e2",
            "accc6197395b705f37fa4892e13e5c5f82822ecb6c58d2d334e62e41fce95a20",
            "b16eb500cf29e953df02224a6acd9dd4ea953b4cffe65626b2fedb9a87939be0",
            "6e5785df169592f13214591d9d5559e5e5cc328c2f3a65c59cc0a676cd9014bb",
            "9aa9518ce744c5c8833ae1241e8b300bd028faefe08658960956b67b7c0486bb",
            "cb39e4eb310d1ff5510074cac93564b7a1f679e350e65f44fdf1f78a37f1bfeb",
            "5f792ba70c353886c3afa2503137781498c0a4ca011aa54932a24904210d6d11",
            "f319cf67034cbad33618a6d34a28e858c3584edeae6db2422fa5542cdd62f605",
            "c3af2bd080267f7eb9a5e1b6db6f7f156a14b9a75763ce7b4e85b00d99a32c1b",
            "81497ec00f4561bb1ee38ce8ca7b2ad920cdc86c7d15c415b35f8c024f0e5045",
            "cdaf03f9f4cac95d868a488b1675dbec2f37c56cdd86fe67b4d09caf35b5f09c",
            "25f45cbd2d3d76d84a03606b4222fa1c0a0169dbe5aefffc5635f383f6c19900",
            "656f187ccfb9d52e1d5aab8e09879e743fe9a91dfbc869062ee6f2f6184552c2",
            "b1167179ebdfbc01ab59f27a31e7dabc4d97e2c3595fce568b1525e2156bf74d",
            "05a34bed2bc9e4aa2f4922779f90f6eb9cc7722b012cd8ddc2aebed7704456cb",
            "424163b23f51c7d535347196f35ae2c3daf7c3044a8741e38fbdd8494fbed081",
            "1e8a9bba83ae04cf1f2055b01ef61e2d78e1b610ef970fc95dd9bf3e321def6b",
            "50c362f2650031bb368cb64c3b06dcae96b2227cd87448c7d6472ba2ae13f521",
            "919fb8a1566a9d454b478af43299125e6f37c596b240cd2ca4ab7941af471f0c",
            "c9849b6a5dbe0c04a4de8bff0373f01b08a27c08cc77193f99788537ea2cd23c",
            "21bd7e3b462cf53d6a5b7a524e29c538e3f9c4019002a5f232b4fcd380afd2ff",
            "a8f92b767cabaf64a5da8cf93c3b147c6185817e65af95c0be9f0511f165880c",
            "081eee972cb0d718e1d37facbb5dbbc97949b9018e2a142cd6b17967b3da64dc",
            "96e81545f6eff2d0badac6c60daa6f8c74758775305c096fc08aaf16d46fea88",
            "0b9ac06659d26590600c701614e4faf256a5efa79fa2cef6af3653f6c6f44e0f",
            "72bb9733ba88d07f355081f2a363947487ed7beebad12b66e385dc0343fab5a6",
            "ee9991b77eff59b1c1d00c81811e21a5f7194bcc24ffffc6569fc715618d8cdc",
            "a66dda9658d741a2b5bad49e80ae08e1b058f47a7dc52a4c344bb35256b5ef7e",
            "33f5c13c1e8e3450ec5e9dd0a0844192b8be523ceb8e5160ce7b0dd987875dcd",
        ));
        let v2_pk = hex_decode(concat!(
            "18f43cb28987882f1e3ddfe4834c91d7ea55d28ec84f2b8c155929831933b0dc",
            "a32432f65fef7137445f8996c60b6815c4076ddd4c950ed1f3cfda618f43847d",
            "4557510796fedd644f081e73e0751631588293154e4628078b365a2b05b9ad27",
            "7542a7c4404de3b5e8c99d066e05545e3bb0b04f310fce3c4e1ca7f7a1b65bc5",
            "aa4f93c542afba06908bfa00f1b54085cb64884a654060b6c7586935e969d735",
            "931bcd88914c8260bbeca6284c8ac3f92de15420cffc9b3c2402ceb7d1a9e7be",
            "57b511eedf4fefb7c819175f366b77c8773b3112cbf5330a8e8c2ba49273f460",
            "cb0ba29f2cbc0567ef87f4623f191a5062389d79ed03a5e11e01a3b97b5b28d7",
            "1f00528d938f35185a4dbdad8d9eb3728a265a3a36a5f3ac3d1ebfea15a6801e",
            "732d831d5a4aa4c86e9bce68c39c68dcdc38fac0ce5e86f84cc28354d7b23065",
            "6cd2e3ccf1e758562c2b7a1e84e5b6d56c7d19b205b9544f3307e05108d4e370",
            "289c271c127d2943eb982943e5ef5c738c0f2f3e9a63814720ee4afffc3b705f",
            "e18d29fa65204e0f47d1d639d9554e39743ab07f833d3fd61766dd173263b2ac",
            "95261f865a6c335a405fcf1a8dd2601b1c9660bb8c74d357cd6d0ed68e719bd3",
            "bbc8ee2ca5a2179f679c1a36bd1aecb6eff0c6f1a99b86aa11361ae9dbd2a6de",
            "4b717f73f90583f24b2e888da2076021aeeae84b9f520c6790d0b5634a6c5ced",
            "e8fa31a890bdf4311b65b5ccfccca43fe9382b061493dd44a941917366a64cca",
            "ce7c055ee051a084c9944eb040df4eaeece605ce3b150db9a370355352bba63e",
            "bacbfb2aa2cc94cfbd47633b4df51c9fca6683990b43deeaf59de62543c99f49",
            "b32b9e4cf62dd97de5cf9da492f95746e41d8b552df0543db1e5a0be91e11701",
            "6cac5b899b283bc42ad32db72f3ede93ec30614bd10a85e87e4b7f91d487f6e0",
            "c03ca0c53e243afb0060e9e58dc4d9aa4979d713f237fe2e882fb5d868385ed1",
            "7f714901b5cd3a50625e5d907d9522cf702739a8959e7fcb80f20218adf7a95a",
            "2b4c2bbdbe91a03aa23b3e22b8ed9d9c989e11b1f85ba73e5f5909a40e7bd4b3",
            "bce9a398aef08f85cea8c277ce6c01df331d44e94819c45997ab4a532b6ec83f",
            "3e97bd94c38322893927b2d413e8f37e0cdc4e0a6538da8dcb90c17c90934f34",
            "1b6210fdf08856b0b4a6f03067b319a5c453786caa39f736d19b695c38677e49",
            "ba0b92759f41a3725c2a5bb38aeed79b69fba9774bf639a969edff23dcc8b8b4",
            "ac7f2c0db5559c6d54134a37bd270ee0b9639fd1c3ff873aed23d4f65c02a10f",
            "95729390e3b16d8d32a9d60b6c7de6261840f65b99faf3426f9984cf58042866",
            "7a05b370730d32c000e3e6649cbcd246e037bcb92cd8dcf1acacbd7afd6ad7ab",
            "6b3c9b5cf20523b5d07f0662e4c189a65a12d78ce95cf00135393ddd6fa5a789",
            "84a36a5ae3aadcf39cf7bc0f1aab8559de8eb390710b05916b4e0b343efe5f17",
            "33278b07abbde1b81497cd2a9d7e3f8807219ae7dae67a030cedff99ed5d5683",
            "497461872be52a403c2263f96c78d50f79f5352078e2050ae16d8925921271903",
            "bb7a4982ebe7d4b0a5a863497eb73513b6463ff8c2729c9cc9ae2d395559dfb2",
            "1640ed960db9ccc3664a700e9f3d914aaaf03f40ff60e254d3216a22dc9dd640",
            "5d0ba228a699e6a1fc9ac66809513f679ae8b95afc5cb3cbd2d1500350e5947b",
            "970055f481d49398dc1cce868aafb7e6afb2299a594145231434df467a86e495",
            "12ad405d833f8a61a02fa6bf6d3b861e5b2e6bcf034927facf8f0cbe3011968f",
            "821af36b06b1fcfd7a65043bb743fee314432b5337e1f5af3db29cd40df547ba",
            "05ba322c79bfd6e4be2a7c49d05fd955bbba33640c819c2f056809fe8bbf980e",
            "f1541d597727aa68f92c75097d90c4a8aa4b1599799617481fc8eea2dddda749",
            "abe03811887f0965a0ad8d4dbec0a805e7ad7a60acddf34ddd14200cc0487e32",
            "77790ec8353ff80c2d712be4a5f827539c609407c89cbd2c39068ea79f7c615c",
            "621511611374a2e84018214f45254f94ae492df9ee0cb8cc9278862cb372a26e",
            "15afbb481fd5b2b228689ad9dc86d1a65433a448c87d816d0f96d75dffbc0137",
            "1e74aa3e896c028d56ebe1be59e087798833ee497c18684bd387ac88dce6286a",
            "a2b23bb623cf3e139bf5150ba87df0d6dca2d338dce5c45536c68875b3daae1c",
            "97ada89569d5e8f9424558761133bfdf700778ed4de2edd8ae1fce1837f4da58",
            "f583fd5eef03bd06be0e76c477f9928d815e0d2e78aec77712dfeb1ac2bf9a85",
            "9aa323ecc810adbefafdfb88a106ac027b18d7c68d6f785a3a677ffd8e969156",
            "4a482e58b56764a829590e7619b941e6220442fec8156bbeccab9df9813d5d17",
            "5ed3b7518083620675e9b06bf1bbbcb1c14cb8f8a1e8cd01f4bc93acd5059272",
            "f81213b920292cebe423b69574574fa283476198f6cc1f8d7e91ee545275d10c",
            "639c03f7bd779685e085a3941a20c6060b77e059f8caac63ce9a75f7a03f3145",
            "5bf3e98d48a794d3d79a8baddd6d06fe61bd059130d14b25da91b12c7d53dbc5",
            "3e0c16ac48906af29fcb5cb385f0aada96cf00cad682ee188e9477bac28e13ac",
            "bd00d9e5455ccb3e939135f3be6a88f3161a2917389d217a769a8f5b4f4c34e6",
            "e0bee5a7d523ae9d91e4f1bd85f37e1f46bcdd64b4430fdf9f6a1f37b08a3d34",
            "d182ef5b6d2812d0054564f0f127abb7607509d5e003090fa3d549bb5e41024",
        ));
        let v3_pk = hex_decode(concat!(
            "5ab45322e816d4cfe645cf9085216f0dacf5175a2c4d6cf9c6fa942b86044286",
            "cb2788474c9b0e9e2f02852623b17fdda6d83bb5cca7ac673bf4ef7805b4d6ea",
            "414f0a210f84a0d40f3514ba893d775ef4cb092c199cff8496842e2a9ec789e4",
            "93e446623de241b6bdf9231bf67f6eae58ccef04259a93f5e0e50289474bfc1e",
            "b5ca87a31e0f44731b7f2c4def4eb208fbb4726785e40867b171b0d77f40255d",
            "cc246e8ce42ce383a4e1aff54bc876ebe766e33424e5599023c5a0bceaea5c56",
            "6e0e906d4941a331141bb99aa4269f29f82b362f9900f57035862b4a2bfc8b11",
            "f447b59d260f429aed5d187c3f7ba71309742de3e24e0ca19ac5bb58238809d2",
            "9bd1ef265a9a3949f5748631005b61406d5f82557a515263e246c201c64ebfea",
            "a9be976c26a368c2181946106c0e4b2e1459e5bdd08f7f904582edd3c30b9be7",
            "fd0a154905276297b5a49a2572783e9e75cdc7722a2931f27261e1457f2c8d1d",
            "a88cc53be70486e5fecfd3b5fb5340c2668d3358d42fc4cf4c6b51dbaad27436",
            "245929443aee81bb9fdfc5470f7a917f1471f54d67c540e065c2bf1b42607ee0",
            "f9e4d3ae4af2b0958c3420ae162f0749746daf38fc4af9b30972dcb18a41794b",
            "e375542a6c7554fdd79a7876e9336aa426e8d9209c24e4c535b410f8f0d9216f",
            "84bbe55561e296bbee7b295271befac93ba5d3a86953f3c60f09a15b779dbc6b",
            "4735ac1a97ab180e06206ae50971aaca5f72cf014848045df48b55c1a794acc0",
            "a702e14c59ec570ec0ef70f27ce07ca3d588aa84c971d703d2560d202aea1588",
            "61b9e2da7f9a63f9b118ac9ab97e391e950181aff91e740dab13f870d0b2c23a",
            "7590e49bdaba82eb0627e0701c5eb36c452a8bb3c86986ec1370a50ede82924c",
            "137525a7cd656f0f38dee24c4a4557d2bafa02531b69b09be3f9e77cef81a0ea",
            "adc1f9d8ad95fc8b77df3811703a9fec041d31972a0a10595f557db90d0d85f4",
            "1dbd26d65e46d924d89eeee653874a7e247e4a00d9869910b6280af97d206f95",
            "dbd7c0aabe8e2183ba908f5c9e7e58b0e523e133686d7f230e2d31f65a9189a2",
            "74cb1d50559d0ea9b2f1a3b72ad4f03067e59392a3be0b35c796f95690d85a8e",
            "75b442fd75f0609e6db226382b7c28e6d14167962ab444fa76dce8d5994ba2ac",
            "6dff4d89d94d4f3af1f9c9a755dd05c80775c7b9d9128d7770dcad4cb65e4819",
            "5b971b14e640b663cee2d30fac03d0d9e65cea0daf062789f6629e78be68d6a8",
            "88f176d761407b69db001a7b3588bc638b8f246b12603b2b56b3b5115d52b3fa",
            "b1876610f8976732c8308a603b7d33a9d674ac0afa7f7a64ab4235191a3c92b3",
            "8917133fa6978cee7d849a8f5fbf8c84e8d82a78cdd30ad13af0cc9396b0c7f2",
            "44013377b961ac4382ee0928a5373a4bc0fb1f806ec06108ae6daef81177e5cb",
            "e42df0ec65b7db7949f27bac9e76aa2f014581d89bad04c3dbb885ed0cb2be3f",
            "86c23f969d93ec34aa3f38173ff498c688121009a6dde9c8b86078b2036882459",
            "ca7eb7135a41502e6b04f56e70b90cab81013056b45e8e0a12dd5abac0ff143c",
            "853c4d5507d93c855ed43be2a49745431879f7c311fe8f5ecbb7fa2a013712c4",
            "7b53ba8e44cd3b7bd9c28910a541b43ed600e7807d6bd90b0d0b4acbb38155c8",
            "a2cdabb35caece804c017bbc2b7381d519232f4e92ea8754ec364d3a53dc189d",
            "b6171803ce42b7e5ea226a4ffe5f5a0ffadbedbedfdf58b0e98eb7f8af30f83c",
            "adcbaf1611bfcae085cdbff23c31dcf8fb5c539d29e2ac7033f551b10f3b7c7a",
            "652651f1c16ee080eec1fdc0d6e766b15410391bc6a4e789d00de76d83c23912",
            "36359d4dced325093d23a91694c2007d19534965a76b4999b9d0c61aea56b717",
            "e75a8b3e6e7aa93bf781720988eb37973f6027fb6b314bade517e56633ea7346",
            "98a9f4cbce545fd9643a28f4e637f78a63f051d128819f6e310324ae459537441",
            "d5186e4782de44ef71a095a5f579fca3875efa42073ca621531e0cd57bb9843f",
            "c4f8aef6cb9785feaeb86adf6fcdb09237a770a7b1318070f920e34a7292926d",
            "ba700074c429c289235a6a7c5537a65aab987611007d02b794f1f02ecbfd4b64",
            "6812ddaf6f880a0a70f0cc43d354a00db8c28c744b43a2612f9e62e1f26fa5d5",
            "ca25827bfbce414700e066121cdeab98f0da8c2bb37686c7729ebca733738c9f",
            "e4946cb4f98b68f86aeba1d6e4adb1846113c9e090df9c13ea9c1a3bd102ea42",
            "69e9c33214eba80d6d9fce1adfdb0d1d7adee4665571a69e91d53c7a57fce7cb",
            "fcc18538d5235a458f040b291b4844f6c0f606be6cbe55586bcc3c7416ed442a",
            "3a7fc4b60b5c902741b8912be36da11d3af3d4e437921a36df23ab16a6c7538d",
            "b921cb8034d2f90feabd923a49f3c2c88e5e010d28d3b9fa427b85d581abffad",
            "b73964cbf68a9b366badc6089fc255d71e1704a75132eb1f13ca4728cfdc7632",
            "345b5534adf76517490834e91be52854651ddf04be3a6e9f66aa51d70554fb4e",
            "0054c9bb8d736f6cb829676feb2397bcbb76bffa764eb9c6fb1e9cd5e517119b",
            "8402e2f96279a2f1de2718a80159ecceb280aebbf1ab6b2ea31570b7ff8c274a",
            "047dc7f1ee2befc583809f867880adc917c89c2f1c6914713459844cf6d245d0",
            "a42ec6ce8fdb939070690d1ef3eeffb69eb5372e9630fa9f2c13079213dc7802",
            "4891d25d24867d625c6402b7189a67a7c7fedd6b73053b039f75e6402e469c",
        ));

        vec![
            (
                addr("087024f943f46283fbfffd2536313d74a87c39aee943f5b4dce88a6f1ba53cfc"),
                AlgId::MlDsa65,
                v1_pk,
            ),
            (
                addr("d80d06acccca94680382ba79cb07d473a482567071497b3f74d934f03e4c3516"),
                AlgId::MlDsa65,
                v2_pk,
            ),
            (
                addr("1e8d7e0409cdf863dda465627cfb84a58e04bf9e2bbc6852228bf343c048e0a9"),
                AlgId::MlDsa65,
                v3_pk,
            ),
        ]
    }

    #[test]
    fn viper_pq_1_root_pin() {
        let validators = viper_pq_1_genesis_validators();
        assert_eq!(validators.len(), 3, "viper-pq-1 genesis has 3 validators");
        let computed = compute_genesis_validators_root(&validators);

        // If this assertion fails, run with `-- --nocapture` and copy the
        // printed bytes into VIPER_PQ_1_GENESIS_VALIDATORS_ROOT above.
        // This is intentional pin-test behaviour — a change in the genesis
        // validator set must surface as a deliberate const update.
        println!("computed viper-pq-1 root: {computed:?}");
        println!("computed hex: {}", hex_encode(&computed));
        assert_eq!(
            computed, VIPER_PQ_1_GENESIS_VALIDATORS_ROOT,
            "VIPER_PQ_1_GENESIS_VALIDATORS_ROOT is stale — paste `computed hex` into fork.rs"
        );
    }

    #[test]
    fn root_is_order_independent() {
        let validators = viper_pq_1_genesis_validators();
        let mut shuffled = validators.clone();
        shuffled.reverse();
        let a = compute_genesis_validators_root(&validators);
        let b = compute_genesis_validators_root(&shuffled);
        assert_eq!(a, b, "sort-by-address makes the root order-independent");
    }

    #[test]
    fn root_changes_on_identity_change() {
        let validators = viper_pq_1_genesis_validators();
        let mut tweaked = validators.clone();
        tweaked[0].2[0] ^= 0x01; // flip one bit of the first pk
        let a = compute_genesis_validators_root(&validators);
        let b = compute_genesis_validators_root(&tweaked);
        assert_ne!(a, b, "any pk change must move the root");
    }

    #[test]
    fn fork_digest_viper_pq_1_uses_real_root() {
        let real = ForkDigest::viper_pq_1();
        let zero = ForkDigest::compute(VIPER_FORK_VERSION_V1, &[0u8; 32]);
        assert_ne!(
            real, zero,
            "viper_pq_1() must NOT equal the old [0u8;32]-rooted digest"
        );
    }

    /// Real pin assertion for the viper-research-1 genesis root (Fase 5
    /// landed 2026-05-12). Reads validator entries from the canonical
    /// genesis JSON, recomputes the root via the same algorithm production
    /// uses, and asserts it matches the pinned constant. A drift in EITHER
    /// direction (someone edits the JSON without re-running
    /// `finalize-viper-research-1-genesis.py`, OR someone edits the const
    /// without updating the JSON) surfaces here.
    #[test]
    fn viper_research_1_root_pin() {
        let Some(validators) = viper_research_1_genesis_validators() else {
            return;
        };
        assert_eq!(
            validators.len(),
            3,
            "viper-research-1 genesis has 3 validators"
        );
        let computed = compute_genesis_validators_root(&validators);
        println!("computed viper-research-1 root: {computed:?}");
        println!("computed hex: {}", hex_encode(&computed));
        assert_eq!(
            computed, VIPER_RESEARCH_1_GENESIS_VALIDATORS_ROOT,
            "VIPER_RESEARCH_1_GENESIS_VALIDATORS_ROOT is stale. Either the genesis JSON \
             changed (rerun finalize-viper-research-1-genesis.py and paste the new bytes) \
             or the constant in fork.rs is wrong (paste `computed hex` above)."
        );
    }

    /// Genesis validator set for `viper-research-1` as committed in
    /// `deploy/ansible/files/genesis-viper-research-1.json` at the Fase 5
    /// cutover ceremony (2026-05-12). Reads the JSON at test runtime so
    /// the test fails on any drift between the JSON and the pinned root.
    ///
    /// The artefact belongs to a retired private chain and is not part of
    /// the public tree: when it is absent the callers skip (`None`) instead
    /// of failing, so the pin still guards the private repository.
    fn viper_research_1_genesis_validators() -> Option<Vec<(Address, AlgId, Vec<u8>)>> {
        // env!("CARGO_MANIFEST_DIR") = crates/pqc-types — go up two levels
        // to repo root, then down into deploy/ansible/files/.
        let json_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../deploy/ansible/files/genesis-viper-research-1.json");
        if !json_path.exists() {
            eprintln!(
                "skipped: {} is not in this tree (private artefact of a retired chain)",
                json_path.display()
            );
            return None;
        }
        let raw = std::fs::read_to_string(&json_path)
            .unwrap_or_else(|e| panic!("read {}: {e}", json_path.display()));
        let parsed: serde_json::Value = serde_json::from_str(&raw)
            .unwrap_or_else(|e| panic!("parse {}: {e}", json_path.display()));
        let entries = parsed["genesis_validators"]
            .as_array()
            .expect("genesis_validators must be a JSON array");

        fn hex_decode(s: &str) -> Vec<u8> {
            let s = s.trim_start_matches("0x");
            (0..s.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
                .collect()
        }
        fn addr(s: &str) -> Address {
            let bytes = hex_decode(s);
            let mut out = [0u8; 32];
            assert_eq!(bytes.len(), 32, "address must be 32 bytes");
            out.copy_from_slice(&bytes);
            Address(out)
        }

        entries
            .iter()
            .map(|v| {
                let alg = match v["consensus_alg_id"].as_u64().unwrap() {
                    2 => AlgId::MlDsa65,
                    other => panic!("unsupported alg_id in viper-research-1 genesis: {other}"),
                };
                (
                    addr(v["address"].as_str().expect("address must be a string")),
                    alg,
                    hex_decode(
                        v["consensus_pk"]
                            .as_str()
                            .expect("consensus_pk must be a string"),
                    ),
                )
            })
            .collect::<Vec<_>>()
            .into()
    }

    #[test]
    fn fork_digest_compute_helper_matches_viper_pq_1() {
        let direct =
            ForkDigest::compute(VIPER_FORK_VERSION_V1, &VIPER_PQ_1_GENESIS_VALIDATORS_ROOT);
        assert_eq!(direct, ForkDigest::viper_pq_1());
    }

    fn hex_encode(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }
}

// SPDX-License-Identifier: BUSL-1.1
//! Benchmarks for block production throughput and state-transition costs.
//!
//! Run with:
//!   cargo bench -p pqc-consensus --bench block_throughput
//!
//! Measures the state-machine cost of the producer loop independent of real
//! ML-DSA signing (uses StubVerifier). This gives the overhead floor for:
//!  - block assembly (tx validation, state apply, hash computation)
//!  - per-block state_root hashing (via full block commit path)
//!  - commit overhead (pool eviction, store advance)
//!
//! Combine with sig_verify bench numbers (pqc-crypto) for total per-block cost.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use pqc_consensus::proposer::{LocalProposer, LocalProposerConfig};
use pqc_crypto::{sign::StubVerifier, AlgId};
use pqc_mempool::{admission::try_admit, Mempool};
use pqc_state::StateStore;
use pqc_tx::{codec::encode_tx, validate::FeeParams};
use pqc_types::{
    account::{Account, Address},
    keyset::{allowed_tx, KeyEntry, KeySet, KeyStatus},
    transaction::{MsgType, Transaction},
};

// ── Shared fixtures ────────────────────────────────────────────────────────────

const SENDER: Address = Address([0x01; 32]);
const RECIPIENT: Address = Address([0x02; 32]);

fn sender_account() -> Account {
    Account {
        address: SENDER,
        balance: 1_000_000_000,
        nonce: 0,
        keys: KeySet(vec![KeyEntry {
            alg_id: AlgId::MlDsa65,
            pk_bytes: vec![0u8; 32].into(),
            key_version: 1,
            valid_from_height: 0,
            status: KeyStatus::Active,
            allowed_tx_types: allowed_tx::ALL,
        }]),
        policy_version: 0,
        policy_hash: None,
        verifier_template_id: pqc_types::account::VERIFIER_TEMPLATE_ID_EOA,
        auth_data: Vec::new(),
    }
}

fn base_state() -> StateStore {
    let mut store = StateStore::new();
    store.insert_account(sender_account());
    store
}

fn recipient_state_with_n_accounts(n: usize) -> StateStore {
    let mut store = StateStore::new();
    store.insert_account(sender_account());
    for i in 0..n {
        let mut addr = [0u8; 32];
        addr[0] = (i & 0xff) as u8;
        addr[1] = ((i >> 8) & 0xff) as u8;
        store.insert_account(Account {
            address: Address(addr),
            balance: 1_000,
            nonce: i as u64,
            keys: KeySet(vec![KeyEntry {
                alg_id: AlgId::MlDsa65,
                pk_bytes: vec![0u8; 32].into(),
                key_version: 1,
                valid_from_height: 0,
                status: KeyStatus::Active,
                allowed_tx_types: allowed_tx::ALL,
            }]),
            policy_version: 0,
            policy_hash: None,
            verifier_template_id: pqc_types::account::VERIFIER_TEMPLATE_ID_EOA,
            auth_data: Vec::new(),
        });
    }
    store
}

fn transfer_tx_raw(nonce: u64, sig_fill: u8) -> Vec<u8> {
    use ciborium::value::Value;

    let mut payload = Vec::new();
    let entries: Vec<(Value, Value)> = vec![
        (
            Value::Integer(1u64.into()),
            Value::Bytes(RECIPIENT.0.to_vec()),
        ),
        (Value::Integer(2u64.into()), Value::Integer(100u64.into())),
    ];
    ciborium::into_writer(&Value::Map(entries), &mut payload).unwrap();

    let tx = Transaction {
        tx_version: 1,
        chain_id: vec![],
        msg_type: MsgType::TokenTransfer,
        sender: SENDER,
        nonce,
        fee: 0,
        fee_tip: 0,
        gas_limit: 100_000,
        payload,
        sig_alg_id: AlgId::MlDsa65,
        sig_key_version: 1,
        signature: vec![sig_fill; 3_309],
    };
    encode_tx(&tx).unwrap()
}

fn proposer() -> LocalProposer {
    LocalProposer::new([0u8; 32], LocalProposerConfig::default())
}

fn admit(pool: &mut Mempool, store: &StateStore, raw: Vec<u8>) {
    let verifier = StubVerifier;
    try_admit(pool, raw, store, &verifier, &FeeParams::default())
        .unwrap_or_else(|e| panic!("admit failed: {e}"));
    let _ = (pool, store); // suppress unused mut warning
}

// ── Bench: empty block (just assembly + state_root + commit) ──────────────────

fn bench_empty_block(c: &mut Criterion) {
    c.bench_function("block_throughput/empty_block", |b| {
        b.iter_batched(
            || (proposer(), base_state(), Mempool::new()),
            |(mut p, mut store, mut pool)| black_box(p.run_once(&mut store, &mut pool, 0)).unwrap(),
            criterion::BatchSize::SmallInput,
        )
    });
}

// ── Bench: block with 1 transfer tx ───────────────────────────────────────────

fn bench_block_one_transfer(c: &mut Criterion) {
    c.bench_function("block_throughput/one_transfer_tx", |b| {
        b.iter_batched(
            || {
                let store = base_state();
                let mut pool = Mempool::new();
                admit(&mut pool, &store, transfer_tx_raw(0, 0xAA));
                (proposer(), store, pool)
            },
            |(mut p, mut store, mut pool)| black_box(p.run_once(&mut store, &mut pool, 0)).unwrap(),
            criterion::BatchSize::SmallInput,
        )
    });
}

// ── Bench: N sequential blocks with 1 transfer each ───────────────────────────
//
// Measures steady-state block production throughput when the proposer
// must hash an expanding state root each block.

fn bench_sequential_blocks(c: &mut Criterion) {
    let mut group = c.benchmark_group("block_throughput/sequential_blocks");

    for n in [10usize, 50, 100] {
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &count| {
            b.iter_batched(
                || (proposer(), base_state()),
                |(mut p, mut store)| {
                    let mut pool = Mempool::new();
                    for i in 0..count {
                        admit(
                            &mut pool,
                            &store,
                            transfer_tx_raw(i as u64, (i & 0xff) as u8),
                        );
                        black_box(p.run_once(&mut store, &mut pool, i as u64)).unwrap();
                    }
                },
                criterion::BatchSize::SmallInput,
            )
        });
    }

    group.finish();
}

// ── Bench: state_root cost as account count grows ────────────────────────────
//
// state_root is computed on every committed block over all accounts + attestations.
// Measures how cost scales with state size — critical for planning state growth limits.
// We produce one empty block per account count and measure total commit time.

fn bench_state_root_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("block_throughput/state_root_account_count");

    for n in [1usize, 10, 100, 500, 10_000] {
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &count| {
            b.iter_batched(
                || {
                    let store = recipient_state_with_n_accounts(count);
                    (proposer(), store, Mempool::new())
                },
                |(mut p, mut store, mut pool)| {
                    // One empty block commit — state_root is computed over all N accounts.
                    black_box(p.run_once(&mut store, &mut pool, 0)).unwrap()
                },
                criterion::BatchSize::SmallInput,
            )
        });
    }

    group.finish();
}

// ── Bench: StateStore clone cost with realistic ML-DSA-65 pk sizes ────────────
//
// `build_next_block` calls `store.clone()` while holding the global mutex.
// With pk_bytes: Vec<u8> this deep-copies every public key (ML-DSA-65 = 1952
// bytes). With pk_bytes: Arc<[u8]> (TASK-066 optimization) the clone only
// increments reference counts.
//
// This benchmark measures the raw clone cost as account count grows. The
// improvement is proportional to N × pk_size: for 10 K accounts with 1952-byte
// keys the before cost was ~N × alloc(1952 B) ≈ 20 MB of heap allocation.

fn realistic_key_bytes() -> Vec<u8> {
    // ML-DSA-65 public key size: 1952 bytes (FIPS 204 Table 2 for parameter set 65).
    vec![0xCC_u8; 1952]
}

fn state_with_n_accounts_realistic(n: usize) -> pqc_state::StateStore {
    use std::sync::Arc;
    let mut store = pqc_state::StateStore::new();
    store.insert_account(sender_account());
    for i in 0..n {
        let mut addr = [0u8; 32];
        addr[0] = (i & 0xff) as u8;
        addr[1] = ((i >> 8) & 0xff) as u8;
        addr[2] = ((i >> 16) & 0xff) as u8;
        store.insert_account(Account {
            address: Address(addr),
            balance: 1_000,
            nonce: i as u64,
            keys: KeySet(vec![KeyEntry {
                alg_id: AlgId::MlDsa65,
                pk_bytes: Arc::from(realistic_key_bytes().as_slice()),
                key_version: 1,
                valid_from_height: 0,
                status: KeyStatus::Active,
                allowed_tx_types: allowed_tx::ALL,
            }]),
            policy_version: 0,
            policy_hash: None,
            verifier_template_id: pqc_types::account::VERIFIER_TEMPLATE_ID_EOA,
            auth_data: Vec::new(),
        });
    }
    store
}

fn bench_state_clone_large(c: &mut Criterion) {
    let mut group = c.benchmark_group("block_throughput/state_clone_realistic_pk");

    // Realistic load-test scenario: 10 K independent senders (TASK-062 reference run).
    for n in [100usize, 1_000, 10_000] {
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &count| {
            let store = state_with_n_accounts_realistic(count);
            b.iter(|| {
                // Mirrors the first statement in build_next_block: store.clone().
                // Before TASK-066 (Vec<u8>): O(N × pk_size) heap allocation.
                // After TASK-066 (Arc<[u8]>): O(N) atomic refcount increments.
                black_box(store.clone())
            })
        });
    }

    group.finish();
}

// ── Bench: build_next_block only (no commit) ───────────────────────────────────

fn bench_build_next_block(c: &mut Criterion) {
    let raw = transfer_tx_raw(0, 0xAA);

    c.bench_function("block_throughput/build_next_block_1tx", |b| {
        b.iter_batched(
            || {
                let store = base_state();
                let mut pool = Mempool::new();
                admit(&mut pool, &store, raw.clone());
                (proposer(), store, pool)
            },
            |(p, store, pool)| black_box(p.build_next_block(&store, &pool, 0)).unwrap(),
            criterion::BatchSize::SmallInput,
        )
    });
}

criterion_group!(
    benches,
    bench_empty_block,
    bench_block_one_transfer,
    bench_sequential_blocks,
    bench_state_clone_large,
    bench_state_root_scaling,
    bench_build_next_block,
);
criterion_main!(benches);

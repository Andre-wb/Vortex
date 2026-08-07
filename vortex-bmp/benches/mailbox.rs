use std::sync::Arc;

use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use vortex_bmp::config::storage::StorageConfig;
use vortex_bmp::mailbox::id::MailboxId;
use vortex_bmp::ports::mailbox_store::MailboxStore;
use vortex_bmp::store::memory_store::MemoryMailboxStore;
use vortex_bmp::time::manual_clock::ManualClock;

const NOW: f64 = 1_700_000_000.0;
const MAILBOXES: usize = 1000;
const BATCH: usize = 100;

fn mailbox(index: usize) -> MailboxId {
    MailboxId::parse(&format!("{index:0>32}")).unwrap()
}

fn ciphertext() -> String {
    "ab".repeat(512)
}

fn filled_store(messages_per_mailbox: usize) -> (MemoryMailboxStore, Arc<ManualClock>) {
    let clock = Arc::new(ManualClock::at(NOW));
    let store = MemoryMailboxStore::new(clock.clone(), StorageConfig::default());
    let payload = ciphertext();
    for index in 0..MAILBOXES {
        for _ in 0..messages_per_mailbox {
            store.deposit(&mailbox(index), &payload).unwrap();
        }
    }
    (store, clock)
}

fn deposit(criterion: &mut Criterion) {
    let clock = Arc::new(ManualClock::at(NOW));
    let store = MemoryMailboxStore::new(clock, StorageConfig::default());
    let payload = ciphertext();
    let mut index = 0usize;

    criterion.bench_function("deposit", |bencher| {
        bencher.iter(|| {
            index += 1;
            store.deposit(&mailbox(index % MAILBOXES), &payload)
        })
    });
}

fn fetch_batch(criterion: &mut Criterion) {
    let (store, _clock) = filled_store(4);
    let requested: Vec<MailboxId> = (0..BATCH).map(mailbox).collect();

    criterion.bench_function("fetch_batch_100", |bencher| {
        bencher.iter(|| store.fetch_batch(&requested, 0.0))
    });
}

fn fetch_batch_all_cover(criterion: &mut Criterion) {
    let (store, _clock) = filled_store(4);
    let requested: Vec<MailboxId> = (MAILBOXES..MAILBOXES + BATCH).map(mailbox).collect();

    criterion.bench_function("fetch_batch_100_cover", |bencher| {
        bencher.iter(|| store.fetch_batch(&requested, 0.0))
    });
}

fn collect_garbage(criterion: &mut Criterion) {
    criterion.bench_function("collect_garbage_4000", |bencher| {
        bencher.iter_batched(
            || {
                let (store, clock) = filled_store(4);
                clock.advance(StorageConfig::default().ttl_secs);
                store
            },
            |store| store.collect_garbage(),
            BatchSize::LargeInput,
        )
    });
}

criterion_group!(
    benches,
    deposit,
    fetch_batch,
    fetch_batch_all_cover,
    collect_garbage
);
criterion_main!(benches);

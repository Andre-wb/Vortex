//! Общий контракт хранилища блокировок: прогоняется и по памяти, и по Redis.

use std::sync::Arc;

use crate::domain::block_record::BlockRecord;
use crate::domain::client_ip::ClientIp;
use crate::domain::timestamp::Timestamp;
use crate::ports::prunable_block_store::PrunableBlockStore;
use crate::time::manual_clock::ManualClock;

pub const NOW_SECS: i64 = 1_700_000_000;

pub type StoreFactory = dyn Fn(Arc<ManualClock>) -> Arc<dyn PrunableBlockStore>;

struct Subject {
    store: Arc<dyn PrunableBlockStore>,
    clock: Arc<ManualClock>,
}

fn subject(make: &StoreFactory) -> Subject {
    let clock = Arc::new(ManualClock::new(Timestamp::from_unix_secs(NOW_SECS)));
    Subject {
        store: make(clock.clone()),
        clock,
    }
}

fn ip(value: &str) -> ClientIp {
    ClientIp::new(value)
}

fn now() -> Timestamp {
    Timestamp::from_unix_secs(NOW_SECS)
}

pub fn check_all(make: &StoreFactory) {
    a_blocked_address_is_blocked(make);
    an_unknown_address_is_not_blocked(make);
    a_block_expires_exactly_at_its_deadline(make);
    a_removed_block_stops_applying(make);
    removing_an_absent_block_reports_nothing_was_removed(make);
    a_repeated_block_replaces_the_previous_one(make);
    the_listing_returns_the_reason_and_the_deadline(make);
    pruning_drops_expired_blocks_only(make);
    addresses_do_not_share_their_blocks(make);
}

pub fn a_blocked_address_is_blocked(make: &StoreFactory) {
    let subject = subject(make);
    subject
        .store
        .put(&ip("1.2.3.4"), BlockRecord::new(now(), 60, "manual"));
    assert!(subject.store.is_blocked(&ip("1.2.3.4"), now()));
    assert_eq!(subject.store.len(), 1);
}

pub fn an_unknown_address_is_not_blocked(make: &StoreFactory) {
    let subject = subject(make);
    assert!(!subject.store.is_blocked(&ip("9.9.9.9"), now()));
    assert!(subject.store.is_empty());
}

pub fn a_block_expires_exactly_at_its_deadline(make: &StoreFactory) {
    let subject = subject(make);
    subject
        .store
        .put(&ip("1.2.3.5"), BlockRecord::new(now(), 60, "manual"));
    assert!(subject
        .store
        .is_blocked(&ip("1.2.3.5"), now().plus_secs(59)));
    assert!(!subject
        .store
        .is_blocked(&ip("1.2.3.5"), now().plus_secs(60)));
}

pub fn a_removed_block_stops_applying(make: &StoreFactory) {
    let subject = subject(make);
    subject
        .store
        .put(&ip("1.2.3.6"), BlockRecord::new(now(), 60, "manual"));
    assert!(subject.store.remove(&ip("1.2.3.6")));
    assert!(!subject.store.is_blocked(&ip("1.2.3.6"), now()));
}

pub fn removing_an_absent_block_reports_nothing_was_removed(make: &StoreFactory) {
    let subject = subject(make);
    assert!(!subject.store.remove(&ip("8.8.8.8")));
}

pub fn a_repeated_block_replaces_the_previous_one(make: &StoreFactory) {
    let subject = subject(make);
    subject
        .store
        .put(&ip("1.2.3.7"), BlockRecord::new(now(), 60, "first"));
    subject
        .store
        .put(&ip("1.2.3.7"), BlockRecord::new(now(), 120, "second"));
    let listed = subject.store.list();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].1.reason, "second");
    assert_eq!(listed[0].1.duration_secs, 120);
}

pub fn the_listing_returns_the_reason_and_the_deadline(make: &StoreFactory) {
    let subject = subject(make);
    subject
        .store
        .put(&ip("1.2.3.8"), BlockRecord::new(now(), 90, "flood"));
    let listed = subject.store.list();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].0, ip("1.2.3.8"));
    assert_eq!(listed[0].1.reason, "flood");
    assert_eq!(listed[0].1.blocked_at, now());
    assert_eq!(listed[0].1.until, now().plus_secs(90));
}

pub fn pruning_drops_expired_blocks_only(make: &StoreFactory) {
    let subject = subject(make);
    subject
        .store
        .put(&ip("1.2.3.9"), BlockRecord::new(now(), 60, "short"));
    subject
        .store
        .put(&ip("1.2.3.10"), BlockRecord::new(now(), 600, "long"));
    subject.clock.advance_secs(61);
    assert_eq!(subject.store.prune(), 1);
    assert_eq!(subject.store.len(), 1);
    assert!(subject
        .store
        .is_blocked(&ip("1.2.3.10"), now().plus_secs(61)));
}

pub fn addresses_do_not_share_their_blocks(make: &StoreFactory) {
    let subject = subject(make);
    subject
        .store
        .put(&ip("1.2.3.11"), BlockRecord::new(now(), 60, "manual"));
    assert!(!subject.store.is_blocked(&ip("1.2.3.12"), now()));
}

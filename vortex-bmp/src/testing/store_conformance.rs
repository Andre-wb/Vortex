use std::sync::Arc;

use crate::config::storage::StorageConfig;
use crate::mailbox::id::MailboxId;
use crate::ports::clock::Clock;
use crate::ports::mailbox_store::MailboxStore;
use crate::store::refusal::DepositRefusal;
use crate::time::manual_clock::ManualClock;

pub const NOW: f64 = 1_700_000_000.0;
pub const CIPHERTEXT: &str = "abababababababababababab";

pub type StoreFactory = dyn Fn(Arc<dyn Clock>, StorageConfig) -> Arc<dyn MailboxStore>;

pub struct Subject {
    pub store: Arc<dyn MailboxStore>,
    pub clock: Arc<ManualClock>,
}

fn subject(make: &StoreFactory, config: StorageConfig) -> Subject {
    let clock = Arc::new(ManualClock::at(NOW));
    let store = make(clock.clone(), config);
    Subject { store, clock }
}

pub fn mailbox(seed: &str) -> MailboxId {
    MailboxId::parse(&format!("{seed:0>32}")).unwrap()
}

fn payload(tag: &str) -> String {
    format!("{tag:a>24}")
}

pub fn check_all(make: &StoreFactory) {
    a_deposited_message_comes_back_on_the_next_fetch(make);
    an_unknown_mailbox_looks_exactly_like_an_empty_one(make);
    the_fetched_timestamp_is_bucketed_in_both_fetch_paths(make);
    an_oversized_message_is_refused(make);
    a_full_mailbox_drops_its_oldest_message(make);
    identical_ciphertexts_are_stored_and_returned_separately(make);
    deposits_inside_one_clock_tick_keep_their_insertion_order(make);
    a_new_mailbox_is_refused_once_the_mailbox_limit_is_reached(make);
    a_deposit_is_refused_once_the_byte_budget_is_spent(make);
    a_refused_deposit_leaves_no_empty_mailbox_behind(make);
    a_full_store_accepts_a_deposit_that_evicts_as_much_as_it_adds(make);
    messages_older_than_the_ttl_stop_being_returned(make);
    garbage_collection_reclaims_expired_messages(make);
    garbage_collection_keeps_messages_that_are_still_readable(make);
    a_batch_omits_mailboxes_without_messages(make);
    a_batch_answers_in_the_order_it_was_asked(make);
    a_repeated_mailbox_is_answered_once(make);
    the_since_mark_hides_everything_deposited_before_it(make);
    a_since_equal_to_the_deposit_time_hides_the_message(make);
    the_counters_describe_what_the_store_holds(make);
}

pub fn a_deposited_message_comes_back_on_the_next_fetch(make: &StoreFactory) {
    let subject = subject(make, StorageConfig::default());
    subject.store.deposit(&mailbox("a"), CIPHERTEXT).unwrap();
    let fetched = subject.store.fetch(&mailbox("a"), 0.0);
    assert_eq!(fetched.len(), 1, "депозит должен вернуться при чтении");
    assert_eq!(fetched[0].ciphertext(), CIPHERTEXT);
}

pub fn an_unknown_mailbox_looks_exactly_like_an_empty_one(make: &StoreFactory) {
    let subject = subject(make, StorageConfig::default());
    assert!(subject.store.fetch(&mailbox("b"), 0.0).is_empty());
}

pub fn the_fetched_timestamp_is_bucketed_in_both_fetch_paths(make: &StoreFactory) {
    let subject = subject(make, StorageConfig::default());
    subject.store.deposit(&mailbox("c"), CIPHERTEXT).unwrap();
    let single = subject.store.fetch(&mailbox("c"), 0.0);
    let batch = subject.store.fetch_batch(&[mailbox("c")], 0.0);
    assert_eq!(single[0].bucketed_at(), 1_699_999_800.0);
    assert_eq!(batch[0].1[0].bucketed_at(), single[0].bucketed_at());
}

pub fn an_oversized_message_is_refused(make: &StoreFactory) {
    let subject = subject(make, StorageConfig::default());
    let oversized = "a".repeat(StorageConfig::default().max_ciphertext_chars() + 1);
    assert_eq!(
        subject.store.deposit(&mailbox("d"), &oversized),
        Err(DepositRefusal::TooLarge)
    );
    assert_eq!(subject.store.stats().total_refused, 1);
}

pub fn a_full_mailbox_drops_its_oldest_message(make: &StoreFactory) {
    let config = StorageConfig::default().max_messages_per_mailbox(3);
    let subject = subject(make, config);
    for index in 0..5 {
        subject
            .store
            .deposit(&mailbox("e"), &payload(&format!("m{index}")))
            .unwrap();
        subject.clock.advance(1.0);
    }
    let fetched = subject.store.fetch(&mailbox("e"), 0.0);
    assert_eq!(fetched.len(), 3);
    assert_eq!(fetched[0].ciphertext(), payload("m2"));
    assert_eq!(fetched[2].ciphertext(), payload("m4"));
}

pub fn identical_ciphertexts_are_stored_and_returned_separately(make: &StoreFactory) {
    let subject = subject(make, StorageConfig::default());
    subject.store.deposit(&mailbox("f"), CIPHERTEXT).unwrap();
    subject.store.deposit(&mailbox("f"), CIPHERTEXT).unwrap();
    let fetched = subject.store.fetch(&mailbox("f"), 0.0);
    assert_eq!(
        fetched.len(),
        2,
        "одинаковые шифртексты не должны слипаться"
    );
}

pub fn deposits_inside_one_clock_tick_keep_their_insertion_order(make: &StoreFactory) {
    let subject = subject(make, StorageConfig::default());
    for tag in ["zz", "aa", "mm"] {
        subject
            .store
            .deposit(&mailbox("1a"), &payload(tag))
            .unwrap();
    }
    let fetched = subject.store.fetch(&mailbox("1a"), 0.0);
    let order: Vec<&str> = fetched.iter().map(|message| message.ciphertext()).collect();
    assert_eq!(order, vec![payload("zz"), payload("aa"), payload("mm")]);
}

pub fn a_new_mailbox_is_refused_once_the_mailbox_limit_is_reached(make: &StoreFactory) {
    let config = StorageConfig::default().max_mailboxes(2);
    let subject = subject(make, config);
    subject.store.deposit(&mailbox("1"), CIPHERTEXT).unwrap();
    subject.store.deposit(&mailbox("2"), CIPHERTEXT).unwrap();
    assert_eq!(
        subject.store.deposit(&mailbox("3"), CIPHERTEXT),
        Err(DepositRefusal::AtCapacity)
    );
    assert!(subject.store.deposit(&mailbox("1"), CIPHERTEXT).is_ok());
}

pub fn a_deposit_is_refused_once_the_byte_budget_is_spent(make: &StoreFactory) {
    let config = StorageConfig::default().max_stored_bytes(48);
    let subject = subject(make, config);
    subject.store.deposit(&mailbox("1"), CIPHERTEXT).unwrap();
    subject.store.deposit(&mailbox("2"), CIPHERTEXT).unwrap();
    assert_eq!(
        subject.store.deposit(&mailbox("3"), "a"),
        Err(DepositRefusal::AtCapacity)
    );
}

pub fn a_refused_deposit_leaves_no_empty_mailbox_behind(make: &StoreFactory) {
    let config = StorageConfig::default().max_stored_bytes(24);
    let subject = subject(make, config);
    subject.store.deposit(&mailbox("1"), CIPHERTEXT).unwrap();
    let _ = subject.store.deposit(&mailbox("2"), CIPHERTEXT);
    assert_eq!(subject.store.stats().active_mailboxes, 1);
}

pub fn a_full_store_accepts_a_deposit_that_evicts_as_much_as_it_adds(make: &StoreFactory) {
    let config = StorageConfig::default()
        .max_stored_bytes(24)
        .max_messages_per_mailbox(1);
    let subject = subject(make, config);
    subject.store.deposit(&mailbox("1"), CIPHERTEXT).unwrap();
    assert!(subject.store.deposit(&mailbox("1"), CIPHERTEXT).is_ok());
    assert_eq!(subject.store.stats().stored_bytes, 24);
}

pub fn messages_older_than_the_ttl_stop_being_returned(make: &StoreFactory) {
    let subject = subject(make, StorageConfig::default());
    subject.store.deposit(&mailbox("1b"), CIPHERTEXT).unwrap();
    subject.clock.advance(7200.0);
    assert!(subject.store.fetch(&mailbox("1b"), 0.0).is_empty());
}

pub fn garbage_collection_reclaims_expired_messages(make: &StoreFactory) {
    let subject = subject(make, StorageConfig::default());
    subject.store.deposit(&mailbox("1c"), CIPHERTEXT).unwrap();
    subject.clock.advance(7200.0);
    assert_eq!(subject.store.collect_garbage(), 1);
    let stats = subject.store.stats();
    assert_eq!(stats.active_mailboxes, 0);
    assert_eq!(stats.stored_bytes, 0);
    assert_eq!(stats.total_expired, 1);
}

pub fn garbage_collection_keeps_messages_that_are_still_readable(make: &StoreFactory) {
    let subject = subject(make, StorageConfig::default());
    subject.store.deposit(&mailbox("1d"), CIPHERTEXT).unwrap();
    subject.clock.advance(7199.0);
    assert_eq!(subject.store.collect_garbage(), 0);
    assert_eq!(subject.store.fetch(&mailbox("1d"), 0.0).len(), 1);
}

pub fn a_batch_omits_mailboxes_without_messages(make: &StoreFactory) {
    let subject = subject(make, StorageConfig::default());
    subject.store.deposit(&mailbox("1"), CIPHERTEXT).unwrap();
    let found = subject
        .store
        .fetch_batch(&[mailbox("1"), mailbox("2")], 0.0);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].0, mailbox("1"));
}

pub fn a_batch_answers_in_the_order_it_was_asked(make: &StoreFactory) {
    let subject = subject(make, StorageConfig::default());
    for seed in ["3", "1", "2"] {
        subject.store.deposit(&mailbox(seed), CIPHERTEXT).unwrap();
    }
    let found = subject
        .store
        .fetch_batch(&[mailbox("2"), mailbox("3"), mailbox("1")], 0.0);
    let order: Vec<MailboxId> = found.into_iter().map(|(id, _)| id).collect();
    assert_eq!(order, vec![mailbox("2"), mailbox("3"), mailbox("1")]);
}

pub fn a_repeated_mailbox_is_answered_once(make: &StoreFactory) {
    let subject = subject(make, StorageConfig::default());
    subject.store.deposit(&mailbox("1"), CIPHERTEXT).unwrap();
    let found = subject
        .store
        .fetch_batch(&[mailbox("1"), mailbox("1")], 0.0);
    assert_eq!(found.len(), 1);
}

pub fn the_since_mark_hides_everything_deposited_before_it(make: &StoreFactory) {
    let subject = subject(make, StorageConfig::default());
    subject
        .store
        .deposit(&mailbox("1e"), &payload("old"))
        .unwrap();
    subject.clock.advance(10.0);
    subject
        .store
        .deposit(&mailbox("1e"), &payload("new"))
        .unwrap();
    let fetched = subject.store.fetch(&mailbox("1e"), NOW + 5.0);
    assert_eq!(fetched.len(), 1);
    assert_eq!(fetched[0].ciphertext(), payload("new"));
}

pub fn a_since_equal_to_the_deposit_time_hides_the_message(make: &StoreFactory) {
    let subject = subject(make, StorageConfig::default());
    subject.store.deposit(&mailbox("1f"), CIPHERTEXT).unwrap();
    assert!(subject.store.fetch(&mailbox("1f"), NOW).is_empty());
    assert_eq!(subject.store.fetch(&mailbox("1f"), NOW - 0.5).len(), 1);
}

pub fn the_counters_describe_what_the_store_holds(make: &StoreFactory) {
    let subject = subject(make, StorageConfig::default());
    subject.store.deposit(&mailbox("1"), CIPHERTEXT).unwrap();
    subject.store.deposit(&mailbox("1"), CIPHERTEXT).unwrap();
    subject.store.deposit(&mailbox("2"), CIPHERTEXT).unwrap();
    subject.store.fetch(&mailbox("1"), 0.0);
    let stats = subject.store.stats();
    assert_eq!(stats.active_mailboxes, 2);
    assert_eq!(stats.total_messages, 3);
    assert_eq!(stats.stored_bytes, CIPHERTEXT.len() * 3);
    assert_eq!(stats.total_deposited, 3);
    assert_eq!(stats.total_fetched, 1);
}

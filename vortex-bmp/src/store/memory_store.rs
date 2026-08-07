use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use parking_lot::RwLock;

use crate::config::storage::StorageConfig;
use crate::mailbox::bucket::bucket;
use crate::mailbox::fetched::FetchedMessage;
use crate::mailbox::id::MailboxId;
use crate::mailbox::message::StoredMessage;
use crate::ports::clock::Clock;
use crate::ports::mailbox_store::MailboxStore;
use crate::store::refusal::DepositRefusal;
use crate::store::stats::StoreStats;

#[derive(Default)]
struct Contents {
    mailboxes: HashMap<MailboxId, Vec<StoredMessage>>,
    stored_bytes: usize,
}

#[derive(Default)]
struct Counters {
    deposited: AtomicU64,
    fetched: AtomicU64,
    expired: AtomicU64,
    refused: AtomicU64,
}

impl Counters {
    fn bump(counter: &AtomicU64, by: u64) {
        counter.fetch_add(by, Ordering::Relaxed);
    }

    fn read(counter: &AtomicU64) -> u64 {
        counter.load(Ordering::Relaxed)
    }
}

pub struct MemoryMailboxStore {
    contents: RwLock<Contents>,
    counters: Counters,
    clock: Arc<dyn Clock>,
    config: StorageConfig,
}

impl MemoryMailboxStore {
    pub fn new(clock: Arc<dyn Clock>, config: StorageConfig) -> Self {
        MemoryMailboxStore {
            contents: RwLock::new(Contents::default()),
            counters: Counters::default(),
            clock,
            config,
        }
    }

    fn visible(&self, messages: &[StoredMessage], now: f64, since: f64) -> Vec<FetchedMessage> {
        messages
            .iter()
            .filter(|message| message.is_visible_at(now, since, self.config.ttl_secs))
            .map(|message| {
                FetchedMessage::new(
                    message.ciphertext().to_string(),
                    bucket(message.deposited_at(), self.config.bucket_secs),
                )
            })
            .collect()
    }
}

impl MailboxStore for MemoryMailboxStore {
    fn deposit(&self, mailbox: &MailboxId, ciphertext: &str) -> Result<(), DepositRefusal> {
        let incoming = ciphertext.len();
        let mut contents = self.contents.write();

        if incoming > self.config.max_ciphertext_chars() {
            Counters::bump(&self.counters.refused, 1);
            return Err(DepositRefusal::TooLarge);
        }

        let (is_new, evicted_bytes) = match contents.mailboxes.get(mailbox) {
            None => (true, 0),
            Some(messages) if messages.len() >= self.config.max_messages_per_mailbox => (
                false,
                messages
                    .first()
                    .map(|first| first.stored_bytes())
                    .unwrap_or(0),
            ),
            Some(_) => (false, 0),
        };

        if is_new && contents.mailboxes.len() >= self.config.max_mailboxes {
            Counters::bump(&self.counters.refused, 1);
            return Err(DepositRefusal::AtCapacity);
        }

        let projected = contents
            .stored_bytes
            .saturating_add(incoming)
            .saturating_sub(evicted_bytes);
        if projected > self.config.max_stored_bytes {
            Counters::bump(&self.counters.refused, 1);
            return Err(DepositRefusal::AtCapacity);
        }

        let now = self.clock.unix_seconds();
        let messages = contents.mailboxes.entry(mailbox.clone()).or_default();
        if messages.len() >= self.config.max_messages_per_mailbox {
            messages.remove(0);
        }
        messages.push(StoredMessage::new(ciphertext.to_string(), now));

        contents.stored_bytes = projected;
        Counters::bump(&self.counters.deposited, 1);
        Ok(())
    }

    fn fetch(&self, mailbox: &MailboxId, since: f64) -> Vec<FetchedMessage> {
        let now = self.clock.unix_seconds();
        Counters::bump(&self.counters.fetched, 1);
        let contents = self.contents.read();
        match contents.mailboxes.get(mailbox) {
            Some(messages) => self.visible(messages, now, since),
            None => Vec::new(),
        }
    }

    fn fetch_batch(
        &self,
        mailboxes: &[MailboxId],
        since: f64,
    ) -> Vec<(MailboxId, Vec<FetchedMessage>)> {
        let now = self.clock.unix_seconds();
        Counters::bump(&self.counters.fetched, 1);
        let contents = self.contents.read();

        let mut found = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for mailbox in mailboxes {
            if !seen.insert(mailbox) {
                continue;
            }
            let Some(messages) = contents.mailboxes.get(mailbox) else {
                continue;
            };
            let visible = self.visible(messages, now, since);
            if !visible.is_empty() {
                found.push((mailbox.clone(), visible));
            }
        }
        found
    }

    fn collect_garbage(&self) -> u64 {
        let now = self.clock.unix_seconds();
        let ttl = self.config.ttl_secs;
        let mut contents = self.contents.write();

        let mut removed = 0u64;
        let mut freed = 0usize;
        contents.mailboxes.retain(|_, messages| {
            messages.retain(|message| {
                if message.is_expired_at(now, ttl) {
                    removed += 1;
                    freed += message.stored_bytes();
                    false
                } else {
                    true
                }
            });
            !messages.is_empty()
        });

        contents.stored_bytes = contents.stored_bytes.saturating_sub(freed);
        Counters::bump(&self.counters.expired, removed);
        removed
    }

    fn stats(&self) -> StoreStats {
        let contents = self.contents.read();
        StoreStats {
            active_mailboxes: contents.mailboxes.len(),
            total_messages: contents.mailboxes.values().map(Vec::len).sum(),
            stored_bytes: contents.stored_bytes,
            total_deposited: Counters::read(&self.counters.deposited),
            total_fetched: Counters::read(&self.counters.fetched),
            total_expired: Counters::read(&self.counters.expired),
            total_refused: Counters::read(&self.counters.refused),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::MemoryMailboxStore;
    use crate::config::storage::StorageConfig;
    use crate::mailbox::id::MailboxId;
    use crate::ports::mailbox_store::MailboxStore;
    use crate::store::refusal::DepositRefusal;
    use crate::time::manual_clock::ManualClock;
    use std::sync::Arc;

    const NOW: f64 = 1_700_000_000.0;

    struct Fixture {
        store: MemoryMailboxStore,
        clock: Arc<ManualClock>,
    }

    fn fixture_with(config: StorageConfig) -> Fixture {
        let clock = Arc::new(ManualClock::at(NOW));
        Fixture {
            store: MemoryMailboxStore::new(clock.clone(), config),
            clock,
        }
    }

    fn fixture() -> Fixture {
        fixture_with(StorageConfig::default())
    }

    fn mailbox(seed: &str) -> MailboxId {
        MailboxId::parse(&format!("{seed:0>16}")).unwrap()
    }

    #[test]
    fn a_deposited_message_comes_back_on_the_next_fetch() {
        let fixture = fixture();
        fixture.store.deposit(&mailbox("a"), "aabbccdd").unwrap();
        let fetched = fixture.store.fetch(&mailbox("a"), 0.0);
        assert_eq!(fetched.len(), 1);
        assert_eq!(fetched[0].ciphertext(), "aabbccdd");
    }

    #[test]
    fn an_unknown_mailbox_looks_exactly_like_an_empty_one() {
        let fixture = fixture();
        assert!(fixture.store.fetch(&mailbox("b"), 0.0).is_empty());
    }

    #[test]
    fn the_fetched_timestamp_is_bucketed_in_both_fetch_paths() {
        let fixture = fixture_with(StorageConfig::default());
        fixture.store.deposit(&mailbox("c"), "aa").unwrap();
        let single = fixture.store.fetch(&mailbox("c"), 0.0);
        let batch = fixture.store.fetch_batch(&[mailbox("c")], 0.0);
        assert_eq!(single[0].bucketed_at(), 1_699_999_800.0);
        assert_eq!(batch[0].1[0].bucketed_at(), single[0].bucketed_at());
    }

    #[test]
    fn an_oversized_message_is_refused() {
        let fixture = fixture();
        let oversized = "a".repeat(StorageConfig::default().max_ciphertext_chars() + 1);
        assert_eq!(
            fixture.store.deposit(&mailbox("d"), &oversized),
            Err(DepositRefusal::TooLarge)
        );
        assert_eq!(fixture.store.stats().total_refused, 1);
    }

    #[test]
    fn a_full_mailbox_drops_its_oldest_message() {
        let config = StorageConfig::default().max_messages_per_mailbox(3);
        let fixture = fixture_with(config);
        for index in 0..5 {
            fixture
                .store
                .deposit(&mailbox("e"), &format!("{index:02}"))
                .unwrap();
        }
        let fetched = fixture.store.fetch(&mailbox("e"), 0.0);
        assert_eq!(fetched.len(), 3);
        assert_eq!(fetched[0].ciphertext(), "02");
        assert_eq!(fetched[2].ciphertext(), "04");
    }

    #[test]
    fn eviction_keeps_the_byte_count_honest() {
        let config = StorageConfig::default().max_messages_per_mailbox(2);
        let fixture = fixture_with(config);
        for index in 0..6 {
            fixture
                .store
                .deposit(&mailbox("f"), &format!("{index:04}"))
                .unwrap();
        }
        assert_eq!(fixture.store.stats().stored_bytes, 8);
    }

    #[test]
    fn a_new_mailbox_is_refused_once_the_mailbox_limit_is_reached() {
        let config = StorageConfig::default().max_mailboxes(2);
        let fixture = fixture_with(config);
        fixture.store.deposit(&mailbox("1"), "aa").unwrap();
        fixture.store.deposit(&mailbox("2"), "aa").unwrap();
        assert_eq!(
            fixture.store.deposit(&mailbox("3"), "aa"),
            Err(DepositRefusal::AtCapacity)
        );
        assert!(fixture.store.deposit(&mailbox("1"), "bb").is_ok());
    }

    #[test]
    fn a_deposit_is_refused_once_the_byte_budget_is_spent() {
        let config = StorageConfig::default().max_stored_bytes(8);
        let fixture = fixture_with(config);
        fixture.store.deposit(&mailbox("1"), "aaaa").unwrap();
        fixture.store.deposit(&mailbox("2"), "bbbb").unwrap();
        assert_eq!(
            fixture.store.deposit(&mailbox("3"), "c"),
            Err(DepositRefusal::AtCapacity)
        );
    }

    #[test]
    fn a_refused_deposit_leaves_no_empty_mailbox_behind() {
        let config = StorageConfig::default().max_stored_bytes(4);
        let fixture = fixture_with(config);
        fixture.store.deposit(&mailbox("1"), "aaaa").unwrap();
        let _ = fixture.store.deposit(&mailbox("2"), "b");
        assert_eq!(fixture.store.stats().active_mailboxes, 1);
    }

    #[test]
    fn a_full_store_accepts_a_deposit_that_evicts_as_much_as_it_adds() {
        let config = StorageConfig::default()
            .max_stored_bytes(4)
            .max_messages_per_mailbox(1);
        let fixture = fixture_with(config);
        fixture.store.deposit(&mailbox("1"), "aaaa").unwrap();
        assert!(fixture.store.deposit(&mailbox("1"), "bbbb").is_ok());
        assert_eq!(fixture.store.stats().stored_bytes, 4);
    }

    #[test]
    fn messages_older_than_the_ttl_stop_being_returned() {
        let fixture = fixture();
        fixture.store.deposit(&mailbox("a1"), "aa").unwrap();
        fixture.clock.advance(7200.0);
        assert!(fixture.store.fetch(&mailbox("a1"), 0.0).is_empty());
    }

    #[test]
    fn garbage_collection_reclaims_expired_messages_and_their_bytes() {
        let fixture = fixture();
        fixture.store.deposit(&mailbox("a2"), "aabb").unwrap();
        fixture.clock.advance(7200.0);
        assert_eq!(fixture.store.collect_garbage(), 1);
        let stats = fixture.store.stats();
        assert_eq!(stats.active_mailboxes, 0);
        assert_eq!(stats.stored_bytes, 0);
        assert_eq!(stats.total_expired, 1);
    }

    #[test]
    fn garbage_collection_keeps_messages_that_are_still_readable() {
        let fixture = fixture();
        fixture.store.deposit(&mailbox("a3"), "aa").unwrap();
        fixture.clock.advance(7199.0);
        assert_eq!(fixture.store.collect_garbage(), 0);
        assert_eq!(fixture.store.fetch(&mailbox("a3"), 0.0).len(), 1);
    }

    #[test]
    fn a_batch_omits_mailboxes_without_messages() {
        let fixture = fixture();
        fixture.store.deposit(&mailbox("1"), "aa").unwrap();
        let found = fixture
            .store
            .fetch_batch(&[mailbox("1"), mailbox("2")], 0.0);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].0, mailbox("1"));
    }

    #[test]
    fn a_batch_answers_in_the_order_it_was_asked() {
        let fixture = fixture();
        for seed in ["3", "1", "2"] {
            fixture.store.deposit(&mailbox(seed), "aa").unwrap();
        }
        let found = fixture
            .store
            .fetch_batch(&[mailbox("2"), mailbox("3"), mailbox("1")], 0.0);
        let order: Vec<MailboxId> = found.into_iter().map(|(id, _)| id).collect();
        assert_eq!(order, vec![mailbox("2"), mailbox("3"), mailbox("1")]);
    }

    #[test]
    fn a_repeated_mailbox_is_answered_once() {
        let fixture = fixture();
        fixture.store.deposit(&mailbox("1"), "aa").unwrap();
        let found = fixture
            .store
            .fetch_batch(&[mailbox("1"), mailbox("1")], 0.0);
        assert_eq!(found.len(), 1);
    }

    #[test]
    fn the_since_mark_hides_everything_deposited_before_it() {
        let fixture = fixture();
        fixture.store.deposit(&mailbox("a4"), "old").unwrap();
        fixture.clock.advance(10.0);
        fixture.store.deposit(&mailbox("a4"), "new").unwrap();
        let fetched = fixture.store.fetch(&mailbox("a4"), NOW + 5.0);
        assert_eq!(fetched.len(), 1);
        assert_eq!(fetched[0].ciphertext(), "new");
    }

    #[test]
    fn the_counters_describe_what_the_store_holds() {
        let fixture = fixture();
        fixture.store.deposit(&mailbox("1"), "111").unwrap();
        fixture.store.deposit(&mailbox("1"), "222").unwrap();
        fixture.store.deposit(&mailbox("2"), "333").unwrap();
        fixture.store.fetch(&mailbox("1"), 0.0);
        let stats = fixture.store.stats();
        assert_eq!(stats.active_mailboxes, 2);
        assert_eq!(stats.total_messages, 3);
        assert_eq!(stats.stored_bytes, 9);
        assert_eq!(stats.total_deposited, 3);
        assert_eq!(stats.total_fetched, 1);
    }
}

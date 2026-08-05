//! Хранилище временных блокировок в памяти процесса.

use crate::domain::block_record::BlockRecord;
use crate::domain::client_ip::ClientIp;
use crate::domain::timestamp::Timestamp;
use crate::ports::block_store::BlockStore;
use crate::ports::clock::Clock;
use crate::ports::prunable::Prunable;
use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

pub struct InMemoryBlockStore {
    records: RwLock<BTreeMap<ClientIp, BlockRecord>>,
    clock: Arc<dyn Clock>,
}

impl InMemoryBlockStore {
    pub fn new(clock: Arc<dyn Clock>) -> Self {
        InMemoryBlockStore {
            records: RwLock::new(BTreeMap::new()),
            clock,
        }
    }
}

impl BlockStore for InMemoryBlockStore {
    fn put(&self, ip: &ClientIp, record: BlockRecord) {
        self.records
            .write()
            .expect("хранилище блокировок отравлено")
            .insert(ip.clone(), record);
    }

    fn is_blocked(&self, ip: &ClientIp, now: Timestamp) -> bool {
        let mut guard = self
            .records
            .write()
            .expect("хранилище блокировок отравлено");
        match guard.get(ip) {
            Some(record) if record.is_active_at(now) => true,
            // Просроченную запись удаляем сразу при обращении.
            Some(_) => {
                guard.remove(ip);
                false
            }
            None => false,
        }
    }

    fn remove(&self, ip: &ClientIp) -> bool {
        self.records
            .write()
            .expect("хранилище блокировок отравлено")
            .remove(ip)
            .is_some()
    }

    fn list(&self) -> Vec<(ClientIp, BlockRecord)> {
        self.records
            .read()
            .expect("хранилище блокировок отравлено")
            .iter()
            .map(|(ip, record)| (ip.clone(), record.clone()))
            .collect()
    }

    fn len(&self) -> usize {
        self.records
            .read()
            .expect("хранилище блокировок отравлено")
            .len()
    }
}

impl Prunable for InMemoryBlockStore {
    fn name(&self) -> &'static str {
        "block-store"
    }

    fn prune(&self) -> usize {
        let now = self.clock.now();
        let mut guard = self
            .records
            .write()
            .expect("хранилище блокировок отравлено");
        let before = guard.len();
        guard.retain(|_, record| record.is_active_at(now));
        before - guard.len()
    }
}

#[cfg(test)]
mod tests {
    use super::InMemoryBlockStore;
    use crate::domain::block_record::BlockRecord;
    use crate::domain::client_ip::ClientIp;
    use crate::ports::block_store::BlockStore;
    use crate::ports::clock::Clock;
    use crate::ports::prunable::Prunable;
    use crate::time::manual_clock::ManualClock;
    use std::sync::Arc;

    #[test]
    fn block_expires_with_time() {
        let clock = Arc::new(ManualClock::at_epoch());
        let store = InMemoryBlockStore::new(clock.clone());
        let ip = ClientIp::from("1.2.3.4");
        store.put(&ip, BlockRecord::new(clock.now(), 60, "тест"));

        assert!(store.is_blocked(&ip, clock.now()));
        clock.advance_secs(61);
        assert!(!store.is_blocked(&ip, clock.now()));
        // Просроченная запись удалена при проверке.
        assert!(store.is_empty());
    }

    #[test]
    fn prune_drops_only_expired_records() {
        let clock = Arc::new(ManualClock::at_epoch());
        let store = InMemoryBlockStore::new(clock.clone());
        store.put(
            &ClientIp::from("1.1.1.1"),
            BlockRecord::new(clock.now(), 10, "a"),
        );
        store.put(
            &ClientIp::from("2.2.2.2"),
            BlockRecord::new(clock.now(), 600, "b"),
        );

        clock.advance_secs(60);
        assert_eq!(store.prune(), 1);
        assert_eq!(store.len(), 1);
        assert_eq!(store.list()[0].0.as_str(), "2.2.2.2");
    }

    #[test]
    fn remove_reports_whether_a_record_existed() {
        let clock = Arc::new(ManualClock::at_epoch());
        let store = InMemoryBlockStore::new(clock.clone());
        let ip = ClientIp::from("9.9.9.9");
        assert!(!store.remove(&ip));
        store.put(&ip, BlockRecord::new(clock.now(), 10, "a"));
        assert!(store.remove(&ip));
    }
}

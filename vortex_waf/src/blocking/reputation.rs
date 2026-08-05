//! Репутация адреса: свод белого списка, чёрного списка и временных блокировок.
//!
//! Здесь и только здесь действует правило «адрес из белого списка нельзя
//! заблокировать». Прежде эта проверка была размазана по движку.

use crate::domain::block_record::BlockRecord;
use crate::domain::client_ip::ClientIp;
use crate::ports::block_store::BlockStore;
use crate::ports::clock::Clock;
use crate::ports::ip_allow_list::IpAllowList;
use crate::ports::ip_blocker::IpBlocker;
use crate::ports::ip_deny_list::IpDenyList;
use crate::ports::ip_gate::IpGate;
use crate::ports::stats_collector::StatsCollector;
use std::sync::Arc;

pub struct IpReputation {
    allow_list: Arc<dyn IpAllowList>,
    deny_list: Arc<dyn IpDenyList>,
    store: Arc<dyn BlockStore>,
    clock: Arc<dyn Clock>,
    stats: Arc<dyn StatsCollector>,
}

impl IpReputation {
    pub fn new(
        allow_list: Arc<dyn IpAllowList>,
        deny_list: Arc<dyn IpDenyList>,
        store: Arc<dyn BlockStore>,
        clock: Arc<dyn Clock>,
        stats: Arc<dyn StatsCollector>,
    ) -> Self {
        IpReputation {
            allow_list,
            deny_list,
            store,
            clock,
            stats,
        }
    }

    pub fn allow_list(&self) -> &Arc<dyn IpAllowList> {
        &self.allow_list
    }

    pub fn deny_list(&self) -> &Arc<dyn IpDenyList> {
        &self.deny_list
    }

    pub fn store(&self) -> &Arc<dyn BlockStore> {
        &self.store
    }
}

impl IpGate for IpReputation {
    fn is_blocked(&self, ip: &ClientIp) -> bool {
        if self.allow_list.contains(ip) {
            return false;
        }
        if self.deny_list.contains(ip) {
            return true;
        }
        self.store.is_blocked(ip, self.clock.now())
    }
}

impl IpBlocker for IpReputation {
    fn block(&self, ip: &ClientIp, reason: &str, duration_secs: u64) -> bool {
        if self.allow_list.contains(ip) {
            return false;
        }
        let now = self.clock.now();
        self.store
            .put(ip, BlockRecord::new(now, duration_secs, reason));
        self.stats.record_ip_block();
        true
    }

    fn unblock(&self, ip: &ClientIp) -> bool {
        self.store.remove(ip)
    }
}

#[cfg(test)]
mod tests {
    use super::IpReputation;
    use crate::blocking::allow_list::InMemoryAllowList;
    use crate::blocking::deny_list::InMemoryDenyList;
    use crate::blocking::memory_store::InMemoryBlockStore;
    use crate::domain::client_ip::ClientIp;
    use crate::ports::ip_blocker::IpBlocker;
    use crate::ports::ip_gate::IpGate;
    use crate::ports::stats_reporter::StatsReporter;
    use crate::stats::in_memory::InMemoryStats;
    use crate::time::manual_clock::ManualClock;
    use std::sync::Arc;

    fn reputation() -> (IpReputation, Arc<ManualClock>, Arc<InMemoryStats>) {
        let clock = Arc::new(ManualClock::at_epoch());
        let stats = Arc::new(InMemoryStats::new());
        let reputation = IpReputation::new(
            Arc::new(InMemoryAllowList::with_loopback()),
            Arc::new(InMemoryDenyList::empty()),
            Arc::new(InMemoryBlockStore::new(clock.clone())),
            clock.clone(),
            stats.clone(),
        );
        (reputation, clock, stats)
    }

    #[test]
    fn whitelisted_ip_cannot_be_blocked() {
        let (reputation, _, stats) = reputation();
        let ip = ClientIp::from("127.0.0.1");
        assert!(!reputation.block(&ip, "попытка", 60));
        assert!(!reputation.is_blocked(&ip));
        assert_eq!(stats.snapshot().ip_blocks, 0);
    }

    #[test]
    fn whitelist_wins_over_denylist() {
        let clock = Arc::new(ManualClock::at_epoch());
        let reputation = IpReputation::new(
            Arc::new(InMemoryAllowList::new(["5.5.5.5"])),
            Arc::new(InMemoryDenyList::new(["5.5.5.5"])),
            Arc::new(InMemoryBlockStore::new(clock.clone())),
            clock,
            Arc::new(InMemoryStats::new()),
        );
        assert!(!reputation.is_blocked(&ClientIp::from("5.5.5.5")));
    }

    #[test]
    fn temporary_block_is_counted_and_expires() {
        let (reputation, clock, stats) = reputation();
        let ip = ClientIp::from("8.8.8.8");
        assert!(reputation.block(&ip, "флуд", 120));
        assert!(reputation.is_blocked(&ip));
        assert_eq!(stats.snapshot().ip_blocks, 1);

        clock.advance_secs(121);
        assert!(!reputation.is_blocked(&ip));
    }

    #[test]
    fn unblock_reports_whether_a_block_existed() {
        let (reputation, _, _) = reputation();
        let ip = ClientIp::from("8.8.4.4");
        assert!(!reputation.unblock(&ip));
        reputation.block(&ip, "флуд", 60);
        assert!(reputation.unblock(&ip));
        assert!(!reputation.is_blocked(&ip));
    }
}

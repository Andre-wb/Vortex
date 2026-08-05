//! Счётчики в памяти процесса.

use crate::domain::rule_id::RuleId;
use crate::domain::timestamp::Timestamp;
use crate::ports::rule_activity::{RuleActivity, RuleActivityRecorder};
use crate::ports::stats_collector::StatsCollector;
use crate::ports::stats_reporter::StatsReporter;
use crate::stats::snapshot::StatsSnapshot;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;

#[derive(Debug, Default)]
pub struct InMemoryStats {
    total_requests: AtomicU64,
    blocked_requests: AtomicU64,
    ip_blocks: AtomicU64,
    /// Блокировки в разрезе правил.
    rules_triggered: RwLock<BTreeMap<RuleId, u64>>,
    /// Все совпадения правил, включая не приведшие к блокировке.
    activity: RwLock<BTreeMap<RuleId, RuleActivity>>,
}

impl InMemoryStats {
    pub fn new() -> Self {
        InMemoryStats::default()
    }
}

impl StatsCollector for InMemoryStats {
    fn record_request(&self) {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
    }

    fn record_blocked_request(&self) {
        self.blocked_requests.fetch_add(1, Ordering::Relaxed);
    }

    fn record_rule_block(&self, rule_id: &RuleId) {
        let mut guard = self.rules_triggered.write().expect("статистика отравлена");
        *guard.entry(rule_id.clone()).or_insert(0) += 1;
    }

    fn record_ip_block(&self) {
        self.ip_blocks.fetch_add(1, Ordering::Relaxed);
    }
}

impl RuleActivityRecorder for InMemoryStats {
    fn record_match(&self, rule_id: &RuleId, at: Timestamp) {
        let mut guard = self.activity.write().expect("статистика отравлена");
        let entry = guard.entry(rule_id.clone()).or_default();
        entry.trigger_count += 1;
        entry.last_triggered = Some(at);
    }
}

impl StatsReporter for InMemoryStats {
    fn snapshot(&self) -> StatsSnapshot {
        StatsSnapshot {
            total_requests: self.total_requests.load(Ordering::Relaxed),
            blocked_requests: self.blocked_requests.load(Ordering::Relaxed),
            rules_triggered: self
                .rules_triggered
                .read()
                .expect("статистика отравлена")
                .clone(),
            ip_blocks: self.ip_blocks.load(Ordering::Relaxed),
        }
    }

    fn activity(&self, rule_id: &RuleId) -> RuleActivity {
        self.activity
            .read()
            .expect("статистика отравлена")
            .get(rule_id)
            .cloned()
            .unwrap_or_default()
    }

    fn active_rule_count(&self) -> usize {
        self.activity
            .read()
            .expect("статистика отравлена")
            .values()
            .filter(|a| a.trigger_count > 0)
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::InMemoryStats;
    use crate::domain::rule_id::RuleId;
    use crate::domain::timestamp::Timestamp;
    use crate::ports::rule_activity::RuleActivityRecorder;
    use crate::ports::stats_collector::StatsCollector;
    use crate::ports::stats_reporter::StatsReporter;

    #[test]
    fn separates_matches_from_blocks() {
        let stats = InMemoryStats::new();
        let id = RuleId::from("SQLI-001");
        // Три совпадения, но блокировку засчитали только одну.
        for _ in 0..3 {
            stats.record_match(&id, Timestamp::from_unix_secs(10));
        }
        stats.record_rule_block(&id);
        stats.record_request();
        stats.record_blocked_request();

        let snapshot = stats.snapshot();
        assert_eq!(snapshot.rules_triggered.get(&id), Some(&1));
        assert_eq!(stats.activity(&id).trigger_count, 3);
        assert_eq!(
            stats.activity(&id).last_triggered,
            Some(Timestamp::from_unix_secs(10))
        );
        assert_eq!(stats.active_rule_count(), 1);
        assert_eq!(snapshot.block_rate(), 100.0);
    }

    #[test]
    fn unknown_rule_has_empty_activity() {
        let stats = InMemoryStats::new();
        assert_eq!(stats.activity(&RuleId::from("NOPE")).trigger_count, 0);
    }
}

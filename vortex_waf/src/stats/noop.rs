//! Заглушка статистики: ничего не считает.
//!
//! Пригодна везде, где нужен `StatsCollector`, но телеметрия не нужна —
//! подстановка не меняет наблюдаемого поведения движка (LSP).

use crate::domain::rule_id::RuleId;
use crate::domain::timestamp::Timestamp;
use crate::ports::rule_activity::{RuleActivity, RuleActivityRecorder};
use crate::ports::stats_collector::StatsCollector;
use crate::ports::stats_reporter::StatsReporter;
use crate::stats::snapshot::StatsSnapshot;

#[derive(Debug, Clone, Copy, Default)]
pub struct NoopStats;

impl NoopStats {
    pub fn new() -> Self {
        NoopStats
    }
}

impl StatsCollector for NoopStats {
    fn record_request(&self) {}
    fn record_blocked_request(&self) {}
    fn record_rule_block(&self, _rule_id: &RuleId) {}
    fn record_ip_block(&self) {}
}

impl RuleActivityRecorder for NoopStats {
    fn record_match(&self, _rule_id: &RuleId, _at: Timestamp) {}
}

impl StatsReporter for NoopStats {
    fn snapshot(&self) -> StatsSnapshot {
        StatsSnapshot::default()
    }

    fn activity(&self, _rule_id: &RuleId) -> RuleActivity {
        RuleActivity::default()
    }

    fn active_rule_count(&self) -> usize {
        0
    }
}

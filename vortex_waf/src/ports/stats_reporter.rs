//! Чтение статистики.
//!
//! ISP: инспекторы пишут (`StatsCollector`, `RuleActivityRecorder`), API читает —
//! это разные трейты, и никто не тянет лишние методы.

use crate::domain::rule_id::RuleId;
use crate::ports::rule_activity::RuleActivity;
use crate::stats::snapshot::StatsSnapshot;

pub trait StatsReporter: Send + Sync {
    fn snapshot(&self) -> StatsSnapshot;

    fn activity(&self, rule_id: &RuleId) -> RuleActivity;

    /// Число правил, сработавших хотя бы раз.
    fn active_rule_count(&self) -> usize;
}

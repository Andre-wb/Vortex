//! Запись событий статистики.

use crate::domain::rule_id::RuleId;

pub trait StatsCollector: Send + Sync {
    fn record_request(&self);

    fn record_blocked_request(&self);

    /// Правило, из-за которого запрос заблокирован (учитывается отдельно от
    /// общего числа совпадений).
    fn record_rule_block(&self, rule_id: &RuleId);

    fn record_ip_block(&self);
}

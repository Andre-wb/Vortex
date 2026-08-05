//! Мгновенный срез счётчиков.

use crate::domain::rule_id::RuleId;
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct StatsSnapshot {
    pub total_requests: u64,
    pub blocked_requests: u64,
    /// Сколько раз каждое правило приводило к блокировке.
    pub rules_triggered: BTreeMap<RuleId, u64>,
    pub ip_blocks: u64,
}

impl StatsSnapshot {
    /// Доля заблокированных запросов в процентах, округлённая до сотых.
    pub fn block_rate(&self) -> f64 {
        if self.total_requests == 0 {
            return 0.0;
        }
        let rate = self.blocked_requests as f64 / self.total_requests as f64 * 100.0;
        (rate * 100.0).round() / 100.0
    }
}

#[cfg(test)]
mod tests {
    use super::StatsSnapshot;

    #[test]
    fn block_rate_is_zero_without_traffic() {
        assert_eq!(StatsSnapshot::default().block_rate(), 0.0);
    }

    #[test]
    fn block_rate_rounds_to_two_decimals() {
        let snapshot = StatsSnapshot {
            total_requests: 3,
            blocked_requests: 1,
            ..Default::default()
        };
        assert_eq!(snapshot.block_rate(), 33.33);
    }
}

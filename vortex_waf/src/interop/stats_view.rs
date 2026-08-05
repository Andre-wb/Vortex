//! Статистика в примитивных типах.

use crate::engine::reporting::WafStatsReport;
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq)]
pub struct StatsView {
    pub total_requests: u64,
    pub blocked_requests: u64,
    pub block_rate: f64,
    pub rules_triggered: BTreeMap<String, u64>,
    pub ip_blocks: u64,
    pub blocked_ips_count: usize,
    pub active_rules: usize,
    pub rules_loaded: usize,
}

impl From<&WafStatsReport> for StatsView {
    fn from(report: &WafStatsReport) -> Self {
        StatsView {
            total_requests: report.total_requests,
            blocked_requests: report.blocked_requests,
            block_rate: report.block_rate,
            rules_triggered: report
                .rules_triggered
                .iter()
                .map(|(id, count)| (id.to_string(), *count))
                .collect(),
            ip_blocks: report.ip_blocks,
            blocked_ips_count: report.blocked_ips_count,
            active_rules: report.active_rules,
            rules_loaded: report.rules_loaded,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::StatsView;
    use crate::engine::reporting::WafStatsReport;
    use std::collections::BTreeMap;

    #[test]
    fn rule_identifiers_become_strings() {
        let mut rules_triggered = BTreeMap::new();
        rules_triggered.insert("SQLI-001".into(), 3);
        let report = WafStatsReport {
            total_requests: 10,
            blocked_requests: 2,
            block_rate: 20.0,
            rules_triggered,
            ip_blocks: 1,
            blocked_ips_count: 1,
            active_rules: 4,
            rules_loaded: 41,
        };
        let view = StatsView::from(&report);
        assert_eq!(view.rules_triggered.get("SQLI-001"), Some(&3));
        assert_eq!(view.block_rate, 20.0);
        assert_eq!(view.active_rules, 4);
        assert_eq!(view.rules_loaded, 41);
    }
}

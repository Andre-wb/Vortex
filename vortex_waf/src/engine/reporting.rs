//! Сводный отчёт о работе WAF.

use crate::domain::rule_id::RuleId;
use crate::engine::runtime::WafRuntime;
use crate::ports::stats_reporter::StatsReporter;
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct WafStatsReport {
    pub total_requests: u64,
    pub blocked_requests: u64,
    pub block_rate: f64,
    pub rules_triggered: BTreeMap<RuleId, u64>,
    pub ip_blocks: u64,
    pub blocked_ips_count: usize,
    pub active_rules: usize,
    pub rules_loaded: usize,
}

pub fn build_report(runtime: &WafRuntime) -> WafStatsReport {
    let snapshot = runtime.stats().snapshot();
    WafStatsReport {
        block_rate: snapshot.block_rate(),
        total_requests: snapshot.total_requests,
        blocked_requests: snapshot.blocked_requests,
        rules_triggered: snapshot.rules_triggered,
        ip_blocks: snapshot.ip_blocks,
        blocked_ips_count: runtime.block_store().len(),
        active_rules: runtime.stats().active_rule_count(),
        rules_loaded: runtime.scanner().rules().len(),
    }
}

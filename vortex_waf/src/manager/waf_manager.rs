//! Управляющие операции над WAF — то, что отдавали эндпоинты `/waf/*`.

use crate::domain::client_ip::ClientIp;
use crate::engine::reporting::{build_report, WafStatsReport};
use crate::engine::runtime::WafRuntime;
use crate::manager::dto::{BlockedIpView, OperationResult, RuleView};
use crate::ports::ip_allow_list::IpAllowList;
use crate::ports::ip_blocker::IpBlocker;
use crate::ports::stats_reporter::StatsReporter;
use std::sync::Arc;

pub struct WafManager {
    runtime: Arc<WafRuntime>,
}

impl WafManager {
    pub fn new(runtime: Arc<WafRuntime>) -> Self {
        WafManager { runtime }
    }

    pub fn block_ip(&self, ip: &str, reason: &str, duration_secs: u64) -> OperationResult {
        let success = self
            .runtime
            .reputation()
            .block(&ClientIp::from(ip), reason, duration_secs);
        OperationResult::new(success, ip)
            .with_reason(reason)
            .with_duration(duration_secs)
    }

    pub fn unblock_ip(&self, ip: &str) -> OperationResult {
        if self.runtime.reputation().unblock(&ClientIp::from(ip)) {
            OperationResult::new(true, ip).with_message("IP unblocked")
        } else {
            OperationResult::new(false, ip).with_message("IP not found")
        }
    }

    pub fn blocked_ips(&self) -> Vec<BlockedIpView> {
        self.runtime
            .block_store()
            .list()
            .into_iter()
            .map(|(ip, record)| BlockedIpView {
                ip: ip.to_string(),
                blocked_at: record.blocked_at.to_rfc3339(),
                blocked_until: record.until.to_rfc3339(),
                reason: record.reason,
                duration: record.duration_secs,
            })
            .collect()
    }

    pub fn add_whitelist_ip(&self, ip: &str) -> OperationResult {
        let candidate = ClientIp::from(ip);
        if !candidate.is_valid_ip() {
            return OperationResult::new(false, ip).with_message("Invalid IP format");
        }
        self.runtime.allow_list().add(candidate);
        OperationResult::new(true, ip).with_message("IP added to whitelist")
    }

    pub fn remove_whitelist_ip(&self, ip: &str) -> OperationResult {
        if self.runtime.allow_list().remove(&ClientIp::from(ip)) {
            OperationResult::new(true, ip).with_message("IP removed from whitelist")
        } else {
            OperationResult::new(false, ip).with_message("IP not found in whitelist")
        }
    }

    pub fn whitelist(&self) -> Vec<String> {
        self.runtime
            .allow_list()
            .list()
            .into_iter()
            .map(|ip| ip.to_string())
            .collect()
    }

    pub fn stats(&self) -> WafStatsReport {
        build_report(&self.runtime)
    }

    /// Все правила вместе с накопленной статистикой срабатываний.
    pub fn rules(&self) -> Vec<RuleView> {
        self.runtime
            .scanner()
            .rules()
            .iter()
            .map(|rule| {
                let meta = rule.meta();
                let activity = self.runtime.stats().activity(&meta.id);
                RuleView {
                    id: meta.id.to_string(),
                    description: meta.description.clone(),
                    severity: meta.severity.to_string(),
                    action: meta.action.to_string(),
                    trigger_count: activity.trigger_count,
                    last_triggered: activity.last_triggered.map(|t| t.to_rfc3339()),
                }
            })
            .collect()
    }
}

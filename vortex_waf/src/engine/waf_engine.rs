//! Движок анализа запросов.
//!
//! Своей логики детектирования не содержит: спрашивает репутацию адреса,
//! ограничитель частоты, инспекторы и политику — всё через порты. Добавление
//! проверки или смена политики его не касаются.

use crate::domain::analysis::Analysis;
use crate::domain::finding::Finding;
use crate::domain::request::InspectedRequest;
use crate::domain::severity::Severity;
use crate::ports::block_policy::BlockPolicy;
use crate::ports::inspector::Inspector;
use crate::ports::ip_gate::IpGate;
use crate::ports::rate_limiter::{RateLimitOutcome, RateLimiter};
use crate::ports::stats_collector::StatsCollector;
use std::sync::Arc;

pub struct WafEngine {
    gate: Arc<dyn IpGate>,
    rate_limiter: Arc<dyn RateLimiter>,
    inspector: Arc<dyn Inspector>,
    policy: Arc<dyn BlockPolicy>,
    stats: Arc<dyn StatsCollector>,
}

impl WafEngine {
    pub fn new(
        gate: Arc<dyn IpGate>,
        rate_limiter: Arc<dyn RateLimiter>,
        inspector: Arc<dyn Inspector>,
        policy: Arc<dyn BlockPolicy>,
        stats: Arc<dyn StatsCollector>,
    ) -> Self {
        WafEngine {
            gate,
            rate_limiter,
            inspector,
            policy,
            stats,
        }
    }

    pub fn analyze(&self, request: &InspectedRequest) -> Analysis {
        let ip = request.client_ip.clone();

        // Ранние отказы: до правил дело не доходит, и в общий счётчик запросов
        // они не попадают — так же вела себя прежняя реализация.
        if self.gate.is_blocked(&ip) {
            return Analysis::blocked(
                ip,
                "IP blocked",
                vec![Finding::new("IP-BLOCKED", Severity::Critical)],
                Vec::new(),
            );
        }

        if let RateLimitOutcome::Exceeded { message } = self.rate_limiter.check(&ip) {
            return Analysis::blocked(
                ip,
                message,
                vec![Finding::new("RATE-LIMIT", Severity::Medium)],
                Vec::new(),
            );
        }

        let findings = self.inspector.inspect(request);
        let decision = self.policy.decide(&findings);

        self.stats.record_request();
        if decision.block {
            self.stats.record_blocked_request();
            for rule_id in &decision.matched_rules {
                self.stats.record_rule_block(rule_id);
            }
            return Analysis::blocked(
                ip,
                "Request blocked by WAF",
                findings,
                decision.matched_rules,
            );
        }

        Analysis::allowed(ip, findings)
    }
}

//! Общая обвязка интеграционных тестов.
//!
//! Модуль компилируется в каждый тестовый бинарник целиком, поэтому часть
//! помощников в конкретном файле остаётся невостребованной.
#![allow(dead_code)]

use std::sync::Arc;
use vortex_waf::config::EngineConfig;
use vortex_waf::engine::WafRuntime;
use vortex_waf::stats::InMemoryStats;
use vortex_waf::time::ManualClock;
use vortex_waf::WafBuilder;

/// Собранный WAF с управляемыми часами.
pub struct Harness {
    pub runtime: Arc<WafRuntime>,
    pub clock: Arc<ManualClock>,
    pub stats: Arc<InMemoryStats>,
}

impl Harness {
    pub fn with_config(config: EngineConfig) -> Harness {
        let clock = Arc::new(ManualClock::at_epoch());
        let stats = Arc::new(InMemoryStats::new());
        let runtime = WafBuilder::new()
            .with_config(config)
            .with_clock(clock.clone())
            .with_stats(stats.clone())
            .build()
            .expect("WAF собрался");
        Harness {
            runtime: Arc::new(runtime),
            clock,
            stats,
        }
    }

    pub fn new() -> Harness {
        // Высокий лимит частоты: он не должен мешать проверкам содержимого.
        Harness::with_config(EngineConfig::default().rate_limit(10_000, 60))
    }
}

impl Default for Harness {
    fn default() -> Self {
        Harness::new()
    }
}

/// Есть ли среди находок правило с таким идентификатором.
pub fn has_rule(analysis: &vortex_waf::domain::Analysis, rule_id: &str) -> bool {
    analysis
        .findings
        .iter()
        .any(|f| f.rule_id.as_str() == rule_id)
}

/// Есть ли находка с идентификатором, начинающимся на указанный префикс.
pub fn has_rule_prefix(analysis: &vortex_waf::domain::Analysis, prefix: &str) -> bool {
    analysis
        .findings
        .iter()
        .any(|f| f.rule_id.as_str().starts_with(prefix))
}

/// Тело multipart с заданными частями (заголовки, содержимое).
pub fn multipart_body(parts: &[(&str, &str)]) -> String {
    let mut out = String::new();
    for (headers, value) in parts {
        out.push_str("------WebKitFormBoundaryTest\r\n");
        out.push_str(headers);
        out.push_str("\r\n\r\n");
        out.push_str(value);
        out.push_str("\r\n");
    }
    out.push_str("------WebKitFormBoundaryTest--\r\n");
    out
}

pub const MULTIPART_CONTENT_TYPE: &str = "multipart/form-data; boundary=----WebKitFormBoundaryTest";

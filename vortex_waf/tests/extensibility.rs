//! Расширение без правки существующего кода — проверка принципов O и L.

mod common;

use common::Harness;
use std::sync::Arc;
use vortex_waf::config::EngineConfig;
use vortex_waf::domain::{Action, Finding, InspectedRequest, RequestBuilder, RuleMeta, Severity};
use vortex_waf::policy::{MonitorOnlyPolicy, SeverityThresholdPolicy};
use vortex_waf::ports::{Inspector, Rule, RuleSource, StatsReporter};
use vortex_waf::rules::{
    CatalogRuleSource, CompositeRuleSource, PatternRule, StaticRuleSource, SubstringMatcher,
};
use vortex_waf::stats::InMemoryStats;
use vortex_waf::time::ManualClock;
use vortex_waf::WafBuilder;

/// Свой инспектор: запрещает обращения к служебному заголовку отладки.
struct DebugHeaderInspector;

impl Inspector for DebugHeaderInspector {
    fn name(&self) -> &'static str {
        "debug-header"
    }

    fn inspect(&self, request: &InspectedRequest) -> Vec<Finding> {
        if request.header("x-debug-mode").is_none() {
            return Vec::new();
        }
        vec![Finding::new("DEBUG-HEADER", Severity::Critical)
            .with_description("Отладочный заголовок в боевом запросе")]
    }
}

fn attack() -> InspectedRequest {
    RequestBuilder::new()
        .client_ip("203.0.113.70")
        .path("/api/search")
        .query("q=1%27+OR+1%3D1+--+")
        .build()
}

#[test]
fn a_new_inspector_plugs_in_without_touching_the_engine() {
    let runtime = WafBuilder::new()
        .with_clock(Arc::new(ManualClock::at_epoch()))
        .with_inspector(Arc::new(DebugHeaderInspector))
        .build()
        .unwrap();

    let request = RequestBuilder::new()
        .client_ip("203.0.113.71")
        .path("/api/ping")
        .header("x-debug-mode", "1")
        .header("user-agent", "Mozilla/5.0")
        .build();

    let analysis = runtime.analyze(&request);
    assert!(analysis.block);
    assert!(analysis
        .findings
        .iter()
        .any(|f| f.rule_id.as_str() == "DEBUG-HEADER"));
}

#[test]
fn monitor_policy_records_findings_without_blocking() {
    let stats = Arc::new(InMemoryStats::new());
    let runtime = WafBuilder::new()
        .with_clock(Arc::new(ManualClock::at_epoch()))
        .with_policy(Arc::new(MonitorOnlyPolicy::new()))
        .with_stats(stats.clone())
        .build()
        .unwrap();

    let analysis = runtime.analyze(&attack());
    assert!(!analysis.block);
    assert!(!analysis.findings.is_empty());
    assert_eq!(stats.snapshot().blocked_requests, 0);
    // Сработавшие правила всё равно учтены.
    assert!(stats.active_rule_count() > 0);
}

#[test]
fn raising_the_threshold_changes_what_blocks() {
    let waf = Harness::with_config(EngineConfig::default().rate_limit(10_000, 60));
    // Штатный порог high: XSS блокируется.
    let xss = RequestBuilder::new()
        .client_ip("203.0.113.72")
        .path("/api/search")
        .query("q=%3Cscript%3Ealert(1)%3C%2Fscript%3E")
        .build();
    assert!(waf.runtime.analyze(&xss).block);

    let strict = WafBuilder::new()
        .with_clock(Arc::new(ManualClock::at_epoch()))
        .with_policy(Arc::new(SeverityThresholdPolicy::new(Severity::Critical)))
        .build()
        .unwrap();
    // При пороге critical находки уровня high уже не блокируют.
    let analysis = strict.analyze(&xss);
    assert!(!analysis.findings.is_empty());
    assert!(!analysis.block);
}

#[test]
fn custom_rules_join_the_catalog() {
    let custom: Arc<dyn Rule> = Arc::new(PatternRule::new(
        RuleMeta::new(
            "CUSTOM-001",
            "Внутренний код проекта",
            Severity::Critical,
            Action::Block,
        ),
        // Матчер без регулярного выражения — тоже полноправная реализация.
        Arc::new(SubstringMatcher::new("VORTEX-SECRET")),
    ));

    let runtime = WafBuilder::new()
        .with_clock(Arc::new(ManualClock::at_epoch()))
        .with_rule_source(Arc::new(CompositeRuleSource::new(vec![
            Arc::new(CatalogRuleSource::new()),
            Arc::new(StaticRuleSource::new(vec![custom])),
        ])))
        .build()
        .unwrap();

    let request = RequestBuilder::new()
        .client_ip("203.0.113.73")
        .path("/api/messages")
        .query("text=vortex-secret")
        .build();

    let analysis = runtime.analyze(&request);
    assert!(analysis.block);
    assert!(analysis
        .findings
        .iter()
        .any(|f| f.rule_id.as_str() == "CUSTOM-001"));
    assert_eq!(runtime.scanner().rules().len(), 75);
}

#[test]
fn an_empty_rule_source_leaves_only_structural_checks() {
    let runtime = WafBuilder::new()
        .with_clock(Arc::new(ManualClock::at_epoch()))
        .with_rule_source(Arc::new(StaticRuleSource::empty()))
        .build()
        .unwrap();

    // Сигнатур нет, но проверка обхода каталогов встроена в инспектор пути.
    let analysis = runtime.analyze(
        &RequestBuilder::new()
            .client_ip("203.0.113.74")
            .path("/files/../../etc/passwd")
            .build(),
    );
    assert!(analysis.block);
    assert!(!CatalogRuleSource::new().rules().unwrap().is_empty());
}

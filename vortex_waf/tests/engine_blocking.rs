//! Сквозные проверки решения о блокировке.

mod common;

use common::{has_rule, has_rule_prefix, Harness};
use vortex_waf::domain::{RequestBuilder, Severity};

#[test]
fn sql_injection_in_a_query_parameter_is_blocked() {
    let waf = Harness::new();
    let request = RequestBuilder::new()
        .client_ip("203.0.113.7")
        .path("/api/search")
        .query("q=1%27+OR+1%3D1+--+")
        .build();

    let analysis = waf.runtime.analyze(&request);
    assert!(analysis.block);
    assert!(has_rule_prefix(&analysis, "SQLI"));
    assert!(!analysis.matched_rules.is_empty());
}

#[test]
fn xss_payload_is_blocked() {
    let waf = Harness::new();
    let request = RequestBuilder::new()
        .client_ip("203.0.113.8")
        .path("/api/messages")
        .query("text=%3Cscript%3Ealert(1)%3C%2Fscript%3E")
        .build();

    assert!(waf.runtime.analyze(&request).block);
}

#[test]
fn ordinary_request_passes() {
    let waf = Harness::new();
    let request = RequestBuilder::new()
        .client_ip("203.0.113.9")
        .path("/api/chat/messages")
        .query("room=general&limit=50")
        .header("user-agent", "Mozilla/5.0")
        .build();

    let analysis = waf.runtime.analyze(&request);
    assert!(!analysis.block, "находки: {:?}", analysis.findings);
}

#[test]
fn csrf_token_does_not_trigger_rules() {
    let waf = Harness::new();
    // Значение намеренно выглядит как SQL-инъекция.
    let request = RequestBuilder::new()
        .client_ip("203.0.113.10")
        .path("/api/messages")
        .query("csrf_token=SELECT+something+FROM+dual")
        .build();

    assert!(!waf.runtime.analyze(&request).block);
}

#[test]
fn low_severity_findings_do_not_block() {
    let waf = Harness::new();
    let request = RequestBuilder::new()
        .client_ip("203.0.113.11")
        .path("/robots.txt")
        .header("user-agent", "ab")
        .build();

    let analysis = waf.runtime.analyze(&request);
    assert!(!analysis.block);
    assert!(has_rule(&analysis, "SUSPICIOUS-UA"));
    assert!(analysis
        .findings
        .iter()
        .all(|f| f.severity < Severity::High));
}

#[test]
fn nonstandard_method_is_reported_but_not_blocked() {
    let waf = Harness::new();
    let request = RequestBuilder::new()
        .client_ip("203.0.113.12")
        .method("TRACE")
        .path("/api/ping")
        .build();

    let analysis = waf.runtime.analyze(&request);
    assert!(has_rule(&analysis, "INVALID-METHOD"));
    assert!(!analysis.block);
}

#[test]
fn javascript_referer_blocks_the_request() {
    let waf = Harness::new();
    let request = RequestBuilder::new()
        .client_ip("203.0.113.13")
        .path("/api/ping")
        .header("referer", "javascript:alert(document.cookie)")
        .build();

    let analysis = waf.runtime.analyze(&request);
    assert!(analysis.block);
    assert!(has_rule(&analysis, "XSS-REFERER"));
}

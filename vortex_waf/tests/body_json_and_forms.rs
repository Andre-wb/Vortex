//! JSON, формы и неизвестные форматы тела.

mod common;

use common::{has_rule, has_rule_prefix, Harness};
use vortex_waf::config::EngineConfig;
use vortex_waf::domain::RequestBuilder;

fn post(content_type: &str, body: &str) -> vortex_waf::domain::InspectedRequest {
    RequestBuilder::new()
        .client_ip("203.0.113.30")
        .method("POST")
        .path("/api/messages")
        .content_type(content_type)
        .body(body)
        .build()
}

#[test]
fn injection_nested_in_json_is_found() {
    let waf = Harness::new();
    let body = r#"{"message": {"parts": [{"text": "1 UNION ALL SELECT * FROM users"}]}}"#;
    let analysis = waf.runtime.analyze(&post("application/json", body));
    assert!(analysis.block);
    assert!(has_rule_prefix(&analysis, "SQLI"));
}

#[test]
fn payload_in_a_json_key_is_found() {
    let waf = Harness::new();
    let body = r#"{"<svg onload=alert(1)>": "значение"}"#;
    assert!(waf.runtime.analyze(&post("application/json", body)).block);
}

#[test]
fn clean_json_passes() {
    let waf = Harness::new();
    let body = r#"{"room": "general", "text": "привет, как дела?", "draft": false}"#;
    let analysis = waf.runtime.analyze(&post("application/json", body));
    assert!(!analysis.block, "находки: {:?}", analysis.findings);
}

#[test]
fn broken_json_is_reported_and_still_scanned() {
    let waf = Harness::new();
    let body = "{это не json, но здесь есть javascript:alert(1)";
    let analysis = waf.runtime.analyze(&post("application/json", body));
    assert!(has_rule(&analysis, "INVALID-JSON"));
    // Разбор не удался, поэтому тело прогоняется правилами целиком.
    assert!(analysis.block);
}

#[test]
fn form_urlencoded_body_is_parsed() {
    let waf = Harness::new();
    let body = "comment=%3Cscript%3Ealert(1)%3C%2Fscript%3E&page=1";
    assert!(
        waf.runtime
            .analyze(&post("application/x-www-form-urlencoded", body))
            .block
    );
}

#[test]
fn unknown_content_type_falls_back_to_a_full_body_scan() {
    let waf = Harness::new();
    let body = "произвольный текст с javascript:alert(1) внутри";
    let analysis = waf.runtime.analyze(&post("text/plain", body));
    assert!(analysis.block);
    assert!(analysis.findings.iter().any(|f| f
        .description
        .as_deref()
        .unwrap_or("")
        .contains("in request body")));
}

#[test]
fn oversized_body_is_blocked() {
    let waf = Harness::with_config(
        EngineConfig::default()
            .rate_limit(10_000, 60)
            .max_content_length(64),
    );
    let analysis = waf.runtime.analyze(&post("text/plain", &"a".repeat(100)));
    assert!(analysis.block);
    assert!(has_rule(&analysis, "LARGE-BODY"));
}

#[test]
fn empty_body_is_not_inspected() {
    let waf = Harness::new();
    let analysis = waf.runtime.analyze(&post("application/json", ""));
    assert!(!analysis.block);
    assert!(!has_rule(&analysis, "INVALID-JSON"));
}

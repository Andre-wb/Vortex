//! Проверки пути запроса.

mod common;

use common::{has_rule, Harness};
use vortex_waf::domain::RequestBuilder;

fn get(path: &str) -> vortex_waf::domain::InspectedRequest {
    RequestBuilder::new()
        .client_ip("203.0.113.40")
        .path(path)
        .build()
}

#[test]
fn traversal_in_the_path_is_blocked() {
    let waf = Harness::new();
    let analysis = waf.runtime.analyze(&get("/static/../../etc/passwd"));
    assert!(analysis.block);
    assert!(has_rule(&analysis, "PATH-TRAVERSAL"));
}

#[test]
fn double_encoded_traversal_is_blocked() {
    let waf = Harness::new();
    assert!(
        waf.runtime
            .analyze(&get("/files/%252e%252e%252fetc%252fpasswd"))
            .block
    );
}

#[test]
fn script_extension_is_reported_at_medium_severity() {
    let waf = Harness::new();
    let analysis = waf.runtime.analyze(&get("/uploads/shell.py"));
    assert!(has_rule(&analysis, "DANGEROUS-EXTENSION"));
    // Уровня medium недостаточно для блокировки.
    assert!(!analysis.block);
}

#[test]
fn long_path_is_reported() {
    let waf = Harness::new();
    let analysis = waf.runtime.analyze(&get(&format!("/{}", "a".repeat(600))));
    assert!(has_rule(&analysis, "LONG-PATH"));
}

#[test]
fn signature_rules_run_against_the_path() {
    let waf = Harness::new();
    let analysis = waf.runtime.analyze(&get("/.git/HEAD"));
    assert!(analysis.findings.iter().any(|f| f
        .description
        .as_deref()
        .unwrap_or("")
        .ends_with("in URL path")));
}

#[test]
fn path_findings_carry_no_value_fragment() {
    let waf = Harness::new();
    let analysis = waf.runtime.analyze(&get("/etc/passwd"));
    let path_findings: Vec<_> = analysis
        .findings
        .iter()
        .filter(|f| {
            f.description
                .as_deref()
                .unwrap_or("")
                .ends_with("in URL path")
        })
        .collect();
    assert!(!path_findings.is_empty());
    assert!(path_findings.iter().all(|f| f.value.is_none()));
}

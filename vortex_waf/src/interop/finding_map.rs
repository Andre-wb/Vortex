//! Находки и вердикт в виде плоских отображений.
//!
//! Ключи совпадают с теми, что отдавал прежний движок, чтобы вызывающая сторона
//! читала результат без переходников.

use crate::domain::analysis::Analysis;
use crate::domain::finding::Finding;
use std::collections::BTreeMap;

pub type FlatMap = BTreeMap<String, String>;

pub fn finding_to_map(finding: &Finding) -> FlatMap {
    let mut map = BTreeMap::new();
    map.insert("rule_id".to_owned(), finding.rule_id.to_string());
    map.insert("severity".to_owned(), finding.severity.as_str().to_owned());
    if let Some(description) = &finding.description {
        map.insert("description".to_owned(), description.clone());
    }
    if let Some(value) = &finding.value {
        map.insert("value".to_owned(), value.clone());
    }
    map
}

pub fn findings_to_maps(findings: &[Finding]) -> Vec<FlatMap> {
    findings.iter().map(finding_to_map).collect()
}

/// Разложенный на примитивы вердикт анализа.
#[derive(Debug, Clone)]
pub struct AnalysisView {
    pub block: bool,
    pub reason: Option<String>,
    pub findings: Vec<FlatMap>,
    pub matched_rules: Vec<String>,
    pub client_ip: String,
}

impl From<&Analysis> for AnalysisView {
    fn from(analysis: &Analysis) -> Self {
        AnalysisView {
            block: analysis.block,
            reason: analysis.reason.clone(),
            findings: findings_to_maps(&analysis.findings),
            matched_rules: analysis
                .matched_rules
                .iter()
                .map(ToString::to_string)
                .collect(),
            client_ip: analysis.client_ip.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{finding_to_map, AnalysisView};
    use crate::domain::analysis::Analysis;
    use crate::domain::client_ip::ClientIp;
    use crate::domain::finding::Finding;
    use crate::domain::severity::Severity;

    #[test]
    fn absent_fields_are_omitted() {
        let map = finding_to_map(&Finding::new("RATE-LIMIT", Severity::Medium));
        assert_eq!(map.get("rule_id").map(String::as_str), Some("RATE-LIMIT"));
        assert_eq!(map.get("severity").map(String::as_str), Some("medium"));
        assert!(!map.contains_key("description"));
        assert!(!map.contains_key("value"));
    }

    #[test]
    fn populated_fields_are_carried_over() {
        let finding = Finding::new("XSS-011", Severity::High)
            .with_description("Script Tag XSS in parameter q")
            .with_value("<script>");
        let map = finding_to_map(&finding);
        assert_eq!(
            map.get("description").map(String::as_str),
            Some("Script Tag XSS in parameter q")
        );
        assert_eq!(map.get("value").map(String::as_str), Some("<script>"));
    }

    #[test]
    fn analysis_view_flattens_the_verdict() {
        let analysis = Analysis::blocked(
            ClientIp::from("1.2.3.4"),
            "Request blocked by WAF",
            vec![Finding::new("SQLI-001", Severity::Critical)],
            vec!["SQLI-001".into()],
        );
        let view = AnalysisView::from(&analysis);
        assert!(view.block);
        assert_eq!(view.reason.as_deref(), Some("Request blocked by WAF"));
        assert_eq!(view.matched_rules, vec!["SQLI-001"]);
        assert_eq!(view.client_ip, "1.2.3.4");
        assert_eq!(view.findings.len(), 1);
    }

    #[test]
    fn allowed_analysis_has_no_reason() {
        let view = AnalysisView::from(&Analysis::allowed(ClientIp::unknown(), Vec::new()));
        assert!(!view.block);
        assert!(view.reason.is_none());
        assert!(view.findings.is_empty());
    }
}

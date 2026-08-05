//! Находка — единица результата анализа.

use crate::domain::rule_id::RuleId;
use crate::domain::severity::Severity;
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    pub rule_id: RuleId,
    pub severity: Severity,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Обрезанный фрагмент значения, вызвавшего срабатывание.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

impl Finding {
    pub fn new(rule_id: impl Into<RuleId>, severity: Severity) -> Self {
        Finding {
            rule_id: rule_id.into(),
            severity,
            description: None,
            value: None,
        }
    }

    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    pub fn with_value(mut self, value: impl Into<String>) -> Self {
        self.value = Some(value.into());
        self
    }

    pub fn is_at_least(&self, threshold: Severity) -> bool {
        self.severity >= threshold
    }
}

#[cfg(test)]
mod tests {
    use super::Finding;
    use crate::domain::severity::Severity;

    #[test]
    fn builder_fills_optional_fields() {
        let f = Finding::new("XSS-011", Severity::High)
            .with_description("Script Tag XSS")
            .with_value("<script>");
        assert_eq!(f.description.as_deref(), Some("Script Tag XSS"));
        assert_eq!(f.value.as_deref(), Some("<script>"));
        assert!(f.is_at_least(Severity::High));
        assert!(!f.is_at_least(Severity::Critical));
    }

    #[test]
    fn empty_optionals_are_skipped_in_json() {
        let json = serde_json::to_string(&Finding::new("RATE-LIMIT", Severity::Medium)).unwrap();
        assert_eq!(json, r#"{"rule_id":"RATE-LIMIT","severity":"medium"}"#);
    }
}

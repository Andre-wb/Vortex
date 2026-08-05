//! Проверка заголовка `Referer`.

use crate::domain::finding::Finding;
use crate::domain::request::InspectedRequest;
use crate::domain::severity::Severity;
use crate::ports::inspector::Inspector;

#[derive(Debug, Clone, Copy, Default)]
pub struct RefererInspector;

impl RefererInspector {
    pub fn new() -> Self {
        RefererInspector
    }
}

impl Inspector for RefererInspector {
    fn name(&self) -> &'static str {
        "referer"
    }

    fn inspect(&self, request: &InspectedRequest) -> Vec<Finding> {
        let Some(value) = request.header("referer") else {
            return Vec::new();
        };
        if !value.to_ascii_lowercase().contains("javascript:") {
            return Vec::new();
        }
        vec![Finding::new("XSS-REFERER", Severity::High).with_description("XSS in Referer header")]
    }
}

#[cfg(test)]
mod tests {
    use super::RefererInspector;
    use crate::domain::request_builder::RequestBuilder;
    use crate::domain::severity::Severity;
    use crate::ports::inspector::Inspector;

    #[test]
    fn javascript_scheme_is_high_severity() {
        let req = RequestBuilder::new()
            .header("referer", "JavaScript:alert(1)")
            .build();
        let findings = RefererInspector::new().inspect(&req);
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn ordinary_referer_passes() {
        let req = RequestBuilder::new()
            .header("referer", "https://example.com/page")
            .build();
        assert!(RefererInspector::new().inspect(&req).is_empty());
    }
}

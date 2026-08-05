//! Проверка HTTP-метода.

use crate::domain::finding::Finding;
use crate::domain::request::InspectedRequest;
use crate::domain::severity::Severity;
use crate::ports::inspector::Inspector;

#[derive(Debug, Clone, Copy, Default)]
pub struct MethodInspector;

impl MethodInspector {
    pub fn new() -> Self {
        MethodInspector
    }
}

impl Inspector for MethodInspector {
    fn name(&self) -> &'static str {
        "method"
    }

    fn inspect(&self, request: &InspectedRequest) -> Vec<Finding> {
        if request.method.is_standard() {
            return Vec::new();
        }
        vec![Finding::new("INVALID-METHOD", Severity::Medium)
            .with_description(format!("Invalid HTTP method: {}", request.method))]
    }
}

#[cfg(test)]
mod tests {
    use super::MethodInspector;
    use crate::domain::request_builder::RequestBuilder;
    use crate::ports::inspector::Inspector;

    #[test]
    fn standard_methods_pass() {
        let req = RequestBuilder::new().method("POST").build();
        assert!(MethodInspector::new().inspect(&req).is_empty());
    }

    #[test]
    fn unknown_method_is_reported() {
        let req = RequestBuilder::new().method("TRACE").build();
        let findings = MethodInspector::new().inspect(&req);
        assert_eq!(findings[0].rule_id.as_str(), "INVALID-METHOD");
        assert_eq!(
            findings[0].description.as_deref(),
            Some("Invalid HTTP method: TRACE")
        );
    }
}

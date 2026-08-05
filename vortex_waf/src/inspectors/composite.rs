//! Композит инспекторов: сам является инспектором.
//!
//! Движок вызывает один `Inspector` и не знает, что внутри их десяток —
//! добавление или снятие проверки не затрагивает его код.

use crate::domain::finding::Finding;
use crate::domain::request::InspectedRequest;
use crate::ports::inspector::Inspector;
use std::sync::Arc;

#[derive(Default)]
pub struct CompositeInspector {
    inspectors: Vec<Arc<dyn Inspector>>,
}

impl CompositeInspector {
    pub fn new() -> Self {
        CompositeInspector::default()
    }

    pub fn with(mut self, inspector: Arc<dyn Inspector>) -> Self {
        self.inspectors.push(inspector);
        self
    }

    pub fn len(&self) -> usize {
        self.inspectors.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inspectors.is_empty()
    }

    pub fn names(&self) -> Vec<&'static str> {
        self.inspectors.iter().map(|i| i.name()).collect()
    }
}

impl Inspector for CompositeInspector {
    fn name(&self) -> &'static str {
        "composite"
    }

    fn inspect(&self, request: &InspectedRequest) -> Vec<Finding> {
        let mut findings = Vec::new();
        for inspector in &self.inspectors {
            findings.extend(inspector.inspect(request));
        }
        findings
    }
}

#[cfg(test)]
mod tests {
    use super::CompositeInspector;
    use crate::domain::request_builder::RequestBuilder;
    use crate::inspectors::method::MethodInspector;
    use crate::inspectors::url_length::UrlLengthInspector;
    use crate::ports::inspector::Inspector;
    use std::sync::Arc;

    #[test]
    fn findings_keep_the_registration_order() {
        let composite = CompositeInspector::new()
            .with(Arc::new(MethodInspector::new()))
            .with(Arc::new(UrlLengthInspector::with_limit(5)));
        let req = RequestBuilder::new()
            .method("TRACE")
            .path("/очень-длинный-путь")
            .build();
        let findings = composite.inspect(&req);
        assert_eq!(findings[0].rule_id.as_str(), "INVALID-METHOD");
        assert_eq!(findings[1].rule_id.as_str(), "LONG-URL");
        assert_eq!(composite.names(), vec!["method", "url-length"]);
    }

    #[test]
    fn empty_composite_finds_nothing() {
        let composite = CompositeInspector::new();
        assert!(composite.is_empty());
        assert!(composite.inspect(&RequestBuilder::new().build()).is_empty());
    }
}

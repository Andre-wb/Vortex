//! Проверка длины URL.

use crate::domain::finding::Finding;
use crate::domain::request::InspectedRequest;
use crate::domain::severity::Severity;
use crate::ports::inspector::Inspector;
use crate::util::truncate::char_len;

pub const DEFAULT_MAX_URL_CHARS: usize = 2048;

#[derive(Debug, Clone, Copy)]
pub struct UrlLengthInspector {
    max_chars: usize,
}

impl Default for UrlLengthInspector {
    fn default() -> Self {
        UrlLengthInspector {
            max_chars: DEFAULT_MAX_URL_CHARS,
        }
    }
}

impl UrlLengthInspector {
    pub fn new() -> Self {
        UrlLengthInspector::default()
    }

    pub fn with_limit(max_chars: usize) -> Self {
        UrlLengthInspector { max_chars }
    }
}

impl Inspector for UrlLengthInspector {
    fn name(&self) -> &'static str {
        "url-length"
    }

    fn inspect(&self, request: &InspectedRequest) -> Vec<Finding> {
        let length = char_len(&request.url);
        if length <= self.max_chars {
            return Vec::new();
        }
        vec![Finding::new("LONG-URL", Severity::Low)
            .with_description(format!("URL too long: {length} characters"))]
    }
}

#[cfg(test)]
mod tests {
    use super::UrlLengthInspector;
    use crate::domain::request_builder::RequestBuilder;
    use crate::ports::inspector::Inspector;

    #[test]
    fn long_url_is_reported_as_low_severity() {
        let req = RequestBuilder::new().path("/".repeat(3000)).build();
        let findings = UrlLengthInspector::new().inspect(&req);
        assert_eq!(findings[0].rule_id.as_str(), "LONG-URL");
    }

    #[test]
    fn limit_is_inclusive() {
        let req = RequestBuilder::new().path("x".repeat(10)).build();
        assert!(UrlLengthInspector::with_limit(10).inspect(&req).is_empty());
        assert!(!UrlLengthInspector::with_limit(9).inspect(&req).is_empty());
    }
}

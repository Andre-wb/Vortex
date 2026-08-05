//! Обход каталогов в пути запроса.

use crate::domain::finding::Finding;
use crate::domain::request::InspectedRequest;
use crate::domain::severity::Severity;
use crate::ports::inspector::Inspector;
use crate::util::percent_decode::decode_twice;

#[derive(Debug, Clone, Copy, Default)]
pub struct PathTraversalInspector;

impl PathTraversalInspector {
    pub fn new() -> Self {
        PathTraversalInspector
    }
}

impl Inspector for PathTraversalInspector {
    fn name(&self) -> &'static str {
        "path-traversal"
    }

    fn inspect(&self, request: &InspectedRequest) -> Vec<Finding> {
        // В пути (в отличие от тела формы) любые две точки подряд — уже повод
        // для блокировки: легитимных имён с ".." в маршрутах нет.
        if !decode_twice(&request.path).contains("..") {
            return Vec::new();
        }
        vec![Finding::new("PATH-TRAVERSAL", Severity::High)
            .with_description("Directory traversal attempt in path")]
    }
}

#[cfg(test)]
mod tests {
    use super::PathTraversalInspector;
    use crate::domain::request_builder::RequestBuilder;
    use crate::ports::inspector::Inspector;

    #[test]
    fn detects_plain_and_encoded_traversal() {
        for path in ["/files/../../etc/passwd", "/files/%252e%252e%252fetc"] {
            let req = RequestBuilder::new().path(path).build();
            assert_eq!(
                PathTraversalInspector::new().inspect(&req).len(),
                1,
                "{path}"
            );
        }
    }

    #[test]
    fn clean_path_passes() {
        let req = RequestBuilder::new().path("/api/chat/messages").build();
        assert!(PathTraversalInspector::new().inspect(&req).is_empty());
    }
}

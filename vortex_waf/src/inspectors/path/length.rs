//! Длина пути запроса.

use crate::domain::finding::Finding;
use crate::domain::request::InspectedRequest;
use crate::domain::severity::Severity;
use crate::ports::inspector::Inspector;
use crate::util::truncate::char_len;

pub const DEFAULT_MAX_PATH_CHARS: usize = 500;

#[derive(Debug, Clone, Copy)]
pub struct PathLengthInspector {
    max_chars: usize,
}

impl Default for PathLengthInspector {
    fn default() -> Self {
        PathLengthInspector {
            max_chars: DEFAULT_MAX_PATH_CHARS,
        }
    }
}

impl PathLengthInspector {
    pub fn new() -> Self {
        PathLengthInspector::default()
    }

    pub fn with_limit(max_chars: usize) -> Self {
        PathLengthInspector { max_chars }
    }
}

impl Inspector for PathLengthInspector {
    fn name(&self) -> &'static str {
        "path-length"
    }

    fn inspect(&self, request: &InspectedRequest) -> Vec<Finding> {
        let length = char_len(&request.path);
        if length <= self.max_chars {
            return Vec::new();
        }
        vec![Finding::new("LONG-PATH", Severity::Low)
            .with_description(format!("Path too long: {length} characters"))]
    }
}

#[cfg(test)]
mod tests {
    use super::PathLengthInspector;
    use crate::domain::request_builder::RequestBuilder;
    use crate::ports::inspector::Inspector;

    #[test]
    fn long_path_is_reported() {
        let req = RequestBuilder::new().path("a".repeat(600)).build();
        assert_eq!(
            PathLengthInspector::new().inspect(&req)[0].rule_id.as_str(),
            "LONG-PATH"
        );
    }
}

//! Разбор `application/json`.

use crate::body::json_walk;
use crate::domain::content_type::ContentType;
use crate::domain::finding::Finding;
use crate::domain::severity::Severity;
use crate::ports::body_parser::{BodyParser, ParseOutcome};

#[derive(Debug, Clone, Copy, Default)]
pub struct JsonBodyParser;

impl JsonBodyParser {
    pub fn new() -> Self {
        JsonBodyParser
    }
}

impl BodyParser for JsonBodyParser {
    fn name(&self) -> &'static str {
        "json"
    }

    fn supports(&self, content_type: &ContentType) -> bool {
        content_type.is_json()
    }

    fn parse(&self, body: &str) -> ParseOutcome {
        match serde_json::from_str(body) {
            Ok(value) => ParseOutcome::consumed(json_walk::flatten(&value), Vec::new()),
            // Тело не разобрано: помимо находки запускается сплошной скан.
            Err(_) => ParseOutcome::rejected(vec![Finding::new("INVALID-JSON", Severity::Medium)
                .with_description("Invalid JSON in request body")]),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::JsonBodyParser;
    use crate::domain::content_type::ContentType;
    use crate::ports::body_parser::BodyParser;

    #[test]
    fn valid_json_is_consumed() {
        let outcome = JsonBodyParser::new().parse(r#"{"q": "hello"}"#);
        assert!(outcome.consumed);
        assert!(outcome.findings.is_empty());
        assert_eq!(outcome.fields.len(), 2); // ключ + значение
    }

    #[test]
    fn broken_json_reports_and_falls_through() {
        let outcome = JsonBodyParser::new().parse("{не json");
        assert!(!outcome.consumed);
        assert_eq!(outcome.findings[0].rule_id.as_str(), "INVALID-JSON");
    }

    #[test]
    fn supports_only_json_content_type() {
        let parser = JsonBodyParser::new();
        assert!(parser.supports(&ContentType::from("application/json; charset=utf-8")));
        assert!(!parser.supports(&ContentType::from("text/plain")));
    }
}

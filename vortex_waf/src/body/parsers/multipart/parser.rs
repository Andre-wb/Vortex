//! Разбор `multipart/form-data`.
//!
//! Собирает воедино три независимые проверки: обход каталогов, опасные загрузки
//! и выделение текстовых полей под общий прогон правил.

use crate::body::parsers::multipart::{splitter, traversal, webshell};
use crate::domain::content_type::ContentType;
use crate::ports::body_parser::{BodyParser, ParseOutcome};
use crate::util::percent_decode::decode_twice;

#[derive(Debug, Clone, Copy, Default)]
pub struct MultipartParser;

impl MultipartParser {
    pub fn new() -> Self {
        MultipartParser
    }
}

impl BodyParser for MultipartParser {
    fn name(&self) -> &'static str {
        "multipart"
    }

    fn supports(&self, content_type: &ContentType) -> bool {
        content_type.is_multipart()
    }

    fn parse(&self, body: &str) -> ParseOutcome {
        let decoded = decode_twice(body);
        let mut findings = Vec::new();

        if let Some(finding) = traversal::detect(&decoded) {
            findings.push(finding);
        }
        findings.extend(webshell::detect_in_filenames(&decoded));

        // Текстовые поля берём из исходного тела: структура multipart в
        // раскодированном виде может поехать.
        let fields = splitter::text_fields(body);
        findings.extend(webshell::detect_in_text_fields(&fields));

        ParseOutcome::consumed(fields, findings)
    }
}

#[cfg(test)]
mod tests {
    use super::MultipartParser;
    use crate::domain::content_type::ContentType;
    use crate::ports::body_parser::BodyParser;

    fn body(headers: &str, value: &str) -> String {
        format!("------x\r\n{headers}\r\n\r\n{value}\r\n------x--\r\n")
    }

    #[test]
    fn reports_traversal_and_keeps_parsing() {
        let raw = body(
            r#"Content-Disposition: form-data; name="comment""#,
            "../../etc/passwd",
        );
        let outcome = MultipartParser::new().parse(&raw);
        assert!(outcome.consumed);
        assert!(outcome
            .findings
            .iter()
            .any(|f| f.rule_id.as_str() == "PATH-TRAVERSAL"));
        assert_eq!(outcome.fields.len(), 1);
    }

    #[test]
    fn catches_webshell_in_the_file_name_field() {
        let raw = body(
            r#"Content-Disposition: form-data; name="file_name""#,
            "shell.php",
        );
        let outcome = MultipartParser::new().parse(&raw);
        assert!(outcome
            .findings
            .iter()
            .any(|f| f.rule_id.as_str() == "DANGEROUS-UPLOAD"));
    }

    #[test]
    fn supports_only_multipart() {
        assert!(
            MultipartParser::new().supports(&ContentType::from("multipart/form-data; boundary=x"))
        );
        assert!(!MultipartParser::new().supports(&ContentType::from("application/json")));
    }
}

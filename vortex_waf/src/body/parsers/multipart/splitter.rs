//! Выделение текстовых частей multipart-тела.
//!
//! Части с `filename=` пропускаются: там лежат байты загружаемого файла, и
//! сигнатуры на них дают ложные срабатывания.

use crate::domain::body_field::BodyField;
use regex::Regex;
use std::sync::OnceLock;

fn name_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?i)name="?([^";\r\n]+)"?"#).expect("регулярное выражение имени части")
    })
}

/// Текстовые поля multipart-тела в порядке следования.
pub fn text_fields(body: &str) -> Vec<BodyField> {
    let stripped = body.trim_start();
    if !stripped.starts_with("--") {
        return Vec::new();
    }
    // Разделитель восстанавливается из первой строки — вместе с ведущими "--".
    let delimiter = stripped.split('\n').next().unwrap_or("").trim();
    if delimiter.is_empty() {
        return Vec::new();
    }

    let mut fields = Vec::new();
    for part in body.split(delimiter) {
        let trimmed = part.trim_matches(|c| c == '\r' || c == '\n');
        if trimmed.is_empty() || trimmed == "--" {
            continue;
        }
        let (headers, value) = match split_headers(part) {
            Some(pair) => pair,
            None => continue,
        };
        if headers.to_ascii_lowercase().contains("filename=") {
            continue;
        }
        let name = name_regex()
            .captures(headers)
            .map(|c| c[1].to_owned())
            .unwrap_or_else(|| "field".to_owned());
        let value = value
            .trim_matches(|c| c == '\r' || c == '\n')
            .trim_end_matches('-')
            .trim_matches(|c| c == '\r' || c == '\n');
        fields.push(BodyField::new(name, value));
    }
    fields
}

/// Заголовки части и её содержимое, разделённые пустой строкой.
fn split_headers(part: &str) -> Option<(&str, &str)> {
    if let Some((headers, value)) = part.split_once("\r\n\r\n") {
        return Some((headers, value));
    }
    part.split_once("\n\n")
}

#[cfg(test)]
mod tests {
    use super::text_fields;

    const BOUNDARY: &str = "------x";

    fn multipart(parts: &[(&str, &str)]) -> String {
        let mut out = String::new();
        for (headers, value) in parts {
            out.push_str(BOUNDARY);
            out.push_str("\r\n");
            out.push_str(headers);
            out.push_str("\r\n\r\n");
            out.push_str(value);
            out.push_str("\r\n");
        }
        out.push_str(BOUNDARY);
        out.push_str("--\r\n");
        out
    }

    #[test]
    fn extracts_named_text_fields() {
        let body = multipart(&[
            (
                r#"Content-Disposition: form-data; name="comment""#,
                "привет",
            ),
            (r#"Content-Disposition: form-data; name="page""#, "2"),
        ]);
        let fields = text_fields(&body);
        assert_eq!(fields.len(), 2);
        assert_eq!(fields[0].name, "comment");
        assert_eq!(fields[0].value, "привет");
        assert_eq!(fields[1].name, "page");
    }

    #[test]
    fn skips_file_parts() {
        let body = multipart(&[
            (
                r#"Content-Disposition: form-data; name="upload"; filename="a.bin""#,
                "\u{0}\u{1}бинарь",
            ),
            (r#"Content-Disposition: form-data; name="title""#, "отчёт"),
        ]);
        let fields = text_fields(&body);
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].name, "title");
    }

    #[test]
    fn non_multipart_body_yields_nothing() {
        assert!(text_fields("обычный текст").is_empty());
        assert!(text_fields("").is_empty());
    }

    #[test]
    fn part_without_a_name_falls_back_to_field() {
        let body = multipart(&[("Content-Disposition: form-data", "значение")]);
        let fields = text_fields(&body);
        assert_eq!(fields[0].name, "field");
    }
}

//! Поиск обхода каталогов в multipart-теле.
//!
//! Голая последовательность `..` не считается атакой: `file..ext` в имени и
//! многоточие в тексте сообщения — обычное дело. Ищем только реальные
//! конструкции обхода.

use crate::domain::finding::Finding;
use crate::domain::severity::Severity;
use regex::Regex;
use std::sync::OnceLock;

fn traversal_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(concat!(
            r#"(?i)"#,
            r#"(?:filename\s*=\s*["']?[^"']*(?:\.\./|\.\.\\))"#, // ../ в filename
            r#"|(?:name\s*=\s*["']?[^"']*(?:\.\./|\.\.\\))"#,    // ../ в имени поля
            r#"|(?:\.\./\.\./)"#,                                // двойной обход
            r#"|(?:\.\.[\\/](?:etc|proc|windows|usr|var|tmp|boot))"#, // обход к системным каталогам
        ))
        .expect("регулярное выражение обхода каталогов")
    })
}

/// Находка, если в уже раскодированном теле есть обход каталогов.
pub fn detect(decoded_body: &str) -> Option<Finding> {
    if traversal_regex().is_match(decoded_body) {
        return Some(
            Finding::new("PATH-TRAVERSAL", Severity::High)
                .with_description("Directory traversal attempt in multipart form data"),
        );
    }
    None
}

#[cfg(test)]
mod tests {
    use super::detect;

    #[test]
    fn flags_traversal_in_filename() {
        assert!(detect(r#"Content-Disposition: form-data; filename="../../etc/passwd""#).is_some());
    }

    #[test]
    fn flags_traversal_to_system_directories() {
        assert!(detect("../etc/shadow").is_some());
        assert!(detect(r"..\windows\win.ini").is_some());
    }

    #[test]
    fn ignores_harmless_double_dots() {
        assert!(detect("файл называется report..txt").is_none());
        assert!(detect("ну и что дальше...").is_none());
    }
}

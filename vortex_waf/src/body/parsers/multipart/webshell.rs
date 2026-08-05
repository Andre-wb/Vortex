//! Поиск загрузок, способных исполниться на сервере.
//!
//! Блокируются только расширения, исполняемые веб-сервером. Исходники `.py`,
//! `.sh`, `.pl` — законное вложение в мессенджере, и точка загрузки всё равно
//! проверяет MIME и переименовывает файл при сохранении.

use crate::domain::body_field::BodyField;
use crate::domain::finding::Finding;
use crate::domain::severity::Severity;
use crate::util::percent_decode::decode;
use regex::Regex;
use std::sync::OnceLock;

pub const WEBSHELL_EXTENSIONS: &[&str] = &[".php", ".asp", ".aspx", ".jsp", ".exe", ".bat", ".cmd"];

/// Имя текстового поля, в котором точка возобновляемой загрузки передаёт
/// исходное имя файла — токена `filename=` там нет.
pub const FILE_NAME_FIELD: &str = "file_name";

fn filename_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?i)filename\s*=\s*["']?([^"';\r\n]+)"#)
            .expect("регулярное выражение filename")
    })
}

/// Первое опасное расширение, которым оканчивается имя.
fn dangerous_extension(name: &str) -> Option<&'static str> {
    let lowered = name.trim().to_ascii_lowercase();
    WEBSHELL_EXTENSIONS
        .iter()
        .find(|ext| lowered.ends_with(**ext))
        .copied()
}

/// Проверка токенов `filename=` в раскодированном теле.
pub fn detect_in_filenames(decoded_body: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    for capture in filename_regex().captures_iter(decoded_body) {
        if let Some(ext) = dangerous_extension(&capture[1]) {
            findings.push(
                Finding::new("DANGEROUS-UPLOAD", Severity::High).with_description(format!(
                    "Dangerous file extension {ext} in multipart upload"
                )),
            );
        }
    }
    findings
}

/// Проверка текстового поля `file_name`.
pub fn detect_in_text_fields(fields: &[BodyField]) -> Vec<Finding> {
    let mut findings = Vec::new();
    for field in fields {
        if !field.name.trim().eq_ignore_ascii_case(FILE_NAME_FIELD) {
            continue;
        }
        if let Some(ext) = dangerous_extension(&decode(&field.value)) {
            findings.push(
                Finding::new("DANGEROUS-UPLOAD", Severity::High).with_description(format!(
                    "Dangerous file extension {ext} in file_name form field"
                )),
            );
        }
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::{detect_in_filenames, detect_in_text_fields};
    use crate::domain::body_field::BodyField;

    #[test]
    fn flags_executable_upload() {
        let findings = detect_in_filenames(r#"filename="shell.php""#);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id.as_str(), "DANGEROUS-UPLOAD");
    }

    #[test]
    fn allows_source_files_and_documents() {
        assert!(detect_in_filenames(r#"filename="script.py""#).is_empty());
        assert!(detect_in_filenames(r#"filename="notes.sh""#).is_empty());
        assert!(detect_in_filenames(r#"filename="отчёт.pdf""#).is_empty());
    }

    #[test]
    fn checks_the_file_name_text_field() {
        let fields = vec![BodyField::new("file_name", "payload.PHP")];
        assert_eq!(detect_in_text_fields(&fields).len(), 1);
    }

    #[test]
    fn decodes_the_file_name_field_before_checking() {
        let fields = vec![BodyField::new("file_name", "payload%2Ephp")];
        assert_eq!(detect_in_text_fields(&fields).len(), 1);
    }

    #[test]
    fn other_text_fields_are_not_checked() {
        let fields = vec![BodyField::new("comment", "смотри shell.php")];
        assert!(detect_in_text_fields(&fields).is_empty());
    }
}

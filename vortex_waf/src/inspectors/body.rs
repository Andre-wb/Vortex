//! Проверка тела запроса.
//!
//! Сам не разбирает форматы: подбирает разборщик в реестре, а его поля
//! отправляет в общий сканер. Если формат неизвестен или разбор не удался —
//! сплошной прогон правил по всему телу.

use crate::body::registry::ParserRegistry;
use crate::domain::finding::Finding;
use crate::domain::request::InspectedRequest;
use crate::domain::severity::Severity;
use crate::ports::inspector::Inspector;
use crate::scanning::field_scanner::FieldScanner;
use crate::util::truncate::char_len;
use std::sync::Arc;

pub struct BodyInspector {
    registry: ParserRegistry,
    scanner: Arc<FieldScanner>,
    max_content_chars: usize,
}

impl BodyInspector {
    pub fn new(
        registry: ParserRegistry,
        scanner: Arc<FieldScanner>,
        max_content_chars: usize,
    ) -> Self {
        BodyInspector {
            registry,
            scanner,
            max_content_chars,
        }
    }
}

impl Inspector for BodyInspector {
    fn name(&self) -> &'static str {
        "body"
    }

    fn inspect(&self, request: &InspectedRequest) -> Vec<Finding> {
        if !request.has_body() {
            return Vec::new();
        }

        let length = char_len(&request.body);
        if length > self.max_content_chars {
            // Уровень high => запрос блокируется. Транспортный слой уже
            // ограничивает абсолютный размер кодом 413; эта проверка ловит
            // случаи, когда объявленный content-type не совпал с реальностью.
            return vec![Finding::new("LARGE-BODY", Severity::High)
                .with_description(format!("Request body too large: {length} bytes"))];
        }

        let mut findings = Vec::new();
        let mut consumed = false;

        if let Some(parser) = self.registry.find(&request.content_type) {
            let outcome = parser.parse(&request.body);
            findings.extend(outcome.findings);
            for field in &outcome.fields {
                findings.extend(self.scanner.scan_parameter(&field.name, &field.value));
            }
            consumed = outcome.consumed;
        }

        if !consumed {
            findings.extend(self.scanner.scan_text(&request.body, "request body", true));
        }
        findings
    }
}

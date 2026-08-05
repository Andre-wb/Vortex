//! Реестр разборщиков тела.
//!
//! Заменяет цепочку `if content_type == … elif …`: подбор идёт опросом
//! реализаций, добавление формата не требует правок здесь.

use crate::domain::content_type::ContentType;
use crate::ports::body_parser::BodyParser;
use std::sync::Arc;

#[derive(Default)]
pub struct ParserRegistry {
    parsers: Vec<Arc<dyn BodyParser>>,
}

impl ParserRegistry {
    pub fn new() -> Self {
        ParserRegistry::default()
    }

    pub fn with(mut self, parser: Arc<dyn BodyParser>) -> Self {
        self.parsers.push(parser);
        self
    }

    /// Первый подходящий разборщик.
    pub fn find(&self, content_type: &ContentType) -> Option<&Arc<dyn BodyParser>> {
        self.parsers.iter().find(|p| p.supports(content_type))
    }

    pub fn len(&self) -> usize {
        self.parsers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.parsers.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::ParserRegistry;
    use crate::body::parsers::{FormUrlEncodedParser, JsonBodyParser, MultipartParser};
    use crate::domain::content_type::ContentType;
    use std::sync::Arc;

    fn registry() -> ParserRegistry {
        ParserRegistry::new()
            .with(Arc::new(MultipartParser::new()))
            .with(Arc::new(JsonBodyParser::new()))
            .with(Arc::new(FormUrlEncodedParser::new()))
    }

    #[test]
    fn picks_the_parser_by_content_type() {
        let registry = registry();
        assert_eq!(
            registry
                .find(&ContentType::from("application/json"))
                .map(|p| p.name()),
            Some("json")
        );
        assert_eq!(
            registry
                .find(&ContentType::from("multipart/form-data; boundary=x"))
                .map(|p| p.name()),
            Some("multipart")
        );
        assert_eq!(registry.len(), 3);
    }

    #[test]
    fn unknown_content_type_has_no_parser() {
        assert!(registry().find(&ContentType::from("text/plain")).is_none());
    }
}

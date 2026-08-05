//! Разбор `application/x-www-form-urlencoded`.

use crate::domain::body_field::BodyField;
use crate::domain::content_type::ContentType;
use crate::ports::body_parser::{BodyParser, ParseOutcome};
use crate::util::query::parse_qs;

#[derive(Debug, Clone, Copy, Default)]
pub struct FormUrlEncodedParser;

impl FormUrlEncodedParser {
    pub fn new() -> Self {
        FormUrlEncodedParser
    }
}

impl BodyParser for FormUrlEncodedParser {
    fn name(&self) -> &'static str {
        "form-urlencoded"
    }

    fn supports(&self, content_type: &ContentType) -> bool {
        content_type.is_form_urlencoded()
    }

    fn parse(&self, body: &str) -> ParseOutcome {
        let params = parse_qs(body);
        let fields = params
            .flat_iter()
            .map(|(name, value)| BodyField::new(name, value))
            .collect();
        ParseOutcome::consumed(fields, Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use super::FormUrlEncodedParser;
    use crate::ports::body_parser::BodyParser;

    #[test]
    fn splits_and_decodes_pairs() {
        let outcome = FormUrlEncodedParser::new().parse("q=%3Cscript%3E&page=2");
        assert!(outcome.consumed);
        let values: Vec<&str> = outcome.fields.iter().map(|f| f.value.as_str()).collect();
        assert!(values.contains(&"<script>"));
        assert!(values.contains(&"2"));
    }
}

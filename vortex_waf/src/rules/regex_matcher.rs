//! Матчер на регулярном выражении.

use crate::ports::matcher::Matcher;
use crate::util::truncate::take_chars;
use regex::{Regex, RegexBuilder};

/// Ограничение длины входа перед сопоставлением.
///
/// В Rust движок регулярных выражений не откатывается, так что защита от ReDoS
/// здесь не нужна. Ограничение сохранено ради совпадения поведения с прежней
/// реализацией: совпадение за пределами первых 4096 символов не считается
/// сработавшим ни там, ни здесь.
pub const MAX_INPUT_CHARS: usize = 4096;

#[derive(Debug, Clone)]
pub struct RegexMatcher {
    regex: Regex,
    max_input_chars: usize,
}

impl RegexMatcher {
    /// Компилирует выражение без учёта регистра.
    pub fn compile(pattern: &str) -> Result<Self, regex::Error> {
        Ok(RegexMatcher {
            regex: RegexBuilder::new(pattern).case_insensitive(true).build()?,
            max_input_chars: MAX_INPUT_CHARS,
        })
    }

    pub fn with_max_input_chars(mut self, max: usize) -> Self {
        self.max_input_chars = max;
        self
    }

    pub fn as_str(&self) -> &str {
        self.regex.as_str()
    }
}

impl Matcher for RegexMatcher {
    fn is_match(&self, input: &str) -> bool {
        self.regex.is_match(take_chars(input, self.max_input_chars))
    }
}

#[cfg(test)]
mod tests {
    use super::{RegexMatcher, MAX_INPUT_CHARS};
    use crate::ports::matcher::Matcher;

    #[test]
    fn matching_ignores_case() {
        let m = RegexMatcher::compile(r"select").unwrap();
        assert!(m.is_match("SeLeCt 1"));
    }

    #[test]
    fn input_beyond_the_cap_is_not_examined() {
        let m = RegexMatcher::compile(r"needle").unwrap();
        let payload = format!("{}needle", "x".repeat(MAX_INPUT_CHARS));
        assert!(!m.is_match(&payload));
        assert!(m.is_match(&format!("{}needle", "x".repeat(10))));
    }

    #[test]
    fn broken_pattern_reports_an_error() {
        assert!(RegexMatcher::compile(r"(unclosed").is_err());
    }
}

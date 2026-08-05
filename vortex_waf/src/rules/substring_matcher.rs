//! Матчер по подстроке — без регулярных выражений.
//!
//! Существует, чтобы показать: новый способ сопоставления добавляется отдельным
//! файлом, а `PatternRule`, реестр и движок при этом не меняются (OCP).

use crate::ports::matcher::Matcher;

#[derive(Debug, Clone)]
pub struct SubstringMatcher {
    needle: String,
    case_sensitive: bool,
}

impl SubstringMatcher {
    pub fn new(needle: impl Into<String>) -> Self {
        SubstringMatcher {
            needle: needle.into(),
            case_sensitive: false,
        }
    }

    pub fn case_sensitive(mut self) -> Self {
        self.case_sensitive = true;
        self
    }
}

impl Matcher for SubstringMatcher {
    fn is_match(&self, input: &str) -> bool {
        if self.case_sensitive {
            input.contains(&self.needle)
        } else {
            input
                .to_ascii_lowercase()
                .contains(&self.needle.to_ascii_lowercase())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::SubstringMatcher;
    use crate::ports::matcher::Matcher;

    #[test]
    fn case_insensitive_by_default() {
        assert!(SubstringMatcher::new("DROP").is_match("drop table"));
        assert!(!SubstringMatcher::new("DROP")
            .case_sensitive()
            .is_match("drop table"));
    }
}

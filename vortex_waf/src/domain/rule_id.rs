//! Идентификатор правила (`SQLI-001`, `PATH-TRAVERSAL`, …).

use serde::Serialize;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct RuleId(String);

impl RuleId {
    pub fn new(value: impl Into<String>) -> Self {
        RuleId(value.into())
    }

    /// Составной идентификатор из префикса категории и порядкового номера.
    pub fn numbered(prefix: &str, number: usize) -> Self {
        RuleId(format!("{prefix}-{number:03}"))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RuleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<&str> for RuleId {
    fn from(value: &str) -> Self {
        RuleId(value.to_owned())
    }
}

impl From<String> for RuleId {
    fn from(value: String) -> Self {
        RuleId(value)
    }
}

#[cfg(test)]
mod tests {
    use super::RuleId;

    #[test]
    fn numbered_pads_to_three_digits() {
        assert_eq!(RuleId::numbered("SQLI", 7).as_str(), "SQLI-007");
        assert_eq!(RuleId::numbered("XSS", 123).as_str(), "XSS-123");
    }
}

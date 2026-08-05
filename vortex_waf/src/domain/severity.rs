//! Уровень опасности находки.

use serde::Serialize;
use std::fmt;

/// Порядок вариантов задаёт отношение «строже чем» через `PartialOrd`:
/// `Severity::High >= Severity::Medium`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }

    /// Разбор из строкового представления, совместимого с прежним Python-кодом.
    pub fn parse(raw: &str) -> Option<Severity> {
        match raw.to_ascii_lowercase().as_str() {
            "low" => Some(Severity::Low),
            "medium" => Some(Severity::Medium),
            "high" => Some(Severity::High),
            "critical" => Some(Severity::Critical),
            _ => None,
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::Severity;

    #[test]
    fn ordering_follows_strictness() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
    }

    #[test]
    fn parses_known_names() {
        assert_eq!(Severity::parse("HIGH"), Some(Severity::High));
        assert_eq!(Severity::parse("nope"), None);
    }
}

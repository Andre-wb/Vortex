//! Ошибки уровня крейта.

use std::fmt;

#[derive(Debug)]
pub enum WafError {
    /// Паттерн правила не компилируется.
    RuleCompile {
        rule_id: String,
        pattern: String,
        source: String,
    },
    /// Некорректная конфигурация (диапазоны, пустые обязательные поля).
    Config(String),
}

impl fmt::Display for WafError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WafError::RuleCompile {
                rule_id,
                pattern,
                source,
            } => write!(
                f,
                "не удалось скомпилировать правило {rule_id} ({pattern}): {source}"
            ),
            WafError::Config(msg) => write!(f, "некорректная конфигурация: {msg}"),
        }
    }
}

impl std::error::Error for WafError {}

pub type Result<T> = std::result::Result<T, WafError>;

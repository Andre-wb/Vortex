//! Паспорт правила: идентификатор, описание, серьёзность, действие.
//!
//! Отделён от предиката сопоставления (`ports::matcher::Matcher`), поэтому
//! метаданные можно читать, не зная, как именно правило ищет совпадение.

use crate::domain::action::Action;
use crate::domain::rule_id::RuleId;
use crate::domain::severity::Severity;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleMeta {
    pub id: RuleId,
    pub description: String,
    pub severity: Severity,
    pub action: Action,
}

impl RuleMeta {
    pub fn new(
        id: impl Into<RuleId>,
        description: impl Into<String>,
        severity: Severity,
        action: Action,
    ) -> Self {
        RuleMeta {
            id: id.into(),
            description: description.into(),
            severity,
            action,
        }
    }
}

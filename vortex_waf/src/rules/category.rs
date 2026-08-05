//! Описание категории правил: префикс, серьёзность, действие, таблица паттернов.

use crate::domain::action::Action;
use crate::domain::severity::Severity;

#[derive(Debug, Clone, Copy)]
pub struct RuleCategory {
    pub prefix: &'static str,
    pub severity: Severity,
    pub action: Action,
    pub patterns: &'static [(&'static str, &'static str)],
}

impl RuleCategory {
    pub const fn new(
        prefix: &'static str,
        severity: Severity,
        action: Action,
        patterns: &'static [(&'static str, &'static str)],
    ) -> Self {
        RuleCategory {
            prefix,
            severity,
            action,
            patterns,
        }
    }

    pub fn len(&self) -> usize {
        self.patterns.len()
    }

    pub fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }
}

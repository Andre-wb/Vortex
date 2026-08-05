//! Решение политики блокировки по набору находок.

use crate::domain::rule_id::RuleId;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Decision {
    pub block: bool,
    /// Идентификаторы правил, вызвавших блокировку; повторы сохраняются —
    /// на них опирается подсчёт статистики.
    pub matched_rules: Vec<RuleId>,
}

impl Decision {
    pub fn allow() -> Self {
        Decision {
            block: false,
            matched_rules: Vec::new(),
        }
    }

    pub fn block(matched_rules: Vec<RuleId>) -> Self {
        Decision {
            block: true,
            matched_rules,
        }
    }
}

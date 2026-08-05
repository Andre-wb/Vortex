//! Штатный каталог категорий.
//!
//! Порядок и присвоенные уровни опасности совпадают с прежней таблицей
//! `WAFSignature.get_all_rules`, поэтому идентификаторы правил остались теми же.

use crate::domain::action::Action;
use crate::domain::severity::Severity;
use crate::rules::category::RuleCategory;
use crate::rules::patterns;

pub const CATEGORIES: &[RuleCategory] = &[
    RuleCategory::new(
        "SQLI",
        Severity::Critical,
        Action::Block,
        patterns::sql_injection::PATTERNS,
    ),
    RuleCategory::new(
        "XSS",
        Severity::High,
        Action::Block,
        patterns::xss::PATTERNS,
    ),
    RuleCategory::new(
        "PT",
        Severity::High,
        Action::Block,
        patterns::path_traversal::PATTERNS,
    ),
    RuleCategory::new(
        "CI",
        Severity::Critical,
        Action::Block,
        patterns::command_injection::PATTERNS,
    ),
    RuleCategory::new(
        "FI",
        Severity::High,
        Action::Block,
        patterns::file_inclusion::PATTERNS,
    ),
    RuleCategory::new(
        "SSRF",
        Severity::Medium,
        Action::Alert,
        patterns::ssrf::PATTERNS,
    ),
    RuleCategory::new(
        "XXE",
        Severity::High,
        Action::Block,
        patterns::xxe::PATTERNS,
    ),
    RuleCategory::new(
        "API",
        Severity::Medium,
        Action::Alert,
        patterns::api_abuse::PATTERNS,
    ),
    RuleCategory::new(
        "SCAN",
        Severity::Low,
        Action::Log,
        patterns::scanner::PATTERNS,
    ),
];

/// Общее число паттернов во всех категориях.
pub fn total_patterns() -> usize {
    CATEGORIES.iter().map(RuleCategory::len).sum()
}

#[cfg(test)]
mod tests {
    use super::{total_patterns, CATEGORIES};

    #[test]
    fn catalog_matches_the_python_signature_table() {
        assert_eq!(CATEGORIES.len(), 9);
        assert_eq!(total_patterns(), 74);
    }
}

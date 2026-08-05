//! Поставщик правил из статического каталога категорий.

use crate::domain::rule_id::RuleId;
use crate::domain::rule_meta::RuleMeta;
use crate::error::{Result, WafError};
use crate::ports::rule::Rule;
use crate::ports::rule_source::RuleSource;
use crate::rules::catalog::CATEGORIES;
use crate::rules::category::RuleCategory;
use crate::rules::pattern_rule::PatternRule;
use crate::rules::regex_matcher::RegexMatcher;
use std::sync::Arc;

pub struct CatalogRuleSource {
    categories: Vec<RuleCategory>,
}

impl Default for CatalogRuleSource {
    fn default() -> Self {
        CatalogRuleSource {
            categories: CATEGORIES.to_vec(),
        }
    }
}

impl CatalogRuleSource {
    pub fn new() -> Self {
        CatalogRuleSource::default()
    }

    /// Свой набор категорий — например, только SQLi и XSS.
    pub fn with_categories(categories: Vec<RuleCategory>) -> Self {
        CatalogRuleSource { categories }
    }
}

impl RuleSource for CatalogRuleSource {
    fn rules(&self) -> Result<Vec<Arc<dyn Rule>>> {
        let mut rules: Vec<Arc<dyn Rule>> = Vec::new();
        // Сквозная нумерация по всем категориям — как в прежней реализации.
        let mut counter = 1usize;
        for category in &self.categories {
            for (pattern, description) in category.patterns {
                let matcher =
                    RegexMatcher::compile(pattern).map_err(|err| WafError::RuleCompile {
                        rule_id: format!("{}-{counter:03}", category.prefix),
                        pattern: (*pattern).to_owned(),
                        source: err.to_string(),
                    })?;
                let meta = RuleMeta::new(
                    RuleId::numbered(category.prefix, counter),
                    *description,
                    category.severity,
                    category.action,
                );
                rules.push(Arc::new(PatternRule::new(meta, Arc::new(matcher))));
                counter += 1;
            }
        }
        Ok(rules)
    }
}

#[cfg(test)]
mod tests {
    use super::CatalogRuleSource;
    use crate::domain::severity::Severity;
    use crate::ports::rule_source::RuleSource;
    use crate::rules::catalog::total_patterns;

    #[test]
    fn every_shipped_pattern_compiles() {
        let rules = CatalogRuleSource::new()
            .rules()
            .expect("каталог не собрался");
        assert_eq!(rules.len(), total_patterns());
    }

    #[test]
    fn ids_are_numbered_continuously_across_categories() {
        let rules = CatalogRuleSource::new().rules().unwrap();
        assert_eq!(rules[0].meta().id.as_str(), "SQLI-001");
        assert_eq!(rules[0].meta().severity, Severity::Critical);
        // 10 паттернов SQLi -> XSS начинается с 011.
        assert_eq!(rules[10].meta().id.as_str(), "XSS-011");
        assert_eq!(rules[10].meta().severity, Severity::High);
    }
}

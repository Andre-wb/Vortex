//! Поставщик заранее собранных правил — для тестов и точечных наборов.

use crate::error::Result;
use crate::ports::rule::Rule;
use crate::ports::rule_source::RuleSource;
use std::sync::Arc;

pub struct StaticRuleSource {
    rules: Vec<Arc<dyn Rule>>,
}

impl StaticRuleSource {
    pub fn new(rules: Vec<Arc<dyn Rule>>) -> Self {
        StaticRuleSource { rules }
    }

    pub fn empty() -> Self {
        StaticRuleSource { rules: Vec::new() }
    }
}

impl RuleSource for StaticRuleSource {
    fn rules(&self) -> Result<Vec<Arc<dyn Rule>>> {
        Ok(self.rules.clone())
    }
}

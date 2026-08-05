//! Объединение нескольких поставщиков правил в один.

use crate::error::Result;
use crate::ports::rule::Rule;
use crate::ports::rule_source::RuleSource;
use std::sync::Arc;

pub struct CompositeRuleSource {
    sources: Vec<Arc<dyn RuleSource>>,
}

impl CompositeRuleSource {
    pub fn new(sources: Vec<Arc<dyn RuleSource>>) -> Self {
        CompositeRuleSource { sources }
    }
}

impl RuleSource for CompositeRuleSource {
    fn rules(&self) -> Result<Vec<Arc<dyn Rule>>> {
        let mut all = Vec::new();
        for source in &self.sources {
            all.extend(source.rules()?);
        }
        Ok(all)
    }
}

#[cfg(test)]
mod tests {
    use super::CompositeRuleSource;
    use crate::domain::action::Action;
    use crate::domain::rule_meta::RuleMeta;
    use crate::domain::severity::Severity;
    use crate::ports::rule::Rule;
    use crate::ports::rule_source::RuleSource;
    use crate::rules::pattern_rule::PatternRule;
    use crate::rules::static_source::StaticRuleSource;
    use crate::rules::substring_matcher::SubstringMatcher;
    use std::sync::Arc;

    fn rule(id: &str) -> Arc<dyn Rule> {
        Arc::new(PatternRule::new(
            RuleMeta::new(id, "тест", Severity::Low, Action::Log),
            Arc::new(SubstringMatcher::new("x")),
        ))
    }

    #[test]
    fn concatenates_sources_in_order() {
        let composite = CompositeRuleSource::new(vec![
            Arc::new(StaticRuleSource::new(vec![rule("A-001")])),
            Arc::new(StaticRuleSource::new(vec![rule("B-001")])),
            Arc::new(StaticRuleSource::empty()),
        ]);
        let ids: Vec<String> = composite
            .rules()
            .unwrap()
            .iter()
            .map(|r| r.meta().id.to_string())
            .collect();
        assert_eq!(ids, vec!["A-001", "B-001"]);
    }
}

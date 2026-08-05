//! Правило = паспорт + матчер.

use crate::domain::rule_meta::RuleMeta;
use crate::ports::matcher::Matcher;
use crate::ports::rule::Rule;
use std::sync::Arc;

pub struct PatternRule {
    meta: RuleMeta,
    matcher: Arc<dyn Matcher>,
}

impl PatternRule {
    pub fn new(meta: RuleMeta, matcher: Arc<dyn Matcher>) -> Self {
        PatternRule { meta, matcher }
    }
}

impl Matcher for PatternRule {
    fn is_match(&self, input: &str) -> bool {
        self.matcher.is_match(input)
    }
}

impl Rule for PatternRule {
    fn meta(&self) -> &RuleMeta {
        &self.meta
    }
}

impl std::fmt::Debug for PatternRule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PatternRule")
            .field("meta", &self.meta)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::PatternRule;
    use crate::domain::action::Action;
    use crate::domain::rule_meta::RuleMeta;
    use crate::domain::severity::Severity;
    use crate::ports::matcher::Matcher;
    use crate::ports::rule::Rule;
    use crate::rules::substring_matcher::SubstringMatcher;
    use std::sync::Arc;

    #[test]
    fn delegates_matching_to_the_matcher() {
        let rule = PatternRule::new(
            RuleMeta::new("T-001", "тест", Severity::High, Action::Block),
            Arc::new(SubstringMatcher::new("payload")),
        );
        assert!(rule.is_match("вот payload"));
        assert_eq!(rule.meta().id.as_str(), "T-001");
    }
}

//! Блокировка по действию правила, а не по уровню опасности.
//!
//! Ещё один пример расширения без правки движка: политика меняет критерий
//! целиком, оставаясь взаимозаменяемой с остальными (LSP).

use crate::domain::decision::Decision;
use crate::domain::finding::Finding;
use crate::domain::rule_id::RuleId;
use crate::ports::block_policy::BlockPolicy;
use std::collections::HashSet;

pub struct DenyListPolicy {
    blocking_rules: HashSet<RuleId>,
}

impl DenyListPolicy {
    pub fn new<I, S>(rule_ids: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<RuleId>,
    {
        DenyListPolicy {
            blocking_rules: rule_ids.into_iter().map(Into::into).collect(),
        }
    }
}

impl BlockPolicy for DenyListPolicy {
    fn decide(&self, findings: &[Finding]) -> Decision {
        let matched: Vec<_> = findings
            .iter()
            .filter(|f| self.blocking_rules.contains(&f.rule_id))
            .map(|f| f.rule_id.clone())
            .collect();
        if matched.is_empty() {
            Decision::allow()
        } else {
            Decision::block(matched)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::DenyListPolicy;
    use crate::domain::finding::Finding;
    use crate::domain::severity::Severity;
    use crate::ports::block_policy::BlockPolicy;

    #[test]
    fn blocks_only_listed_rules() {
        let policy = DenyListPolicy::new(["SQLI-001"]);
        assert!(
            policy
                .decide(&[Finding::new("SQLI-001", Severity::Low)])
                .block
        );
        assert!(
            !policy
                .decide(&[Finding::new("XSS-011", Severity::Critical)])
                .block
        );
    }
}

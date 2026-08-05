//! Блокировка по порогу серьёзности.

use crate::domain::decision::Decision;
use crate::domain::finding::Finding;
use crate::domain::severity::Severity;
use crate::ports::block_policy::BlockPolicy;

#[derive(Debug, Clone, Copy)]
pub struct SeverityThresholdPolicy {
    threshold: Severity,
}

impl Default for SeverityThresholdPolicy {
    fn default() -> Self {
        SeverityThresholdPolicy {
            threshold: Severity::High,
        }
    }
}

impl SeverityThresholdPolicy {
    pub fn new(threshold: Severity) -> Self {
        SeverityThresholdPolicy { threshold }
    }

    pub fn threshold(&self) -> Severity {
        self.threshold
    }
}

impl BlockPolicy for SeverityThresholdPolicy {
    fn decide(&self, findings: &[Finding]) -> Decision {
        // Повторы идентификаторов сохраняем: статистика считает срабатывания,
        // а не уникальные правила.
        let matched: Vec<_> = findings
            .iter()
            .filter(|f| f.is_at_least(self.threshold))
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
    use super::SeverityThresholdPolicy;
    use crate::domain::finding::Finding;
    use crate::domain::severity::Severity;
    use crate::ports::block_policy::BlockPolicy;

    #[test]
    fn blocks_on_high_and_above() {
        let policy = SeverityThresholdPolicy::default();
        let findings = vec![
            Finding::new("SCAN-070", Severity::Low),
            Finding::new("XSS-011", Severity::High),
            Finding::new("SQLI-001", Severity::Critical),
        ];
        let decision = policy.decide(&findings);
        assert!(decision.block);
        assert_eq!(decision.matched_rules.len(), 2);
    }

    #[test]
    fn low_severity_alone_does_not_block() {
        let policy = SeverityThresholdPolicy::default();
        let decision = policy.decide(&[Finding::new("SCAN-070", Severity::Low)]);
        assert!(!decision.block);
        assert!(decision.matched_rules.is_empty());
    }

    #[test]
    fn threshold_is_configurable() {
        let strict = SeverityThresholdPolicy::new(Severity::Critical);
        assert!(
            !strict
                .decide(&[Finding::new("XSS-011", Severity::High)])
                .block
        );
        assert_eq!(strict.threshold(), Severity::Critical);
    }

    #[test]
    fn duplicate_rule_ids_are_kept() {
        let policy = SeverityThresholdPolicy::default();
        let findings = vec![
            Finding::new("XSS-011", Severity::High),
            Finding::new("XSS-011", Severity::High),
        ];
        assert_eq!(policy.decide(&findings).matched_rules.len(), 2);
    }
}

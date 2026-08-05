//! Итог анализа одного запроса.

use crate::domain::client_ip::ClientIp;
use crate::domain::finding::Finding;
use crate::domain::rule_id::RuleId;
use crate::domain::severity::Severity;

#[derive(Debug, Clone)]
pub struct Analysis {
    pub block: bool,
    pub reason: Option<String>,
    pub findings: Vec<Finding>,
    pub matched_rules: Vec<RuleId>,
    pub client_ip: ClientIp,
}

impl Analysis {
    pub fn allowed(client_ip: ClientIp, findings: Vec<Finding>) -> Self {
        Analysis {
            block: false,
            reason: None,
            findings,
            matched_rules: Vec::new(),
            client_ip,
        }
    }

    pub fn blocked(
        client_ip: ClientIp,
        reason: impl Into<String>,
        findings: Vec<Finding>,
        matched_rules: Vec<RuleId>,
    ) -> Self {
        Analysis {
            block: true,
            reason: Some(reason.into()),
            findings,
            matched_rules,
            client_ip,
        }
    }

    /// Находки уровня high и выше — их показывает ответ 403.
    pub fn critical_findings(&self) -> impl Iterator<Item = &Finding> {
        self.findings
            .iter()
            .filter(|f| f.is_at_least(Severity::High))
    }
}

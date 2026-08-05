//! Режим наблюдения: находки собираются, но запрос не блокируется.
//!
//! Пригодится при обкатке новых сигнатур на боевом трафике.

use crate::domain::decision::Decision;
use crate::domain::finding::Finding;
use crate::ports::block_policy::BlockPolicy;

#[derive(Debug, Clone, Copy, Default)]
pub struct MonitorOnlyPolicy;

impl MonitorOnlyPolicy {
    pub fn new() -> Self {
        MonitorOnlyPolicy
    }
}

impl BlockPolicy for MonitorOnlyPolicy {
    fn decide(&self, _findings: &[Finding]) -> Decision {
        Decision::allow()
    }
}

#[cfg(test)]
mod tests {
    use super::MonitorOnlyPolicy;
    use crate::domain::finding::Finding;
    use crate::domain::severity::Severity;
    use crate::ports::block_policy::BlockPolicy;

    #[test]
    fn never_blocks_even_on_critical() {
        let decision =
            MonitorOnlyPolicy::new().decide(&[Finding::new("SQLI-001", Severity::Critical)]);
        assert!(!decision.block);
    }
}

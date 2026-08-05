//! Ответ 403 на заблокированный запрос.

use crate::domain::analysis::Analysis;
use crate::http::responses::http_response::HttpResponse;
use crate::ports::clock::Clock;
use crate::ports::random_source::RandomSource;
use serde_json::json;
use std::sync::Arc;

/// Сколько нарушений показывать клиенту.
pub const MAX_REPORTED_VIOLATIONS: usize = 3;

pub struct BlockedResponseBuilder {
    clock: Arc<dyn Clock>,
    random: Arc<dyn RandomSource>,
}

impl BlockedResponseBuilder {
    pub fn new(clock: Arc<dyn Clock>, random: Arc<dyn RandomSource>) -> Self {
        BlockedResponseBuilder { clock, random }
    }

    pub fn build(&self, analysis: &Analysis) -> HttpResponse {
        let violations: Vec<_> = analysis
            .critical_findings()
            .take(MAX_REPORTED_VIOLATIONS)
            .map(|f| {
                json!({
                    "rule_id": f.rule_id,
                    "description": f.description,
                    "severity": f.severity,
                })
            })
            .collect();

        let body = json!({
            "error": "Request blocked by WAF",
            "request_id": self.random.hex(8),
            "timestamp": self.clock.now().to_rfc3339(),
            "client_ip": analysis.client_ip,
            "violations": violations,
        });

        HttpResponse::json(403, body.to_string().into_bytes()).with_header("x-waf-blocked", "true")
    }
}

#[cfg(test)]
mod tests {
    use super::BlockedResponseBuilder;
    use crate::domain::analysis::Analysis;
    use crate::domain::client_ip::ClientIp;
    use crate::domain::finding::Finding;
    use crate::domain::severity::Severity;
    use crate::random::sequence_random::SequenceRandom;
    use crate::time::manual_clock::ManualClock;
    use std::sync::Arc;

    fn builder() -> BlockedResponseBuilder {
        BlockedResponseBuilder::new(
            Arc::new(ManualClock::at_epoch()),
            Arc::new(SequenceRandom::new(vec![0]).with_filler(0xAA)),
        )
    }

    #[test]
    fn reports_at_most_three_critical_violations() {
        let findings = (0..5)
            .map(|i| Finding::new(format!("XSS-{i:03}"), Severity::High))
            .chain(std::iter::once(Finding::new("SCAN-070", Severity::Low)))
            .collect();
        let analysis = Analysis::blocked(
            ClientIp::from("1.2.3.4"),
            "заблокировано",
            findings,
            Vec::new(),
        );

        let response = builder().build(&analysis);
        assert_eq!(response.status, 403);
        assert_eq!(response.header("x-waf-blocked"), Some("true"));

        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(body["violations"].as_array().unwrap().len(), 3);
        assert_eq!(body["client_ip"], "1.2.3.4");
        assert_eq!(body["request_id"], "aaaaaaaaaaaaaaaa");
        assert_eq!(body["timestamp"], "2026-01-01T00:00:00+00:00");
    }

    #[test]
    fn low_severity_findings_are_not_disclosed() {
        let analysis = Analysis::blocked(
            ClientIp::unknown(),
            "заблокировано",
            vec![Finding::new("SCAN-070", Severity::Low)],
            Vec::new(),
        );
        let body: serde_json::Value =
            serde_json::from_slice(&builder().build(&analysis).body).unwrap();
        assert!(body["violations"].as_array().unwrap().is_empty());
    }
}

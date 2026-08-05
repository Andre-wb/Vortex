//! Проверка заголовка `User-Agent`.

use crate::domain::finding::Finding;
use crate::domain::request::InspectedRequest;
use crate::domain::severity::Severity;
use crate::ports::inspector::Inspector;
use crate::util::truncate::char_len;

/// Значения короче этой длины считаются подозрительными.
pub const MIN_USER_AGENT_CHARS: usize = 5;

#[derive(Debug, Clone, Copy, Default)]
pub struct UserAgentInspector;

impl UserAgentInspector {
    pub fn new() -> Self {
        UserAgentInspector
    }
}

impl Inspector for UserAgentInspector {
    fn name(&self) -> &'static str {
        "user-agent"
    }

    fn inspect(&self, request: &InspectedRequest) -> Vec<Finding> {
        // Отсутствующий заголовок не проверяется — так же было и раньше.
        let Some(value) = request.header("user-agent") else {
            return Vec::new();
        };
        if !value.is_empty() && char_len(value) >= MIN_USER_AGENT_CHARS {
            return Vec::new();
        }
        vec![Finding::new("SUSPICIOUS-UA", Severity::Low).with_description("Suspicious User-Agent")]
    }
}

#[cfg(test)]
mod tests {
    use super::UserAgentInspector;
    use crate::domain::request_builder::RequestBuilder;
    use crate::ports::inspector::Inspector;

    #[test]
    fn short_or_empty_user_agent_is_flagged() {
        for value in ["", "curl"] {
            let req = RequestBuilder::new().header("user-agent", value).build();
            assert_eq!(UserAgentInspector::new().inspect(&req).len(), 1, "{value}");
        }
    }

    #[test]
    fn normal_and_missing_user_agent_pass() {
        let req = RequestBuilder::new()
            .header("user-agent", "Mozilla/5.0")
            .build();
        assert!(UserAgentInspector::new().inspect(&req).is_empty());
        assert!(UserAgentInspector::new()
            .inspect(&RequestBuilder::new().build())
            .is_empty());
    }
}

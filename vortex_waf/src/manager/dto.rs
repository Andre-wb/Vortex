//! Структуры ответов управляющего API.

use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OperationResult {
    pub success: bool,
    pub ip: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl OperationResult {
    pub fn new(success: bool, ip: impl Into<String>) -> Self {
        OperationResult {
            success,
            ip: ip.into(),
            reason: None,
            duration: None,
            message: None,
        }
    }

    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = Some(reason.into());
        self
    }

    pub fn with_duration(mut self, duration: u64) -> Self {
        self.duration = Some(duration);
        self
    }

    pub fn with_message(mut self, message: impl Into<String>) -> Self {
        self.message = Some(message.into());
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BlockedIpView {
    pub ip: String,
    pub blocked_at: String,
    pub blocked_until: String,
    pub reason: String,
    pub duration: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RuleView {
    pub id: String,
    pub description: String,
    pub severity: String,
    pub action: String,
    pub trigger_count: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_triggered: Option<String>,
}

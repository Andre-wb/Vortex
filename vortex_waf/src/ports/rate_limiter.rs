//! Ограничитель частоты запросов.

use crate::domain::client_ip::ClientIp;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RateLimitOutcome {
    Allowed,
    Exceeded { message: String },
}

impl RateLimitOutcome {
    pub fn is_allowed(&self) -> bool {
        matches!(self, RateLimitOutcome::Allowed)
    }
}

pub trait RateLimiter: Send + Sync {
    fn check(&self, ip: &ClientIp) -> RateLimitOutcome;
}

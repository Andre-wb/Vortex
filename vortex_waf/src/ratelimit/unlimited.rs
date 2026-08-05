//! Ограничитель, который ничего не ограничивает.
//!
//! Подставляется в конфигурациях без лимита частоты и в тестах, где лимит
//! мешает. Контракт соблюдён полностью: всегда возвращает «разрешено».

use crate::domain::client_ip::ClientIp;
use crate::ports::rate_limiter::{RateLimitOutcome, RateLimiter};

#[derive(Debug, Clone, Copy, Default)]
pub struct UnlimitedRateLimiter;

impl UnlimitedRateLimiter {
    pub fn new() -> Self {
        UnlimitedRateLimiter
    }
}

impl RateLimiter for UnlimitedRateLimiter {
    fn check(&self, _ip: &ClientIp) -> RateLimitOutcome {
        RateLimitOutcome::Allowed
    }
}

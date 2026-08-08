pub const MAX_ATTEMPTS: u32 = 3;
pub const BACKOFF_BASE_MS: u32 = 1000;
pub const BACKOFF_MAX_MS: u32 = 30000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryPolicy {
    pub max_attempts: u32,
    pub backoff_base_ms: u32,
    pub backoff_max_ms: u32,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        RetryPolicy {
            max_attempts: MAX_ATTEMPTS,
            backoff_base_ms: BACKOFF_BASE_MS,
            backoff_max_ms: BACKOFF_MAX_MS,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::RetryPolicy;

    #[test]
    fn a_retry_gives_up_before_it_becomes_a_flood() {
        let policy = RetryPolicy::default();
        assert!(policy.max_attempts > 1);
        assert!(policy.max_attempts <= 5);
    }

    #[test]
    fn the_wait_between_attempts_has_a_ceiling_above_its_floor() {
        let policy = RetryPolicy::default();
        assert!(policy.backoff_max_ms > policy.backoff_base_ms);
    }
}

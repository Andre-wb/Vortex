//! Настройки ограничителя частоты.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimitConfig {
    /// Разрешённое число запросов в окне.
    pub requests: usize,
    /// Длина окна в секундах.
    pub window_secs: u64,
    /// На сколько блокировать адрес при грубом превышении.
    pub escalation_block_secs: u64,
    /// Порог, после которого адрес блокируется, а не просто получает отказ.
    /// `None` — двукратный лимит, как в прежней реализации.
    pub escalation_threshold: Option<usize>,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        RateLimitConfig {
            requests: 100,
            window_secs: 60,
            escalation_block_secs: 1800,
            escalation_threshold: None,
        }
    }
}

impl RateLimitConfig {
    pub fn new(requests: usize, window_secs: u64) -> Self {
        RateLimitConfig {
            requests,
            window_secs,
            ..Default::default()
        }
    }

    pub fn with_escalation_threshold(mut self, threshold: usize) -> Self {
        self.escalation_threshold = Some(threshold);
        self
    }

    pub fn escalation_threshold(&self) -> usize {
        self.escalation_threshold
            .unwrap_or_else(|| self.requests.saturating_mul(2))
    }
}

#[cfg(test)]
mod tests {
    use super::RateLimitConfig;

    #[test]
    fn defaults_match_the_previous_engine() {
        let cfg = RateLimitConfig::default();
        assert_eq!(cfg.requests, 100);
        assert_eq!(cfg.window_secs, 60);
        assert_eq!(cfg.escalation_block_secs, 1800);
        assert_eq!(cfg.escalation_threshold(), 200);
    }

    #[test]
    fn escalation_threshold_can_be_overridden() {
        assert_eq!(
            RateLimitConfig::new(10, 60)
                .with_escalation_threshold(12)
                .escalation_threshold(),
            12
        );
    }
}

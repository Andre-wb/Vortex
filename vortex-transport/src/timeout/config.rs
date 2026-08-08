pub const DEFAULT_HANDSHAKE_SECS: f64 = 10.0;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct TimeoutConfig {
    pub handshake_secs: f64,
}

impl Default for TimeoutConfig {
    fn default() -> Self {
        TimeoutConfig {
            handshake_secs: DEFAULT_HANDSHAKE_SECS,
        }
    }
}

impl TimeoutConfig {
    pub fn new(handshake_secs: f64) -> Self {
        TimeoutConfig { handshake_secs }
    }

    pub fn is_usable(&self) -> bool {
        self.handshake_secs.is_finite() && self.handshake_secs > 0.0
    }
}

#[cfg(test)]
mod tests {
    use super::{TimeoutConfig, DEFAULT_HANDSHAKE_SECS};

    #[test]
    fn a_client_gets_ten_seconds_to_finish_what_it_started() {
        assert_eq!(
            TimeoutConfig::default().handshake_secs,
            DEFAULT_HANDSHAKE_SECS
        );
        assert!(TimeoutConfig::default().is_usable());
    }

    #[test]
    fn a_budget_that_is_not_a_budget_is_not_usable() {
        assert!(!TimeoutConfig::new(0.0).is_usable());
        assert!(!TimeoutConfig::new(-1.0).is_usable());
        assert!(!TimeoutConfig::new(f64::NAN).is_usable());
        assert!(!TimeoutConfig::new(f64::INFINITY).is_usable());
    }
}

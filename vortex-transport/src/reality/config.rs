pub const DEFAULT_AUTH_WINDOW_PAST_SECS: i64 = 120;
pub const DEFAULT_AUTH_WINDOW_FUTURE_SECS: i64 = 30;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RealityConfig {
    pub auth_window_past_secs: i64,
    pub auth_window_future_secs: i64,
}

impl Default for RealityConfig {
    fn default() -> Self {
        RealityConfig {
            auth_window_past_secs: DEFAULT_AUTH_WINDOW_PAST_SECS,
            auth_window_future_secs: DEFAULT_AUTH_WINDOW_FUTURE_SECS,
        }
    }
}

impl RealityConfig {
    pub fn new() -> Self {
        RealityConfig::default()
    }

    pub fn auth_window_past_secs(mut self, seconds: i64) -> Self {
        self.auth_window_past_secs = seconds;
        self
    }

    pub fn auth_window_future_secs(mut self, seconds: i64) -> Self {
        self.auth_window_future_secs = seconds;
        self
    }

    pub fn accepts(&self, now: i64, timestamp: i64) -> bool {
        let age = now.saturating_sub(timestamp);
        age <= self.auth_window_past_secs && age.saturating_neg() <= self.auth_window_future_secs
    }
}

#[cfg(test)]
mod tests {
    use super::{RealityConfig, DEFAULT_AUTH_WINDOW_FUTURE_SECS, DEFAULT_AUTH_WINDOW_PAST_SECS};

    #[test]
    fn tolerates_much_less_clock_skew_forward_than_backward() {
        assert_eq!(DEFAULT_AUTH_WINDOW_PAST_SECS, 120);
        assert_eq!(DEFAULT_AUTH_WINDOW_FUTURE_SECS, 30);
    }

    #[test]
    fn accepts_the_whole_past_window_and_no_more() {
        let config = RealityConfig::default();
        assert!(config.accepts(1000, 1000 - 120));
        assert!(!config.accepts(1000, 1000 - 121));
    }

    #[test]
    fn accepts_only_a_small_step_into_the_future() {
        let config = RealityConfig::default();
        assert!(config.accepts(1000, 1030));
        assert!(!config.accepts(1000, 1031));
    }

    #[test]
    fn survives_extreme_timestamps_without_overflow() {
        let config = RealityConfig::default();
        assert!(!config.accepts(0, i64::MAX));
        assert!(!config.accepts(0, i64::MIN));
        assert!(!config.accepts(i64::MAX, i64::MIN));
    }
}

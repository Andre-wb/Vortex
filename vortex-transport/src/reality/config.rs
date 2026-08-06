pub const DEFAULT_AUTH_WINDOW_SECS: i64 = 120;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RealityConfig {
    pub auth_window_secs: i64,
}

impl Default for RealityConfig {
    fn default() -> Self {
        RealityConfig {
            auth_window_secs: DEFAULT_AUTH_WINDOW_SECS,
        }
    }
}

impl RealityConfig {
    pub fn new() -> Self {
        RealityConfig::default()
    }

    pub fn auth_window_secs(mut self, seconds: i64) -> Self {
        self.auth_window_secs = seconds;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::{RealityConfig, DEFAULT_AUTH_WINDOW_SECS};

    #[test]
    fn defaults_to_the_two_minute_window() {
        assert_eq!(
            RealityConfig::default().auth_window_secs,
            DEFAULT_AUTH_WINDOW_SECS
        );
    }
}

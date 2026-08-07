pub const DEFAULT_ROTATION_PERIOD_SECS: u64 = 3600;
pub const DEFAULT_ROTATION_JITTER_SECS: u16 = 600;
pub const DEFAULT_CLOCK_SKEW_EPOCHS: i64 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RotationConfig {
    pub period_secs: u64,
    pub jitter_secs: u16,
    pub clock_skew_epochs: i64,
}

impl Default for RotationConfig {
    fn default() -> Self {
        RotationConfig {
            period_secs: DEFAULT_ROTATION_PERIOD_SECS,
            jitter_secs: DEFAULT_ROTATION_JITTER_SECS,
            clock_skew_epochs: DEFAULT_CLOCK_SKEW_EPOCHS,
        }
    }
}

impl RotationConfig {
    pub fn new() -> Self {
        RotationConfig::default()
    }

    pub fn period_secs(mut self, seconds: u64) -> Self {
        self.period_secs = seconds;
        self
    }

    pub fn jitter_secs(mut self, seconds: u16) -> Self {
        self.jitter_secs = seconds;
        self
    }

    pub fn clock_skew_epochs(mut self, epochs: i64) -> Self {
        self.clock_skew_epochs = epochs;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::RotationConfig;

    #[test]
    fn the_defaults_match_the_javascript_client() {
        let config = RotationConfig::default();
        assert_eq!(config.period_secs, 3600);
        assert_eq!(config.jitter_secs, 600);
        assert_eq!(config.clock_skew_epochs, 1);
    }
}

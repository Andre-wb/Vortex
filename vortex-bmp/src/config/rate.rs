pub const DEFAULT_WINDOW_SECS: f64 = 60.0;
pub const DEFAULT_STANDARD_PER_WINDOW: u32 = 600;
pub const DEFAULT_FAST_PER_WINDOW: u32 = 3000;
pub const DEFAULT_MAX_TRACKED_KEYS: usize = 50_000;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RateConfig {
    pub window_secs: f64,
    pub standard_per_window: u32,
    pub fast_per_window: u32,
    pub max_tracked_keys: usize,
}

impl Default for RateConfig {
    fn default() -> Self {
        RateConfig {
            window_secs: DEFAULT_WINDOW_SECS,
            standard_per_window: DEFAULT_STANDARD_PER_WINDOW,
            fast_per_window: DEFAULT_FAST_PER_WINDOW,
            max_tracked_keys: DEFAULT_MAX_TRACKED_KEYS,
        }
    }
}

impl RateConfig {
    pub fn new() -> Self {
        RateConfig::default()
    }

    pub fn window_secs(mut self, seconds: f64) -> Self {
        self.window_secs = seconds;
        self
    }

    pub fn standard_per_window(mut self, limit: u32) -> Self {
        self.standard_per_window = limit;
        self
    }

    pub fn fast_per_window(mut self, limit: u32) -> Self {
        self.fast_per_window = limit;
        self
    }

    pub fn max_tracked_keys(mut self, keys: usize) -> Self {
        self.max_tracked_keys = keys;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::RateConfig;

    #[test]
    fn the_defaults_match_the_python_routes() {
        let config = RateConfig::default();
        assert_eq!(config.window_secs, 60.0);
        assert_eq!(config.standard_per_window, 600);
        assert_eq!(config.fast_per_window, 3000);
    }
}

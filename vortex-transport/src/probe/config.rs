pub const DEFAULT_BASE_INTERVAL_SECS: f64 = 300.0;
pub const DEFAULT_JITTER_LOW: f64 = 0.5;
pub const DEFAULT_JITTER_HIGH: f64 = 2.0;
pub const DEFAULT_RUN_TIMEOUT_SECS: f64 = 35.0;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ProbeConfig {
    pub base_interval_secs: f64,
    pub jitter_low: f64,
    pub jitter_high: f64,
    pub run_timeout_secs: f64,
}

impl Default for ProbeConfig {
    fn default() -> Self {
        ProbeConfig {
            base_interval_secs: DEFAULT_BASE_INTERVAL_SECS,
            jitter_low: DEFAULT_JITTER_LOW,
            jitter_high: DEFAULT_JITTER_HIGH,
            run_timeout_secs: DEFAULT_RUN_TIMEOUT_SECS,
        }
    }
}

impl ProbeConfig {
    pub fn base_interval_secs(mut self, seconds: f64) -> Self {
        self.base_interval_secs = seconds;
        self
    }

    pub fn run_timeout_secs(mut self, seconds: f64) -> Self {
        self.run_timeout_secs = seconds;
        self
    }

    pub fn shortest_interval(&self) -> f64 {
        self.base_interval_secs * self.jitter_low
    }

    pub fn longest_interval(&self) -> f64 {
        self.base_interval_secs * self.jitter_high
    }
}

#[cfg(test)]
mod tests {
    use super::ProbeConfig;

    #[test]
    fn the_default_run_waits_longer_than_the_slowest_probe() {
        let config = ProbeConfig::default();
        let slowest = crate::probe::catalogue::PROBES
            .iter()
            .map(|probe| probe.timeout_secs)
            .fold(0.0f64, f64::max);
        assert!(
            config.run_timeout_secs > slowest,
            "общий предел обязан переживать самую медленную пробу"
        );
    }

    #[test]
    fn the_interval_is_named_by_its_own_bounds() {
        let config = ProbeConfig::default();
        assert_eq!(config.shortest_interval(), 150.0);
        assert_eq!(config.longest_interval(), 600.0);
    }

    #[test]
    fn a_named_interval_wins_over_the_default() {
        let config = ProbeConfig::default().base_interval_secs(60.0);
        assert_eq!(config.shortest_interval(), 30.0);
        assert_eq!(config.longest_interval(), 120.0);
    }
}

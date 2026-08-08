pub const DEFAULT_PROBE_INTERVAL_SECS: f64 = 60.0;
pub const DEFAULT_JITTER_LOW: f64 = 0.5;
pub const DEFAULT_JITTER_HIGH: f64 = 1.8;
pub const DEFAULT_HISTORY_LEN: usize = 60;
pub const DEFAULT_FAILURES_TO_BLOCK: usize = 3;
pub const DEFAULT_SAMPLES_BEFORE_DEGRADATION: usize = 5;
pub const DEFAULT_DEGRADATION_FACTOR: f64 = 3.0;
pub const DEFAULT_ALERT_HISTORY_LEN: usize = 200;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LatencyConfig {
    pub probe_interval_secs: f64,
    pub jitter_low: f64,
    pub jitter_high: f64,
    pub history_len: usize,
    pub failures_to_block: usize,
    pub samples_before_degradation: usize,
    pub degradation_factor: f64,
    pub alert_history_len: usize,
}

impl Default for LatencyConfig {
    fn default() -> Self {
        LatencyConfig {
            probe_interval_secs: DEFAULT_PROBE_INTERVAL_SECS,
            jitter_low: DEFAULT_JITTER_LOW,
            jitter_high: DEFAULT_JITTER_HIGH,
            history_len: DEFAULT_HISTORY_LEN,
            failures_to_block: DEFAULT_FAILURES_TO_BLOCK,
            samples_before_degradation: DEFAULT_SAMPLES_BEFORE_DEGRADATION,
            degradation_factor: DEFAULT_DEGRADATION_FACTOR,
            alert_history_len: DEFAULT_ALERT_HISTORY_LEN,
        }
    }
}

impl LatencyConfig {
    pub fn probe_interval_secs(mut self, seconds: f64) -> Self {
        self.probe_interval_secs = seconds;
        self
    }

    pub fn history_len(mut self, samples: usize) -> Self {
        self.history_len = samples;
        self
    }

    pub fn alert_history_len(mut self, alerts: usize) -> Self {
        self.alert_history_len = alerts;
        self
    }

    pub fn shortest_interval(&self) -> f64 {
        self.probe_interval_secs * self.jitter_low
    }

    pub fn longest_interval(&self) -> f64 {
        self.probe_interval_secs * self.jitter_high
    }
}

#[cfg(test)]
mod tests {
    use super::LatencyConfig;

    #[test]
    fn a_verdict_of_blockage_needs_less_history_than_a_verdict_of_slowness() {
        let config = LatencyConfig::default();
        assert!(config.failures_to_block < config.samples_before_degradation);
    }

    #[test]
    fn the_history_holds_more_than_a_single_verdict_needs() {
        let config = LatencyConfig::default();
        assert!(config.history_len > config.samples_before_degradation);
    }

    #[test]
    fn the_interval_is_named_by_its_own_bounds() {
        let config = LatencyConfig::default();
        assert_eq!(config.shortest_interval(), 30.0);
        assert_eq!(config.longest_interval(), 108.0);
    }
}

pub const DEFAULT_SIGNALS_FOR_VERDICT: usize = 2;
pub const DEFAULT_REPLAY_WINDOW: f64 = 2.0;
pub const DEFAULT_MISSING_HEADERS_FOR_SIGNAL: usize = 4;
pub const DEFAULT_SHORT_USER_AGENT: usize = 20;
pub const DEFAULT_MAX_TRACKED_REQUESTS: usize = 10_000;
pub const DEFAULT_REQUEST_MEMORY: f64 = 300.0;
pub const DEFAULT_MAX_TRACKED_PROBES: usize = 10_000;
pub const DEFAULT_PROBE_MEMORY: f64 = 86_400.0;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DetectorConfig {
    pub signals_for_verdict: usize,
    pub replay_window: f64,
    pub missing_headers_for_signal: usize,
    pub short_user_agent: usize,
    pub max_tracked_requests: usize,
    pub request_memory: f64,
    pub max_tracked_probes: usize,
    pub probe_memory: f64,
}

impl Default for DetectorConfig {
    fn default() -> Self {
        DetectorConfig {
            signals_for_verdict: DEFAULT_SIGNALS_FOR_VERDICT,
            replay_window: DEFAULT_REPLAY_WINDOW,
            missing_headers_for_signal: DEFAULT_MISSING_HEADERS_FOR_SIGNAL,
            short_user_agent: DEFAULT_SHORT_USER_AGENT,
            max_tracked_requests: DEFAULT_MAX_TRACKED_REQUESTS,
            request_memory: DEFAULT_REQUEST_MEMORY,
            max_tracked_probes: DEFAULT_MAX_TRACKED_PROBES,
            probe_memory: DEFAULT_PROBE_MEMORY,
        }
    }
}

impl DetectorConfig {
    pub fn signals_for_verdict(mut self, signals: usize) -> Self {
        self.signals_for_verdict = signals;
        self
    }

    pub fn replay_window(mut self, seconds: f64) -> Self {
        self.replay_window = seconds;
        self
    }

    pub fn missing_headers_for_signal(mut self, headers: usize) -> Self {
        self.missing_headers_for_signal = headers;
        self
    }

    pub fn short_user_agent(mut self, length: usize) -> Self {
        self.short_user_agent = length;
        self
    }

    pub fn max_tracked_requests(mut self, requests: usize) -> Self {
        self.max_tracked_requests = requests;
        self
    }

    pub fn request_memory(mut self, seconds: f64) -> Self {
        self.request_memory = seconds;
        self
    }

    pub fn max_tracked_probes(mut self, probes: usize) -> Self {
        self.max_tracked_probes = probes;
        self
    }

    pub fn probe_memory(mut self, seconds: f64) -> Self {
        self.probe_memory = seconds;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::DetectorConfig;

    #[test]
    fn one_signal_alone_never_decides_that_a_client_is_a_censor() {
        assert!(DetectorConfig::default().signals_for_verdict > 1);
    }

    #[test]
    fn a_request_is_remembered_for_longer_than_the_window_it_is_judged_in() {
        let config = DetectorConfig::default();
        assert!(config.request_memory > config.replay_window);
    }

    #[test]
    fn both_things_the_detector_remembers_are_bounded() {
        let config = DetectorConfig::default();
        assert!(config.max_tracked_requests > 0);
        assert!(config.max_tracked_probes > 0);
    }
}

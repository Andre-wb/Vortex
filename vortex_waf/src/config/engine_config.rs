//! Настройки движка.

use crate::domain::severity::Severity;

#[derive(Debug, Clone)]
pub struct EngineConfig {
    pub rate_limit_requests: usize,
    pub rate_limit_window_secs: u64,
    /// Срок блокировки по умолчанию.
    pub block_duration_secs: u64,
    /// Порог, выше которого тело считается слишком большим.
    pub max_content_length: usize,
    /// Порог серьёзности для блокировки.
    pub block_threshold: Severity,
    pub safe_params: Vec<String>,
    pub whitelist_ips: Vec<String>,
}

impl Default for EngineConfig {
    fn default() -> Self {
        EngineConfig {
            rate_limit_requests: 100,
            rate_limit_window_secs: 60,
            block_duration_secs: 3600,
            max_content_length: 10 * 1024 * 1024,
            block_threshold: Severity::High,
            safe_params: vec![
                "csrf_token".to_owned(),
                "_csrf".to_owned(),
                "csrfmiddlewaretoken".to_owned(),
            ],
            whitelist_ips: Vec::new(),
        }
    }
}

impl EngineConfig {
    pub fn new() -> Self {
        EngineConfig::default()
    }

    pub fn rate_limit(mut self, requests: usize, window_secs: u64) -> Self {
        self.rate_limit_requests = requests;
        self.rate_limit_window_secs = window_secs;
        self
    }

    pub fn block_duration(mut self, secs: u64) -> Self {
        self.block_duration_secs = secs;
        self
    }

    pub fn max_content_length(mut self, bytes: usize) -> Self {
        self.max_content_length = bytes;
        self
    }

    pub fn block_threshold(mut self, threshold: Severity) -> Self {
        self.block_threshold = threshold;
        self
    }

    pub fn whitelist<I, S>(mut self, ips: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.whitelist_ips = ips.into_iter().map(Into::into).collect();
        self
    }

    pub fn safe_params<I, S>(mut self, names: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.safe_params = names.into_iter().map(Into::into).collect();
        self
    }
}

#[cfg(test)]
mod tests {
    use super::EngineConfig;
    use crate::domain::severity::Severity;

    #[test]
    fn defaults_match_the_python_engine() {
        let cfg = EngineConfig::default();
        assert_eq!(cfg.rate_limit_requests, 100);
        assert_eq!(cfg.rate_limit_window_secs, 60);
        assert_eq!(cfg.block_duration_secs, 3600);
        assert_eq!(cfg.max_content_length, 10 * 1024 * 1024);
        assert_eq!(cfg.block_threshold, Severity::High);
        assert_eq!(cfg.safe_params.len(), 3);
    }

    #[test]
    fn builder_overrides_apply() {
        let cfg = EngineConfig::new()
            .rate_limit(5, 10)
            .block_duration(60)
            .whitelist(["10.0.0.1"]);
        assert_eq!(cfg.rate_limit_requests, 5);
        assert_eq!(cfg.block_duration_secs, 60);
        assert_eq!(cfg.whitelist_ips, vec!["10.0.0.1"]);
    }
}

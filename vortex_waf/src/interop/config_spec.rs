//! Настройки, приходящие извне крейта в примитивных типах.

use crate::config::engine_config::EngineConfig;

#[derive(Debug, Clone, Default)]
pub struct ConfigSpec {
    pub rate_limit_requests: Option<usize>,
    pub rate_limit_window: Option<u64>,
    pub block_duration: Option<u64>,
    pub max_content_length: Option<usize>,
    pub safe_params: Option<Vec<String>>,
    pub whitelist_ips: Option<Vec<String>>,
    /// Секрет для подписи капчи. Пустой — ключ генерируется на процесс.
    pub captcha_secret: Option<String>,
}

impl ConfigSpec {
    /// Незаданные поля берут значения по умолчанию.
    pub fn to_engine_config(&self) -> EngineConfig {
        let mut config = EngineConfig::default();
        if let Some(value) = self.rate_limit_requests {
            config.rate_limit_requests = value;
        }
        if let Some(value) = self.rate_limit_window {
            config.rate_limit_window_secs = value;
        }
        if let Some(value) = self.block_duration {
            config.block_duration_secs = value;
        }
        if let Some(value) = self.max_content_length {
            config.max_content_length = value;
        }
        if let Some(value) = &self.safe_params {
            config.safe_params = value.clone();
        }
        if let Some(value) = &self.whitelist_ips {
            config.whitelist_ips = value.clone();
        }
        config
    }
}

#[cfg(test)]
mod tests {
    use super::ConfigSpec;

    #[test]
    fn empty_spec_keeps_defaults() {
        let config = ConfigSpec::default().to_engine_config();
        assert_eq!(config.rate_limit_requests, 100);
        assert_eq!(config.rate_limit_window_secs, 60);
        assert_eq!(config.block_duration_secs, 3600);
        assert_eq!(config.safe_params.len(), 3);
    }

    #[test]
    fn provided_fields_override_defaults() {
        let spec = ConfigSpec {
            rate_limit_requests: Some(50),
            rate_limit_window: Some(30),
            whitelist_ips: Some(vec!["10.0.0.1".to_owned()]),
            ..Default::default()
        };
        let config = spec.to_engine_config();
        assert_eq!(config.rate_limit_requests, 50);
        assert_eq!(config.rate_limit_window_secs, 30);
        assert_eq!(config.whitelist_ips, vec!["10.0.0.1"]);
        // Незаданное поле осталось со значением по умолчанию.
        assert_eq!(config.block_duration_secs, 3600);
    }
}

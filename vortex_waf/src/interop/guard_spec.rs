use crate::config::env;
use crate::config::guard_config::GuardConfig;
use crate::http::excluded_paths::ExcludedPaths;

#[derive(Debug, Clone, Default)]
pub struct GuardSpec {
    pub max_body_bytes: Option<usize>,
    pub trusted_proxies: Option<Vec<String>>,
    pub excluded_paths: Option<Vec<String>>,
}

impl GuardSpec {
    pub fn to_guard_config(&self) -> GuardConfig {
        let mut config = env::guard_config_from_env();
        if let Some(bytes) = self.max_body_bytes {
            config.max_body_bytes = bytes;
        }
        if let Some(proxies) = &self.trusted_proxies {
            config.trusted_proxies = proxies.clone();
        }
        config
    }

    pub fn to_excluded_paths(&self) -> ExcludedPaths {
        match &self.excluded_paths {
            Some(paths) => ExcludedPaths::new(paths),
            None => ExcludedPaths::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::GuardSpec;

    #[test]
    fn provided_fields_override_the_environment() {
        let spec = GuardSpec {
            max_body_bytes: Some(4096),
            trusted_proxies: Some(vec!["10.0.0.0/8".to_owned()]),
            excluded_paths: None,
        };
        let config = spec.to_guard_config();
        assert_eq!(config.max_body_bytes, 4096);
        assert_eq!(config.trusted_proxies, vec!["10.0.0.0/8"]);
    }

    #[test]
    fn excluded_paths_default_to_the_shipped_list() {
        assert!(GuardSpec::default()
            .to_excluded_paths()
            .contains("/api/files/upload-init"));
        let custom = GuardSpec {
            excluded_paths: Some(vec!["/internal/".to_owned()]),
            ..Default::default()
        };
        let excluded = custom.to_excluded_paths();
        assert!(excluded.contains("/internal/metrics"));
        assert!(!excluded.contains("/health"));
    }
}

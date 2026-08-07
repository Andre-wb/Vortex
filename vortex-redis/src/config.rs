pub const DEFAULT_POOL_SIZE: usize = 10;
pub const DEFAULT_KEY_PREFIX: &str = "vortex";
pub const DEFAULT_CONNECT_TIMEOUT_SECS: u64 = 5;
pub const DEFAULT_COMMAND_TIMEOUT_SECS: u64 = 2;
pub const DEFAULT_RECOVERY_SECS: u64 = 5;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedisConfig {
    pub url: String,
    pub pool_size: usize,
    pub key_prefix: String,
    pub connect_timeout_secs: u64,
    pub command_timeout_secs: u64,
    pub recovery_secs: u64,
}

impl Default for RedisConfig {
    fn default() -> Self {
        RedisConfig {
            url: String::new(),
            pool_size: DEFAULT_POOL_SIZE,
            key_prefix: DEFAULT_KEY_PREFIX.to_string(),
            connect_timeout_secs: DEFAULT_CONNECT_TIMEOUT_SECS,
            command_timeout_secs: DEFAULT_COMMAND_TIMEOUT_SECS,
            recovery_secs: DEFAULT_RECOVERY_SECS,
        }
    }
}

impl RedisConfig {
    pub fn new(url: impl Into<String>) -> Self {
        RedisConfig {
            url: url.into(),
            ..RedisConfig::default()
        }
    }

    pub fn pool_size(mut self, connections: usize) -> Self {
        self.pool_size = connections.max(1);
        self
    }

    pub fn key_prefix(mut self, prefix: impl Into<String>) -> Self {
        let prefix = prefix.into();
        self.key_prefix = if prefix.is_empty() {
            DEFAULT_KEY_PREFIX.to_string()
        } else {
            prefix
        };
        self
    }

    pub fn connect_timeout_secs(mut self, seconds: u64) -> Self {
        self.connect_timeout_secs = seconds;
        self
    }

    pub fn command_timeout_secs(mut self, seconds: u64) -> Self {
        self.command_timeout_secs = seconds;
        self
    }

    pub fn recovery_secs(mut self, seconds: u64) -> Self {
        self.recovery_secs = seconds;
        self
    }

    pub fn is_configured(&self) -> bool {
        !self.url.trim().is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::{RedisConfig, DEFAULT_KEY_PREFIX};

    #[test]
    fn an_empty_url_means_single_process_mode() {
        assert!(!RedisConfig::default().is_configured());
        assert!(!RedisConfig::new("   ").is_configured());
        assert!(RedisConfig::new("redis://127.0.0.1:6379/0").is_configured());
    }

    #[test]
    fn an_empty_prefix_falls_back_to_the_project_default() {
        assert_eq!(
            RedisConfig::new("redis://x").key_prefix("").key_prefix,
            DEFAULT_KEY_PREFIX
        );
    }

    #[test]
    fn a_pool_always_has_at_least_one_connection() {
        assert_eq!(RedisConfig::new("redis://x").pool_size(0).pool_size, 1);
    }
}

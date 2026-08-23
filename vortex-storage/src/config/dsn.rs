pub const DEFAULT_POOL_SIZE: u32 = 10;
pub const DEFAULT_CONNECT_TIMEOUT_SECS: u64 = 5;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PgConfig {
    pub url: String,
    pub pool_size: u32,
    pub connect_timeout_secs: u64,
}

impl Default for PgConfig {
    fn default() -> Self {
        PgConfig {
            url: String::new(),
            pool_size: DEFAULT_POOL_SIZE,
            connect_timeout_secs: DEFAULT_CONNECT_TIMEOUT_SECS,
        }
    }
}

impl PgConfig {
    pub fn new(url: impl Into<String>) -> Self {
        PgConfig {
            url: url.into(),
            ..PgConfig::default()
        }
    }

    pub fn pool_size(mut self, connections: u32) -> Self {
        self.pool_size = connections.max(1);
        self
    }

    pub fn connect_timeout_secs(mut self, seconds: u64) -> Self {
        self.connect_timeout_secs = seconds;
        self
    }

    pub fn is_configured(&self) -> bool {
        !self.url.trim().is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::PgConfig;

    #[test]
    fn an_empty_url_means_no_postgres() {
        assert!(!PgConfig::default().is_configured());
        assert!(!PgConfig::new("   ").is_configured());
        assert!(PgConfig::new("postgres://localhost/vortex").is_configured());
    }

    #[test]
    fn a_pool_always_has_at_least_one_connection() {
        assert_eq!(PgConfig::new("postgres://x").pool_size(0).pool_size, 1);
    }
}

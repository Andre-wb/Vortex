pub const DEFAULT_PORT: u16 = 443;
pub const DEFAULT_UPSTREAM: &str = "http://127.0.0.1:8000";
pub const DEFAULT_ACME_EMAIL: &str = "admin@example.com";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NaiveConfig {
    pub port: u16,
    pub upstream: String,
    pub server_host: String,
}

impl Default for NaiveConfig {
    fn default() -> Self {
        NaiveConfig {
            port: DEFAULT_PORT,
            upstream: String::new(),
            server_host: String::new(),
        }
    }
}

impl NaiveConfig {
    pub fn new(port: u16, upstream: impl Into<String>, server_host: impl Into<String>) -> Self {
        NaiveConfig {
            port,
            upstream: upstream.into(),
            server_host: server_host.into(),
        }
    }

    pub fn upstream_or_default(&self) -> &str {
        if self.upstream.is_empty() {
            DEFAULT_UPSTREAM
        } else {
            &self.upstream
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{NaiveConfig, DEFAULT_PORT, DEFAULT_UPSTREAM};

    #[test]
    fn a_configuration_that_names_nothing_serves_https_on_the_local_backend() {
        let config = NaiveConfig::default();
        assert_eq!(config.port, DEFAULT_PORT);
        assert_eq!(config.upstream_or_default(), DEFAULT_UPSTREAM);
    }

    #[test]
    fn a_named_backend_wins_over_the_default() {
        let config = NaiveConfig::new(8443, "http://10.0.0.2:9000", "proxy.example.com");
        assert_eq!(config.upstream_or_default(), "http://10.0.0.2:9000");
        assert_eq!(config.server_host, "proxy.example.com");
    }
}

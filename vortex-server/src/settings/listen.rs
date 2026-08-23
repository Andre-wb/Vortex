use std::net::SocketAddr;

use crate::settings::environment;

pub const DEFAULT_HOST: &str = "127.0.0.1";
pub const DEFAULT_PORT: u16 = 9100;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListenAddress {
    host: String,
    port: u16,
}

impl Default for ListenAddress {
    fn default() -> Self {
        ListenAddress {
            host: DEFAULT_HOST.to_string(),
            port: DEFAULT_PORT,
        }
    }
}

impl ListenAddress {
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        ListenAddress {
            host: host.into(),
            port,
        }
    }

    pub fn from_environment() -> Self {
        ListenAddress::new(
            environment::text_or("VORTEX_RUST_HOST", DEFAULT_HOST),
            environment::number_or("VORTEX_RUST_PORT", DEFAULT_PORT),
        )
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn resolve(&self) -> Option<SocketAddr> {
        format!("{}:{}", self.host, self.port).parse().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::{ListenAddress, DEFAULT_HOST, DEFAULT_PORT};

    #[test]
    fn the_default_listener_is_loopback_on_its_own_port() {
        let address = ListenAddress::default();
        assert_eq!(address.host(), DEFAULT_HOST);
        assert_eq!(address.port(), DEFAULT_PORT);
        assert_ne!(address.port(), 9000);
    }

    #[test]
    fn a_literal_address_resolves_without_a_name_lookup() {
        assert_eq!(
            ListenAddress::new("127.0.0.1", 9100).resolve(),
            Some("127.0.0.1:9100".parse().unwrap())
        );
        assert_eq!(ListenAddress::new("не адрес", 9100).resolve(), None);
    }
}

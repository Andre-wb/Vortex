//! Адрес источника = адрес TCP-пира.
//!
//! Реализация по умолчанию: заголовки не читаются вовсе, подделать источник
//! невозможно.

use crate::domain::client_ip::ClientIp;
use crate::domain::header_map::HeaderMap;
use crate::ports::client_ip_resolver::ClientIpResolver;

#[derive(Debug, Clone, Copy, Default)]
pub struct PeerAddressResolver;

impl PeerAddressResolver {
    pub fn new() -> Self {
        PeerAddressResolver
    }
}

impl ClientIpResolver for PeerAddressResolver {
    fn resolve(&self, peer: Option<&str>, _headers: &HeaderMap) -> ClientIp {
        peer.map(ClientIp::from).unwrap_or_else(ClientIp::unknown)
    }
}

#[cfg(test)]
mod tests {
    use super::PeerAddressResolver;
    use crate::domain::header_map::HeaderMap;
    use crate::ports::client_ip_resolver::ClientIpResolver;

    #[test]
    fn forwarded_headers_are_ignored() {
        let headers: HeaderMap = [("x-forwarded-for", "1.2.3.4")].into_iter().collect();
        let ip = PeerAddressResolver::new().resolve(Some("10.0.0.9"), &headers);
        assert_eq!(ip.as_str(), "10.0.0.9");
    }

    #[test]
    fn missing_peer_becomes_unknown() {
        let ip = PeerAddressResolver::new().resolve(None, &HeaderMap::new());
        assert_eq!(ip.as_str(), "unknown");
    }
}

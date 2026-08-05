//! Адрес источника из заголовков — только за доверенным прокси.
//!
//! Декоратор над другим резолвером: если TCP-пир не входит в список доверенных
//! сетей, поведение полностью совпадает с вложенной реализацией. Список пуст по
//! умолчанию, поэтому подделать `X-Forwarded-For` нельзя.

use crate::domain::client_ip::ClientIp;
use crate::domain::header_map::HeaderMap;
use crate::http::client_ip::networks::{parse_networks, IpNetwork};
use crate::ports::client_ip_resolver::ClientIpResolver;
use std::sync::Arc;

/// Заголовки в порядке приоритета.
pub const FORWARD_HEADERS: &[&str] = &["x-forwarded-for", "x-real-ip", "cf-connecting-ip"];

pub struct TrustedProxyResolver {
    networks: Vec<IpNetwork>,
    inner: Arc<dyn ClientIpResolver>,
}

impl TrustedProxyResolver {
    pub fn new<I, S>(entries: I, inner: Arc<dyn ClientIpResolver>) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        TrustedProxyResolver {
            networks: parse_networks(entries),
            inner,
        }
    }

    pub fn trusts(&self, ip: &ClientIp) -> bool {
        if self.networks.is_empty() {
            return false;
        }
        match ip.parsed() {
            Some(addr) => self.networks.iter().any(|net| net.contains(&addr)),
            None => false,
        }
    }
}

impl ClientIpResolver for TrustedProxyResolver {
    fn resolve(&self, peer: Option<&str>, headers: &HeaderMap) -> ClientIp {
        let direct = self.inner.resolve(peer, headers);
        if !self.trusts(&direct) {
            return direct;
        }
        for header in FORWARD_HEADERS {
            let Some(raw) = headers.get(header) else {
                continue;
            };
            // Первый адрес цепочки — исходный клиент.
            let candidate = ClientIp::from(raw.split(',').next().unwrap_or("").trim());
            if candidate.is_valid_ip() {
                return candidate;
            }
        }
        direct
    }
}

#[cfg(test)]
mod tests {
    use super::TrustedProxyResolver;
    use crate::domain::header_map::HeaderMap;
    use crate::http::client_ip::peer_address::PeerAddressResolver;
    use crate::ports::client_ip_resolver::ClientIpResolver;
    use std::sync::Arc;

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        pairs.iter().copied().collect()
    }

    fn resolver(trusted: &[&str]) -> TrustedProxyResolver {
        TrustedProxyResolver::new(trusted.to_vec(), Arc::new(PeerAddressResolver::new()))
    }

    #[test]
    fn empty_allowlist_never_trusts_headers() {
        let ip = resolver(&[]).resolve(
            Some("10.0.0.5"),
            &headers(&[("x-forwarded-for", "1.2.3.4")]),
        );
        assert_eq!(ip.as_str(), "10.0.0.5");
    }

    #[test]
    fn trusted_proxy_headers_are_honored() {
        let ip = resolver(&["10.0.0.0/8"]).resolve(
            Some("10.0.0.5"),
            &headers(&[("x-forwarded-for", "203.0.113.9, 10.0.0.5")]),
        );
        assert_eq!(ip.as_str(), "203.0.113.9");
    }

    #[test]
    fn untrusted_peer_keeps_its_own_address() {
        let ip = resolver(&["10.0.0.0/8"]).resolve(
            Some("192.168.1.7"),
            &headers(&[("x-forwarded-for", "203.0.113.9")]),
        );
        assert_eq!(ip.as_str(), "192.168.1.7");
    }

    #[test]
    fn header_priority_follows_the_list() {
        let ip = resolver(&["10.0.0.5"]).resolve(
            Some("10.0.0.5"),
            &headers(&[
                ("x-real-ip", "198.51.100.4"),
                ("cf-connecting-ip", "1.1.1.1"),
            ]),
        );
        assert_eq!(ip.as_str(), "198.51.100.4");
    }

    #[test]
    fn garbage_header_falls_back_to_the_peer() {
        let ip = resolver(&["10.0.0.5"]).resolve(
            Some("10.0.0.5"),
            &headers(&[("x-forwarded-for", "не-адрес")]),
        );
        assert_eq!(ip.as_str(), "10.0.0.5");
    }
}

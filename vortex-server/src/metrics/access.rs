use std::net::IpAddr;

use http::HeaderMap;

use crate::settings::metrics::MetricsToken;

pub const BEARER: &str = "Bearer ";

pub fn allowed(peer: Option<IpAddr>, headers: &HeaderMap, token: &MetricsToken) -> bool {
    if peer.map(local_network).unwrap_or(false) {
        return true;
    }
    presented(headers)
        .map(|secret| token.matches(secret))
        .unwrap_or(false)
}

pub fn local_network(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_private() || v4.is_link_local(),
        IpAddr::V6(v6) => {
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return mapped.is_loopback() || mapped.is_private() || mapped.is_link_local();
            }
            v6.is_loopback() || unique_local(v6) || link_local(v6)
        }
    }
}

fn unique_local(address: std::net::Ipv6Addr) -> bool {
    address.octets()[0] & 0xfe == 0xfc
}

fn link_local(address: std::net::Ipv6Addr) -> bool {
    let octets = address.octets();
    octets[0] == 0xfe && octets[1] & 0xc0 == 0x80
}

fn presented(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix(BEARER))
        .map(|value| value.trim())
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use http::header::{HeaderMap, HeaderValue};

    use super::{allowed, local_network};
    use crate::settings::metrics::MetricsToken;

    fn bearer(secret: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {secret}")).unwrap(),
        );
        headers
    }

    #[test]
    fn a_local_scraper_needs_no_token() {
        let token = MetricsToken::default();
        for address in ["127.0.0.1", "10.1.2.3", "192.168.0.5", "::1", "fd00::1"] {
            let peer: IpAddr = address.parse().unwrap();
            assert!(local_network(peer), "{address}");
            assert!(allowed(Some(peer), &HeaderMap::new(), &token), "{address}");
        }
    }

    #[test]
    fn a_public_scraper_without_a_token_is_refused() {
        let peer: IpAddr = "203.0.113.7".parse().unwrap();
        assert!(!local_network(peer));
        assert!(!allowed(
            Some(peer),
            &HeaderMap::new(),
            &MetricsToken::new("s3cret")
        ));
    }

    #[test]
    fn a_public_scraper_with_the_right_token_is_admitted() {
        let peer: IpAddr = "203.0.113.7".parse().unwrap();
        let token = MetricsToken::new("s3cret");
        assert!(allowed(Some(peer), &bearer("s3cret"), &token));
        assert!(!allowed(Some(peer), &bearer("другой"), &token));
    }

    #[test]
    fn an_unknown_peer_without_a_token_is_refused() {
        assert!(!allowed(None, &HeaderMap::new(), &MetricsToken::default()));
    }

    #[test]
    fn a_mapped_loopback_address_counts_as_local() {
        let peer: IpAddr = "::ffff:127.0.0.1".parse().unwrap();
        assert!(local_network(peer));
    }
}

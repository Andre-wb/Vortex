use http::header::{HeaderMap, HeaderName};

pub const HOP_BY_HOP: [HeaderName; 8] = [
    http::header::CONNECTION,
    HeaderName::from_static("keep-alive"),
    http::header::PROXY_AUTHENTICATE,
    http::header::PROXY_AUTHORIZATION,
    http::header::TE,
    http::header::TRAILER,
    http::header::TRANSFER_ENCODING,
    http::header::UPGRADE,
];

pub fn is_hop_by_hop(name: &HeaderName) -> bool {
    HOP_BY_HOP.iter().any(|hop| hop == name)
}

pub fn end_to_end(headers: &HeaderMap) -> HeaderMap {
    let mut kept = HeaderMap::with_capacity(headers.len());
    for (name, value) in headers {
        if is_hop_by_hop(name) || name == http::header::HOST {
            continue;
        }
        kept.append(name.clone(), value.clone());
    }
    kept
}

pub fn for_upgrade(headers: &HeaderMap) -> HeaderMap {
    let mut kept = HeaderMap::with_capacity(headers.len());
    for (name, value) in headers {
        let handshake = name == http::header::CONNECTION || name == http::header::UPGRADE;
        if name == http::header::HOST || (is_hop_by_hop(name) && !handshake) {
            continue;
        }
        kept.append(name.clone(), value.clone());
    }
    kept
}

#[cfg(test)]
mod tests {
    use http::header::{HeaderMap, HeaderValue};

    use super::{end_to_end, for_upgrade, is_hop_by_hop};

    #[test]
    fn the_eight_hop_headers_never_cross_the_proxy() {
        for name in super::HOP_BY_HOP {
            assert!(is_hop_by_hop(&name), "{name}");
        }
        assert!(!is_hop_by_hop(&http::header::AUTHORIZATION));
    }

    #[test]
    fn the_host_of_the_edge_is_not_forwarded_to_the_upstream() {
        let mut headers = HeaderMap::new();
        headers.insert(http::header::HOST, HeaderValue::from_static("edge:9100"));
        headers.insert(
            http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer x"),
        );
        headers.insert(http::header::CONNECTION, HeaderValue::from_static("close"));
        let kept = end_to_end(&headers);
        assert!(!kept.contains_key(http::header::HOST));
        assert!(!kept.contains_key(http::header::CONNECTION));
        assert!(kept.contains_key(http::header::AUTHORIZATION));
    }

    #[test]
    fn the_handshake_headers_survive_only_on_the_upgrade_path() {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONNECTION,
            HeaderValue::from_static("Upgrade"),
        );
        headers.insert(http::header::UPGRADE, HeaderValue::from_static("websocket"));
        headers.insert(http::header::TE, HeaderValue::from_static("trailers"));
        let kept = for_upgrade(&headers);
        assert!(kept.contains_key(http::header::CONNECTION));
        assert!(kept.contains_key(http::header::UPGRADE));
        assert!(!kept.contains_key(http::header::TE));
        assert!(!end_to_end(&headers).contains_key(http::header::UPGRADE));
    }

    #[test]
    fn a_repeated_header_keeps_every_value() {
        let mut headers = HeaderMap::new();
        headers.append(http::header::COOKIE, HeaderValue::from_static("a=1"));
        headers.append(http::header::COOKIE, HeaderValue::from_static("b=2"));
        assert_eq!(
            end_to_end(&headers)
                .get_all(http::header::COOKIE)
                .iter()
                .count(),
            2
        );
    }
}

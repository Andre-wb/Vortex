use http::HeaderMap;

pub fn requests_websocket(headers: &HeaderMap) -> bool {
    let upgrade = headers
        .get(http::header::UPGRADE)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false);
    upgrade && connection_mentions_upgrade(headers)
}

fn connection_mentions_upgrade(headers: &HeaderMap) -> bool {
    headers
        .get_all(http::header::CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .any(|value| {
            value
                .split(',')
                .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
        })
}

#[cfg(test)]
mod tests {
    use http::header::{HeaderMap, HeaderValue};

    use super::requests_websocket;

    fn headers(connection: &'static str, upgrade: &'static str) -> HeaderMap {
        let mut map = HeaderMap::new();
        map.insert(
            http::header::CONNECTION,
            HeaderValue::from_static(connection),
        );
        map.insert(http::header::UPGRADE, HeaderValue::from_static(upgrade));
        map
    }

    #[test]
    fn both_headers_are_required_and_the_case_does_not_matter() {
        assert!(requests_websocket(&headers("Upgrade", "websocket")));
        assert!(requests_websocket(&headers("upgrade", "WebSocket")));
        assert!(!requests_websocket(&headers("close", "websocket")));
        assert!(!requests_websocket(&HeaderMap::new()));
    }

    #[test]
    fn a_connection_list_is_read_token_by_token() {
        assert!(requests_websocket(&headers(
            "keep-alive, Upgrade",
            "websocket"
        )));
        assert!(!requests_websocket(&headers("keep-alive", "websocket")));
    }

    #[test]
    fn only_the_websocket_protocol_is_bridged_here() {
        assert!(!requests_websocket(&headers("Upgrade", "h2c")));
    }
}

use crate::domain::content_type::ContentType;
use crate::domain::http_method::HttpMethod;
use crate::domain::request::InspectedRequest;
use crate::http::raw_request::RawHttpRequest;
use crate::ports::client_ip_resolver::ClientIpResolver;
use crate::util::query::parse_qs;
use crate::util::utf8::decode_dropping_invalid;
use std::sync::Arc;

pub struct RequestFactory {
    ip_resolver: Arc<dyn ClientIpResolver>,
}

impl RequestFactory {
    pub fn new(ip_resolver: Arc<dyn ClientIpResolver>) -> Self {
        RequestFactory { ip_resolver }
    }

    pub fn build(&self, raw: &RawHttpRequest) -> InspectedRequest {
        let client_ip = self.ip_resolver.resolve(raw.peer.as_deref(), &raw.headers);
        let url = if raw.query.is_empty() {
            raw.path.clone()
        } else {
            format!("{}?{}", raw.path, raw.query)
        };
        let content_type = raw
            .headers
            .get("content-type")
            .map(ContentType::from)
            .unwrap_or_else(ContentType::empty);
        InspectedRequest {
            client_ip,
            method: HttpMethod::parse(&raw.method),
            path: raw.path.clone(),
            url,
            headers: raw.headers.clone(),
            params: parse_qs(&raw.query),
            content_type,
            body: decode_dropping_invalid(&raw.body),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::RequestFactory;
    use crate::http::client_ip::peer_address::PeerAddressResolver;
    use crate::http::raw_request::RawHttpRequest;
    use std::sync::Arc;

    fn factory() -> RequestFactory {
        RequestFactory::new(Arc::new(PeerAddressResolver::new()))
    }

    #[test]
    fn assembles_all_fields() {
        let raw = RawHttpRequest::post("/api/send", b"{\"a\":1}".to_vec())
            .with_peer("203.0.113.5")
            .with_query("draft=1")
            .with_content_type("application/json");
        let req = factory().build(&raw);

        assert_eq!(req.client_ip.as_str(), "203.0.113.5");
        assert_eq!(req.url, "/api/send?draft=1");
        assert!(req.content_type.is_json());
        assert_eq!(req.params.get("draft").map(|v| v[0].as_str()), Some("1"));
        assert_eq!(req.body, "{\"a\":1}");
    }

    #[test]
    fn invalid_utf8_body_is_dropped_not_rejected() {
        let raw = RawHttpRequest::post("/x", vec![0xff, 0xfe]);
        assert_eq!(factory().build(&raw).body, "");
    }

    #[test]
    fn a_payload_split_by_invalid_bytes_still_matches() {
        let raw = RawHttpRequest::post("/x", b"<scr\xffipt>".to_vec());
        assert_eq!(factory().build(&raw).body, "<script>");
    }
}

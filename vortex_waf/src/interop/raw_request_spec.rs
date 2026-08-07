use crate::domain::header_map::HeaderMap;
use crate::http::raw_request::RawHttpRequest;
use crate::http::request_head::RequestHead;
use crate::util::latin1;

#[derive(Debug, Clone, Default)]
pub struct RawRequestSpec {
    pub method: String,
    pub path: String,
    pub query_string: Vec<u8>,
    pub headers: Vec<(Vec<u8>, Vec<u8>)>,
    pub peer: Option<String>,
    pub content_length: Option<usize>,
    pub body: Vec<u8>,
}

impl RawRequestSpec {
    pub fn into_raw_request(self) -> RawHttpRequest {
        let headers: HeaderMap = self
            .headers
            .iter()
            .map(|(name, value)| (latin1::decode(name), latin1::decode(value)))
            .collect();
        RawHttpRequest {
            method: self.method,
            path: self.path,
            query: latin1::decode(&self.query_string),
            headers,
            peer: self.peer,
            content_length: self.content_length,
            body: self.body,
        }
    }
}

impl From<&RawRequestSpec> for RequestHead {
    fn from(spec: &RawRequestSpec) -> Self {
        RequestHead {
            method: spec.method.clone(),
            path: spec.path.clone(),
            content_length: spec.content_length,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::RawRequestSpec;

    #[test]
    fn header_names_are_normalized_and_values_decoded() {
        let spec = RawRequestSpec {
            method: "POST".to_owned(),
            path: "/api/send".to_owned(),
            query_string: b"draft=1".to_vec(),
            headers: vec![
                (b"Content-Type".to_vec(), b"application/json".to_vec()),
                (b"X-Note".to_vec(), vec![0xff]),
            ],
            peer: Some("203.0.113.5".to_owned()),
            content_length: Some(2),
            body: b"{}".to_vec(),
        };
        let raw = spec.into_raw_request();

        assert_eq!(raw.headers.get("content-type"), Some("application/json"));
        assert_eq!(raw.headers.get("x-note"), Some("\u{ff}"));
        assert_eq!(raw.query, "draft=1");
        assert_eq!(raw.declared_length(), 2);
    }

    #[test]
    fn the_head_is_taken_without_consuming_the_body() {
        let spec = RawRequestSpec {
            method: "PUT".to_owned(),
            path: "/api/rooms/7".to_owned(),
            content_length: Some(1024),
            ..Default::default()
        };
        let head = crate::http::request_head::RequestHead::from(&spec);
        assert_eq!(head.method, "PUT");
        assert_eq!(head.declared_length(), 1024);
        assert_eq!(spec.body.len(), 0);
    }
}

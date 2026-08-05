//! Запрос в терминах транспорта, до превращения в `InspectedRequest`.

use crate::domain::header_map::HeaderMap;

#[derive(Debug, Clone, Default)]
pub struct RawHttpRequest {
    pub method: String,
    pub path: String,
    pub query: String,
    pub headers: HeaderMap,
    /// Адрес TCP-пира, если он известен.
    pub peer: Option<String>,
    /// Значение заголовка `Content-Length`, если он передан.
    pub content_length: Option<usize>,
    pub body: Vec<u8>,
}

impl RawHttpRequest {
    pub fn get(path: impl Into<String>) -> Self {
        RawHttpRequest {
            method: "GET".to_owned(),
            path: path.into(),
            ..Default::default()
        }
    }

    pub fn post(path: impl Into<String>, body: impl Into<Vec<u8>>) -> Self {
        let body = body.into();
        RawHttpRequest {
            method: "POST".to_owned(),
            path: path.into(),
            content_length: Some(body.len()),
            body,
            ..Default::default()
        }
    }

    pub fn with_peer(mut self, peer: impl Into<String>) -> Self {
        self.peer = Some(peer.into());
        self
    }

    pub fn with_query(mut self, query: impl Into<String>) -> Self {
        self.query = query.into();
        self
    }

    pub fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers.insert(name, value);
        self
    }

    pub fn with_content_type(self, value: &str) -> Self {
        self.with_header("content-type", value)
    }

    /// Заявленный размер тела: `Content-Length`, иначе фактическая длина.
    pub fn declared_length(&self) -> usize {
        self.content_length.unwrap_or(self.body.len())
    }
}

#[cfg(test)]
mod tests {
    use super::RawHttpRequest;

    #[test]
    fn post_fills_content_length() {
        let req = RawHttpRequest::post("/api/messages", b"hello".to_vec());
        assert_eq!(req.declared_length(), 5);
    }

    #[test]
    fn declared_length_falls_back_to_the_body() {
        let mut req = RawHttpRequest::post("/x", b"abc".to_vec());
        req.content_length = None;
        assert_eq!(req.declared_length(), 3);
    }
}

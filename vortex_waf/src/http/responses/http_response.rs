//! Ответ, который транспорт отдаёт клиенту вместо обработки запроса.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpResponse {
    pub fn json(status: u16, body: Vec<u8>) -> Self {
        HttpResponse {
            status,
            headers: vec![("content-type".to_owned(), "application/json".to_owned())],
            body,
        }
    }

    pub fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_owned(), value.to_owned()));
        self
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    pub fn body_as_str(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

//! Пошаговая сборка `InspectedRequest`.

use crate::domain::client_ip::ClientIp;
use crate::domain::content_type::ContentType;
use crate::domain::header_map::HeaderMap;
use crate::domain::http_method::HttpMethod;
use crate::domain::param_map::ParamMap;
use crate::domain::request::InspectedRequest;

#[derive(Debug, Clone)]
pub struct RequestBuilder {
    client_ip: ClientIp,
    method: HttpMethod,
    path: String,
    query: String,
    headers: HeaderMap,
    params: ParamMap,
    body: String,
}

impl Default for RequestBuilder {
    fn default() -> Self {
        RequestBuilder {
            client_ip: ClientIp::unknown(),
            method: HttpMethod::Get,
            path: "/".to_owned(),
            query: String::new(),
            headers: HeaderMap::new(),
            params: ParamMap::new(),
            body: String::new(),
        }
    }
}

impl RequestBuilder {
    pub fn new() -> Self {
        RequestBuilder::default()
    }

    pub fn client_ip(mut self, ip: impl Into<ClientIp>) -> Self {
        self.client_ip = ip.into();
        self
    }

    pub fn method(mut self, method: &str) -> Self {
        self.method = HttpMethod::parse(method);
        self
    }

    pub fn path(mut self, path: impl Into<String>) -> Self {
        self.path = path.into();
        self
    }

    /// Строка запроса без ведущего `?`; параметры разбираются автоматически.
    pub fn query(mut self, query: impl Into<String>) -> Self {
        self.query = query.into();
        self.params = crate::util::query::parse_qs(&self.query);
        self
    }

    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.insert(name, value);
        self
    }

    pub fn body(mut self, body: impl Into<String>) -> Self {
        self.body = body.into();
        self
    }

    pub fn content_type(self, value: &str) -> Self {
        self.header("content-type", value)
    }

    pub fn build(self) -> InspectedRequest {
        let url = if self.query.is_empty() {
            self.path.clone()
        } else {
            format!("{}?{}", self.path, self.query)
        };
        let content_type = self
            .headers
            .get("content-type")
            .map(ContentType::from)
            .unwrap_or_else(ContentType::empty);
        InspectedRequest {
            client_ip: self.client_ip,
            method: self.method,
            path: self.path,
            url,
            headers: self.headers,
            params: self.params,
            content_type,
            body: self.body,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::RequestBuilder;

    #[test]
    fn assembles_url_and_params_from_query() {
        let req = RequestBuilder::new()
            .path("/search")
            .query("q=hello&q=world")
            .build();
        assert_eq!(req.url, "/search?q=hello&q=world");
        assert_eq!(req.params.get("q").map(<[String]>::len), Some(2));
    }

    #[test]
    fn content_type_comes_from_headers() {
        let req = RequestBuilder::new()
            .content_type("application/json")
            .build();
        assert!(req.content_type.is_json());
    }
}

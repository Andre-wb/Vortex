//! Запрос в том виде, в каком его получают инспекторы.

use crate::domain::client_ip::ClientIp;
use crate::domain::content_type::ContentType;
use crate::domain::header_map::HeaderMap;
use crate::domain::http_method::HttpMethod;
use crate::domain::param_map::ParamMap;

#[derive(Debug, Clone)]
pub struct InspectedRequest {
    pub client_ip: ClientIp,
    pub method: HttpMethod,
    pub path: String,
    pub url: String,
    pub headers: HeaderMap,
    pub params: ParamMap,
    pub content_type: ContentType,
    pub body: String,
}

impl InspectedRequest {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name)
    }

    pub fn has_body(&self) -> bool {
        !self.body.is_empty()
    }
}

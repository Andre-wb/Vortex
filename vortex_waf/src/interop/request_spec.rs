//! Описание запроса в примитивных типах — то, что приходит извне крейта.
//!
//! Слой без зависимостей от конкретного языка привязки: разбор словаря делает
//! биндинг, а превращение в предмет анализа и все умолчания живут здесь и
//! проверяются обычными тестами.

use crate::domain::client_ip::ClientIp;
use crate::domain::content_type::ContentType;
use crate::domain::header_map::HeaderMap;
use crate::domain::http_method::HttpMethod;
use crate::domain::param_map::ParamMap;
use crate::domain::request::InspectedRequest;

#[derive(Debug, Clone, Default)]
pub struct RequestSpec {
    pub client_ip: Option<String>,
    pub method: Option<String>,
    pub path: Option<String>,
    pub url: Option<String>,
    pub headers: Vec<(String, String)>,
    /// Пары «имя параметра — значение»; многозначные параметры повторяются.
    pub params: Vec<(String, String)>,
    pub content_type: Option<String>,
    pub body: Option<String>,
}

impl RequestSpec {
    /// Умолчания повторяют прежний Python-движок: отсутствующий адрес — это
    /// `unknown`, отсутствующий метод — пустая строка (заведомо нестандартная),
    /// отсутствующий путь — пустая строка.
    pub fn into_request(self) -> InspectedRequest {
        let mut headers = HeaderMap::new();
        for (name, value) in self.headers {
            headers.insert(name, value);
        }

        let mut params = ParamMap::new();
        for (name, value) in self.params {
            params.push(name, value);
        }

        // Content-Type берётся из явного поля, иначе из заголовков.
        let content_type = self
            .content_type
            .or_else(|| headers.get("content-type").map(str::to_owned))
            .map(ContentType::new)
            .unwrap_or_else(ContentType::empty);

        let path = self.path.unwrap_or_default();
        let url = self.url.unwrap_or_else(|| path.clone());

        InspectedRequest {
            client_ip: self
                .client_ip
                .map(ClientIp::new)
                .unwrap_or_else(ClientIp::unknown),
            method: HttpMethod::parse(&self.method.unwrap_or_default()),
            path,
            url,
            headers,
            params,
            content_type,
            body: self.body.unwrap_or_default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::RequestSpec;
    use crate::domain::http_method::HttpMethod;

    #[test]
    fn empty_spec_yields_safe_defaults() {
        let request = RequestSpec::default().into_request();
        assert_eq!(request.client_ip.as_str(), "unknown");
        assert!(!request.method.is_standard());
        assert_eq!(request.path, "");
        assert_eq!(request.url, "");
        assert!(request.body.is_empty());
        assert!(request.content_type.is_empty());
    }

    #[test]
    fn url_defaults_to_the_path() {
        let spec = RequestSpec {
            path: Some("/api/ping".to_owned()),
            ..Default::default()
        };
        assert_eq!(spec.into_request().url, "/api/ping");
    }

    #[test]
    fn content_type_falls_back_to_the_header() {
        let spec = RequestSpec {
            headers: vec![("Content-Type".to_owned(), "application/json".to_owned())],
            ..Default::default()
        };
        assert!(spec.into_request().content_type.is_json());
    }

    #[test]
    fn explicit_content_type_wins_over_the_header() {
        let spec = RequestSpec {
            headers: vec![("content-type".to_owned(), "text/plain".to_owned())],
            content_type: Some("application/json".to_owned()),
            ..Default::default()
        };
        assert!(spec.into_request().content_type.is_json());
    }

    #[test]
    fn repeated_parameters_are_preserved() {
        let spec = RequestSpec {
            params: vec![
                ("id".to_owned(), "1".to_owned()),
                ("id".to_owned(), "2".to_owned()),
            ],
            ..Default::default()
        };
        let request = spec.into_request();
        assert_eq!(request.params.get("id").map(<[String]>::len), Some(2));
    }

    #[test]
    fn method_is_normalized() {
        let spec = RequestSpec {
            method: Some("post".to_owned()),
            ..Default::default()
        };
        assert_eq!(spec.into_request().method, HttpMethod::Post);
    }
}

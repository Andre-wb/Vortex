//! HTTP-метод запроса.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
    Patch,
    Head,
    Options,
    /// Всё, что не входит в список разрешённых, — включая пустую строку.
    Other(String),
}

impl HttpMethod {
    pub fn parse(raw: &str) -> Self {
        match raw.to_ascii_uppercase().as_str() {
            "GET" => HttpMethod::Get,
            "POST" => HttpMethod::Post,
            "PUT" => HttpMethod::Put,
            "DELETE" => HttpMethod::Delete,
            "PATCH" => HttpMethod::Patch,
            "HEAD" => HttpMethod::Head,
            "OPTIONS" => HttpMethod::Options,
            other => HttpMethod::Other(other.to_owned()),
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            HttpMethod::Get => "GET",
            HttpMethod::Post => "POST",
            HttpMethod::Put => "PUT",
            HttpMethod::Delete => "DELETE",
            HttpMethod::Patch => "PATCH",
            HttpMethod::Head => "HEAD",
            HttpMethod::Options => "OPTIONS",
            HttpMethod::Other(raw) => raw,
        }
    }

    pub fn is_standard(&self) -> bool {
        !matches!(self, HttpMethod::Other(_))
    }

    /// Методы, у которых тело запроса подлежит буферизации и анализу.
    pub fn carries_body(&self) -> bool {
        matches!(self, HttpMethod::Post | HttpMethod::Put | HttpMethod::Patch)
    }
}

impl fmt::Display for HttpMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::HttpMethod;

    #[test]
    fn normalizes_case() {
        assert_eq!(HttpMethod::parse("post"), HttpMethod::Post);
        assert!(HttpMethod::parse("post").carries_body());
    }

    #[test]
    fn unknown_method_is_not_standard() {
        let m = HttpMethod::parse("TRACE");
        assert!(!m.is_standard());
        assert_eq!(m.as_str(), "TRACE");
        assert!(!HttpMethod::parse("").is_standard());
    }
}

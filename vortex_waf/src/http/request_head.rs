use crate::domain::http_method::HttpMethod;

#[derive(Debug, Clone, Default)]
pub struct RequestHead {
    pub method: String,
    pub path: String,
    pub content_length: Option<usize>,
}

impl RequestHead {
    pub fn new(method: impl Into<String>, path: impl Into<String>) -> Self {
        RequestHead {
            method: method.into(),
            path: path.into(),
            content_length: None,
        }
    }

    pub fn with_content_length(mut self, bytes: usize) -> Self {
        self.content_length = Some(bytes);
        self
    }

    pub fn declared_length(&self) -> usize {
        self.content_length.unwrap_or(0)
    }

    pub fn declares_body(&self) -> bool {
        HttpMethod::parse(&self.method).carries_body() || self.declared_length() > 0
    }
}

#[cfg(test)]
mod tests {
    use super::RequestHead;

    #[test]
    fn missing_content_length_counts_as_empty() {
        assert_eq!(RequestHead::new("GET", "/api/chat").declared_length(), 0);
        assert_eq!(
            RequestHead::new("POST", "/api/chat")
                .with_content_length(17)
                .declared_length(),
            17
        );
    }

    #[test]
    fn write_methods_declare_a_body_even_without_the_header() {
        for method in ["POST", "PUT", "PATCH"] {
            assert!(RequestHead::new(method, "/api/chat").declares_body());
        }
    }

    #[test]
    fn a_declared_length_makes_any_method_carry_a_body() {
        assert!(!RequestHead::new("DELETE", "/api/chat").declares_body());
        assert!(RequestHead::new("DELETE", "/api/chat")
            .with_content_length(9)
            .declares_body());
        assert!(RequestHead::new("GET", "/api/chat")
            .with_content_length(9)
            .declares_body());
        assert!(!RequestHead::new("GET", "/api/chat")
            .with_content_length(0)
            .declares_body());
    }
}

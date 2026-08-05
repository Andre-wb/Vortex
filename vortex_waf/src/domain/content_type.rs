//! Значение заголовка `Content-Type`.

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ContentType(String);

impl ContentType {
    pub fn new(value: impl Into<String>) -> Self {
        ContentType(value.into())
    }

    pub fn empty() -> Self {
        ContentType(String::new())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Подстрочная проверка — так же, как это делал прежний Python-движок.
    pub fn contains(&self, needle: &str) -> bool {
        self.0
            .to_ascii_lowercase()
            .contains(&needle.to_ascii_lowercase())
    }

    pub fn is_json(&self) -> bool {
        self.contains("application/json")
    }

    pub fn is_multipart(&self) -> bool {
        self.contains("multipart/form-data")
    }

    pub fn is_form_urlencoded(&self) -> bool {
        self.contains("application/x-www-form-urlencoded")
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<&str> for ContentType {
    fn from(value: &str) -> Self {
        ContentType(value.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::ContentType;

    #[test]
    fn recognizes_families_with_parameters() {
        let ct = ContentType::from("multipart/form-data; boundary=----x");
        assert!(ct.is_multipart());
        assert!(!ct.is_json());
        assert!(ContentType::from("Application/JSON").is_json());
        assert!(ContentType::empty().is_empty());
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Handler {
    Rust,
    Python,
}

impl Handler {
    pub fn as_str(&self) -> &'static str {
        match self {
            Handler::Rust => "rust",
            Handler::Python => "python",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "rust" => Some(Handler::Rust),
            "python" => Some(Handler::Python),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Handler;

    #[test]
    fn the_two_spellings_round_trip() {
        for handler in [Handler::Rust, Handler::Python] {
            assert_eq!(Handler::parse(handler.as_str()), Some(handler));
        }
    }

    #[test]
    fn an_unknown_spelling_is_not_a_handler() {
        assert_eq!(Handler::parse("go"), None);
        assert_eq!(Handler::parse(""), None);
    }
}

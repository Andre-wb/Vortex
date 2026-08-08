#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    Http,
    Https,
}

impl Scheme {
    pub fn parse(value: &str) -> Option<Scheme> {
        if value.eq_ignore_ascii_case("http") {
            return Some(Scheme::Http);
        }
        if value.eq_ignore_ascii_case("https") {
            return Some(Scheme::Https);
        }
        None
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Scheme::Http => "http",
            Scheme::Https => "https",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Scheme;

    #[test]
    fn the_two_schemes_caddy_proxies_to_are_accepted() {
        assert_eq!(Scheme::parse("http"), Some(Scheme::Http));
        assert_eq!(Scheme::parse("HTTPS"), Some(Scheme::Https));
    }

    #[test]
    fn a_scheme_is_always_written_back_in_lower_case() {
        assert_eq!(Scheme::parse("HTTP").unwrap().as_str(), "http");
    }

    #[test]
    fn anything_else_is_refused() {
        for value in ["", "file", "unix", "ws", "http:"] {
            assert_eq!(Scheme::parse(value), None, "{value}");
        }
    }
}

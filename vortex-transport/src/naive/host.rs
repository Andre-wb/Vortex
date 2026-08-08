use crate::tls::server_name::plausible_host;
use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Host {
    Name(String),
    Address(IpAddr),
}

impl Host {
    pub fn parse(value: &str) -> Option<Host> {
        if let Some(inner) = value
            .strip_prefix('[')
            .and_then(|rest| rest.strip_suffix(']'))
        {
            return inner
                .parse::<IpAddr>()
                .ok()
                .filter(IpAddr::is_ipv6)
                .map(Host::Address);
        }
        if let Ok(address) = value.parse::<IpAddr>() {
            return Some(Host::Address(address));
        }
        plausible_host(value.as_bytes()).map(|name| Host::Name(name.to_owned()))
    }

    pub fn render(&self) -> String {
        match self {
            Host::Name(name) => name.clone(),
            Host::Address(IpAddr::V6(address)) => format!("[{address}]"),
            Host::Address(address) => address.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Host;

    #[test]
    fn a_name_survives_unchanged() {
        assert_eq!(
            Host::parse("proxy.example.com").unwrap().render(),
            "proxy.example.com"
        );
    }

    #[test]
    fn an_ipv4_literal_survives_unchanged() {
        assert_eq!(Host::parse("127.0.0.1").unwrap().render(), "127.0.0.1");
    }

    #[test]
    fn an_ipv6_literal_is_always_rendered_in_brackets() {
        assert_eq!(
            Host::parse("2001:db8::1").unwrap().render(),
            "[2001:db8::1]"
        );
        assert_eq!(
            Host::parse("[2001:db8::1]").unwrap().render(),
            "[2001:db8::1]"
        );
    }

    #[test]
    fn brackets_belong_to_ipv6_alone() {
        assert_eq!(Host::parse("[127.0.0.1]"), None);
        assert_eq!(Host::parse("[proxy.example.com]"), None);
        assert_eq!(Host::parse("[2001:db8::1"), None);
    }

    #[test]
    fn a_host_that_would_rewrite_the_url_is_refused() {
        for value in [
            "evil.test/path",
            "evil.test?q=1",
            "evil.test#fragment",
            "user@evil.test",
            "evil test",
            "evil.test\nrespond",
            "",
        ] {
            assert_eq!(Host::parse(value), None, "{value}");
        }
    }
}

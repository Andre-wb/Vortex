use crate::error::{Result, TransportError};
use crate::naive::host::Host;
use crate::naive::upstream::port;
use crate::naive::upstream::scheme::Scheme;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamUrl {
    pub scheme: Scheme,
    pub host: Host,
    pub port: Option<u16>,
}

impl UpstreamUrl {
    pub fn parse(value: &str) -> Result<UpstreamUrl> {
        split(value).ok_or_else(|| TransportError::NaiveUpstream(value.to_owned()))
    }

    pub fn render(&self) -> String {
        match self.port {
            Some(port) => format!("{}://{}:{}", self.scheme.as_str(), self.host.render(), port),
            None => format!("{}://{}", self.scheme.as_str(), self.host.render()),
        }
    }
}

fn split(value: &str) -> Option<UpstreamUrl> {
    let (scheme, authority) = value.split_once("://")?;
    let scheme = Scheme::parse(scheme)?;
    if authority.contains(['/', '?', '#', '@']) {
        return None;
    }
    let (host, port) = authority_parts(authority)?;
    Some(UpstreamUrl { scheme, host, port })
}

fn authority_parts(authority: &str) -> Option<(Host, Option<u16>)> {
    if let Some(rest) = authority.strip_prefix('[') {
        let (inside, tail) = rest.split_once(']')?;
        let host = Host::parse(&format!("[{inside}]"))?;
        if tail.is_empty() {
            return Some((host, None));
        }
        return Some((host, Some(port::parse(tail.strip_prefix(':')?)?)));
    }
    match authority.rsplit_once(':') {
        Some((host, port)) => Some((Host::parse(host)?, Some(port::parse(port)?))),
        None => Some((Host::parse(authority)?, None)),
    }
}

#[cfg(test)]
mod tests {
    use super::UpstreamUrl;
    use crate::error::TransportError;

    fn rendered(value: &str) -> String {
        UpstreamUrl::parse(value).unwrap().render()
    }

    #[test]
    fn the_shipped_backend_survives_a_round_trip() {
        assert_eq!(rendered("http://127.0.0.1:8000"), "http://127.0.0.1:8000");
    }

    #[test]
    fn a_named_backend_with_and_without_a_port_is_accepted() {
        assert_eq!(
            rendered("https://backend.internal"),
            "https://backend.internal"
        );
        assert_eq!(
            rendered("https://backend.internal:8443"),
            "https://backend.internal:8443"
        );
    }

    #[test]
    fn an_ipv6_backend_keeps_its_brackets() {
        assert_eq!(rendered("http://[::1]:8000"), "http://[::1]:8000");
        assert_eq!(rendered("http://[::1]"), "http://[::1]");
    }

    #[test]
    fn a_backend_with_a_path_is_refused_the_way_caddy_refuses_it() {
        assert!(matches!(
            UpstreamUrl::parse("http://127.0.0.1:8000/api"),
            Err(TransportError::NaiveUpstream(_))
        ));
        assert!(UpstreamUrl::parse("http://127.0.0.1:8000/").is_err());
    }

    #[test]
    fn a_backend_that_would_smuggle_a_directive_is_refused() {
        for value in [
            "http://127.0.0.1:8000 {\n    respond \"pwned\"\n}",
            "http://127.0.0.1:8000\nrespond",
            "http://user:pass@127.0.0.1:8000",
            "127.0.0.1:8000",
            "unix//run/app.sock",
            "http://",
            "",
        ] {
            assert!(UpstreamUrl::parse(value).is_err(), "{value}");
        }
    }

    #[test]
    fn a_backend_port_that_is_not_plain_digits_is_refused() {
        assert!(UpstreamUrl::parse("http://127.0.0.1:+8000").is_err());
        assert!(UpstreamUrl::parse("http://127.0.0.1:0").is_err());
    }
}

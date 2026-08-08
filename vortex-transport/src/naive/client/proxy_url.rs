use crate::naive::client::percent::encode_userinfo;
use crate::naive::credential::pair::Credentials;
use crate::naive::host::Host;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyUrl(String);

impl ProxyUrl {
    pub fn https(host: &Host, port: u16, credentials: &Credentials) -> ProxyUrl {
        ProxyUrl(format!(
            "https://{}:{}@{}:{}",
            encode_userinfo(credentials.username.as_str()),
            encode_userinfo(credentials.password.as_str()),
            host.render(),
            port
        ))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::ProxyUrl;
    use crate::naive::credential::pair::Credentials;
    use crate::naive::host::Host;

    fn url(username: &str, password: &str, host: &str) -> String {
        let credentials = Credentials::parse(username, password).unwrap();
        ProxyUrl::https(&Host::parse(host).unwrap(), 443, &credentials)
            .as_str()
            .to_owned()
    }

    #[test]
    fn a_generated_pair_reads_the_way_it_was_written() {
        assert_eq!(
            url("a3f9c2b1", "xK-_9Zq", "proxy.example.com"),
            "https://a3f9c2b1:xK-_9Zq@proxy.example.com:443"
        );
    }

    #[test]
    fn a_password_can_no_longer_move_the_authority() {
        assert_eq!(
            url("user", "p@ss/evil.test", "proxy.example.com"),
            "https://user:p%40ss%2Fevil.test@proxy.example.com:443"
        );
    }

    #[test]
    fn a_colon_in_the_password_no_longer_splits_the_userinfo() {
        assert_eq!(
            url("user", "a:b", "proxy.example.com"),
            "https://user:a%3Ab@proxy.example.com:443"
        );
    }

    #[test]
    fn an_ipv6_server_is_bracketed_so_the_port_stays_readable() {
        assert_eq!(
            url("user", "pass", "2001:db8::1"),
            "https://user:pass@[2001:db8::1]:443"
        );
    }
}

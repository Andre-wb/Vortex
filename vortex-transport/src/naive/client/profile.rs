use crate::naive::client::proxy_url::ProxyUrl;

pub const DEFAULT_LISTEN: &str = "socks://127.0.0.1:1080";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientProfile {
    pub listen: String,
    pub proxy: ProxyUrl,
    pub log: String,
    pub padding: bool,
}

impl ClientProfile {
    pub fn new(proxy: ProxyUrl) -> ClientProfile {
        ClientProfile {
            listen: DEFAULT_LISTEN.to_owned(),
            proxy,
            log: String::new(),
            padding: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ClientProfile, DEFAULT_LISTEN};
    use crate::naive::client::proxy_url::ProxyUrl;
    use crate::naive::credential::pair::Credentials;
    use crate::naive::host::Host;

    fn profile() -> ClientProfile {
        let credentials = Credentials::parse("user", "pass").unwrap();
        ClientProfile::new(ProxyUrl::https(
            &Host::parse("proxy.example.com").unwrap(),
            443,
            &credentials,
        ))
    }

    #[test]
    fn the_client_listens_on_the_local_socks_port() {
        assert_eq!(profile().listen, DEFAULT_LISTEN);
    }

    #[test]
    fn padding_is_on_because_naiveproxy_pads_by_default() {
        assert!(profile().padding);
    }

    #[test]
    fn logging_is_off_so_that_the_proxy_url_is_never_written_down() {
        assert_eq!(profile().log, "");
    }
}

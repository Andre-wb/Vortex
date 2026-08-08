use crate::error::{Result, TransportError};
use crate::naive::caddy::render;
use crate::naive::caddy::site::CaddySite;
use crate::naive::client::profile::ClientProfile;
use crate::naive::client::proxy_url::ProxyUrl;
use crate::naive::config::{NaiveConfig, DEFAULT_ACME_EMAIL};
use crate::naive::credential::pair::Credentials;
use crate::naive::host::Host;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Naive {
    config: NaiveConfig,
    username: String,
    password: String,
    probe_domain: String,
}

impl Naive {
    pub fn new(config: NaiveConfig) -> Self {
        Naive {
            config,
            username: String::new(),
            password: String::new(),
            probe_domain: String::new(),
        }
    }

    pub fn reload(&mut self, username: &str, password: &str, probe_domain: &str) {
        self.username = username.to_owned();
        self.password = password.to_owned();
        self.probe_domain = probe_domain.to_owned();
    }

    pub fn config(&self) -> &NaiveConfig {
        &self.config
    }

    pub fn username(&self) -> &str {
        &self.username
    }

    pub fn password(&self) -> &str {
        &self.password
    }

    pub fn probe_domain(&self) -> &str {
        &self.probe_domain
    }

    pub fn is_renderable(&self) -> bool {
        self.site(DEFAULT_ACME_EMAIL, "", "", "").is_ok()
    }

    pub fn caddyfile(
        &self,
        username: &str,
        password: &str,
        email: &str,
        probe_domain: &str,
    ) -> Result<String> {
        let email = fallback(email, DEFAULT_ACME_EMAIL);
        Ok(render::render(&self.site(
            email,
            username,
            password,
            probe_domain,
        )?))
    }

    pub fn proxy_url(&self, server_host: &str, username: &str, password: &str) -> Result<ProxyUrl> {
        if self.config.port == 0 {
            return Err(TransportError::NaivePort);
        }
        let requested = fallback(server_host, &self.config.server_host);
        let host = Host::parse(requested)
            .ok_or_else(|| TransportError::NaiveHost(requested.to_owned()))?;
        let credentials = self.credentials(username, password)?;
        Ok(ProxyUrl::https(&host, self.config.port, &credentials))
    }

    pub fn client_profile(
        &self,
        server_host: &str,
        username: &str,
        password: &str,
    ) -> Result<ClientProfile> {
        Ok(ClientProfile::new(self.proxy_url(
            server_host,
            username,
            password,
        )?))
    }

    fn site(
        &self,
        email: &str,
        username: &str,
        password: &str,
        probe_domain: &str,
    ) -> Result<CaddySite> {
        CaddySite::parse(
            self.config.port,
            email,
            fallback(username, &self.username),
            fallback(password, &self.password),
            fallback(probe_domain, &self.probe_domain),
            self.config.upstream_or_default(),
        )
    }

    fn credentials(&self, username: &str, password: &str) -> Result<Credentials> {
        Credentials::parse(
            fallback(username, &self.username),
            fallback(password, &self.password),
        )
    }
}

fn fallback<'a>(value: &'a str, stored: &'a str) -> &'a str {
    if value.is_empty() {
        stored
    } else {
        value
    }
}

#[cfg(test)]
mod tests {
    use super::Naive;
    use crate::error::TransportError;
    use crate::naive::config::NaiveConfig;
    use crate::naive::credential::pair::PASSWORD_FIELD;

    fn guard() -> Naive {
        let mut guard = Naive::new(NaiveConfig::new(443, "", "proxy.example.com"));
        guard.reload("a3f9c2b1", "xK-_9Zq", "www.bing.com");
        guard
    }

    #[test]
    fn a_configured_guard_writes_a_file_and_a_url() {
        let guard = guard();
        assert!(guard.is_renderable());
        assert!(guard
            .caddyfile("", "", "", "")
            .unwrap()
            .contains("basic_auth \"a3f9c2b1\" \"xK-_9Zq\""));
        assert_eq!(
            guard.proxy_url("", "", "").unwrap().as_str(),
            "https://a3f9c2b1:xK-_9Zq@proxy.example.com:443"
        );
    }

    #[test]
    fn an_argument_wins_over_the_stored_value() {
        let guard = guard();
        let config = guard
            .caddyfile("other", "s3cret", "ops@vortex.test", "archive.org")
            .unwrap();
        assert!(config.contains("basic_auth \"other\" \"s3cret\""));
        assert!(config.contains("tls \"ops@vortex.test\""));
        assert!(config.contains("probe_resistance \"archive.org\""));
    }

    #[test]
    fn a_guard_that_was_never_loaded_writes_nothing() {
        let guard = Naive::new(NaiveConfig::default());
        assert!(!guard.is_renderable());
        assert!(guard.caddyfile("", "", "", "").is_err());
        assert!(guard.proxy_url("proxy.example.com", "", "").is_err());
    }

    #[test]
    fn a_password_that_would_reopen_the_caddyfile_stops_the_whole_file() {
        let mut guard = guard();
        guard.reload(
            "a3f9c2b1",
            "s3cret}\n    respond \"pwned\"\n{",
            "www.bing.com",
        );
        assert!(!guard.is_renderable());
        assert_eq!(
            guard.caddyfile("", "", "", ""),
            Err(TransportError::NaiveCredential(PASSWORD_FIELD.to_owned()))
        );
    }

    #[test]
    fn the_refusal_never_repeats_the_secret_it_refused() {
        let mut guard = guard();
        guard.reload("a3f9c2b1", "s3cret\nrespond", "www.bing.com");
        let refusal = guard.caddyfile("", "", "", "").unwrap_err().to_string();
        assert!(!refusal.contains("s3cret"));
    }

    #[test]
    fn a_server_host_is_required_before_a_url_can_be_written() {
        let mut guard = Naive::new(NaiveConfig::default());
        guard.reload("a3f9c2b1", "xK-_9Zq", "www.bing.com");
        assert_eq!(
            guard.proxy_url("", "", ""),
            Err(TransportError::NaiveHost(String::new()))
        );
        assert!(guard.proxy_url("proxy.example.com", "", "").is_ok());
    }

    #[test]
    fn a_backend_that_is_not_a_url_stops_the_file_but_not_the_client() {
        let mut guard = Naive::new(NaiveConfig::new(443, "127.0.0.1:8000", "proxy.example.com"));
        guard.reload("a3f9c2b1", "xK-_9Zq", "www.bing.com");
        assert!(matches!(
            guard.caddyfile("", "", "", ""),
            Err(TransportError::NaiveUpstream(_))
        ));
        assert!(guard.proxy_url("", "", "").is_ok());
    }

    #[test]
    fn the_stored_secrets_are_readable_as_they_were_loaded() {
        let guard = guard();
        assert_eq!(guard.username(), "a3f9c2b1");
        assert_eq!(guard.password(), "xK-_9Zq");
        assert_eq!(guard.probe_domain(), "www.bing.com");
        assert_eq!(guard.config().server_host, "proxy.example.com");
    }
}

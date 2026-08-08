use crate::error::{Result, TransportError};
use crate::naive::caddy::email::AcmeEmail;
use crate::naive::credential::pair::Credentials;
use crate::naive::probe::ProbeDomain;
use crate::naive::upstream::url::UpstreamUrl;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaddySite {
    pub port: u16,
    pub email: AcmeEmail,
    pub credentials: Credentials,
    pub probe_domain: ProbeDomain,
    pub upstream: UpstreamUrl,
}

impl CaddySite {
    pub fn parse(
        port: u16,
        email: &str,
        username: &str,
        password: &str,
        probe_domain: &str,
        upstream: &str,
    ) -> Result<CaddySite> {
        if port == 0 {
            return Err(TransportError::NaivePort);
        }
        Ok(CaddySite {
            port,
            email: AcmeEmail::parse(email)?,
            credentials: Credentials::parse(username, password)?,
            probe_domain: ProbeDomain::parse(probe_domain)?,
            upstream: UpstreamUrl::parse(upstream)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::CaddySite;
    use crate::error::TransportError;

    fn site(port: u16) -> Result<CaddySite, TransportError> {
        CaddySite::parse(
            port,
            "admin@example.com",
            "a3f9c2b1",
            "xK-_9Zq",
            "www.bing.com",
            "http://127.0.0.1:8000",
        )
    }

    #[test]
    fn every_field_of_a_shipped_configuration_is_accepted() {
        let site = site(443).unwrap();
        assert_eq!(site.port, 443);
        assert_eq!(site.probe_domain.as_str(), "www.bing.com");
        assert_eq!(site.upstream.render(), "http://127.0.0.1:8000");
    }

    #[test]
    fn a_site_without_a_port_is_refused() {
        assert_eq!(site(0), Err(TransportError::NaivePort));
    }
}

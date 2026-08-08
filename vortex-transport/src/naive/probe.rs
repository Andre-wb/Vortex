use crate::error::{Result, TransportError};
use crate::tls::server_name::plausible_host;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeDomain(String);

impl ProbeDomain {
    pub fn parse(value: &str) -> Result<ProbeDomain> {
        plausible_host(value.as_bytes())
            .map(|host| ProbeDomain(host.to_owned()))
            .ok_or_else(|| TransportError::NaiveProbeDomain(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::ProbeDomain;
    use crate::error::TransportError;

    #[test]
    fn a_shipped_probe_domain_is_accepted() {
        for value in ["www.bing.com", "duckduckgo.com", "archive.org"] {
            assert_eq!(ProbeDomain::parse(value).unwrap().as_str(), value);
        }
    }

    #[test]
    fn a_probe_domain_that_is_not_a_host_name_is_refused() {
        for value in ["", "www bing.com", "www.bing.com\n    respond", "гугл.рф"] {
            assert!(matches!(
                ProbeDomain::parse(value),
                Err(TransportError::NaiveProbeDomain(_))
            ));
        }
    }
}

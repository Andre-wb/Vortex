use crate::error::{Result, TransportError};
use crate::naive::credential::text::acceptable;
use crate::tls::server_name::plausible_host;

pub const MAX_EMAIL_LEN: usize = 254;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcmeEmail(String);

impl AcmeEmail {
    pub fn parse(value: &str) -> Result<AcmeEmail> {
        split(value)
            .map(|_| AcmeEmail(value.to_owned()))
            .ok_or_else(|| TransportError::NaiveEmail(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn split(value: &str) -> Option<()> {
    if value.is_empty() || value.len() > MAX_EMAIL_LEN {
        return None;
    }
    if !value.bytes().all(acceptable) {
        return None;
    }
    let (local, domain) = value.split_once('@')?;
    if local.is_empty() || domain.contains('@') {
        return None;
    }
    plausible_host(domain.as_bytes()).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::AcmeEmail;
    use crate::error::TransportError;

    #[test]
    fn an_address_an_acme_directory_would_take_is_accepted() {
        for value in ["admin@example.com", "ops+acme@vortex.test", "a@b.co"] {
            assert_eq!(AcmeEmail::parse(value).unwrap().as_str(), value);
        }
    }

    #[test]
    fn an_address_that_would_smuggle_a_directive_is_refused() {
        for value in [
            "admin@example.com\n    respond \"pwned\"",
            "admin@example.com {",
            "admin @example.com",
            "admin@exa mple.com",
        ] {
            assert!(matches!(
                AcmeEmail::parse(value),
                Err(TransportError::NaiveEmail(_))
            ));
        }
    }

    #[test]
    fn something_that_is_not_an_address_is_refused() {
        for value in [
            "",
            "admin",
            "@example.com",
            "admin@",
            "a@b@c.com",
            "internal",
        ] {
            assert!(AcmeEmail::parse(value).is_err(), "{value}");
        }
    }
}

pub const DEFAULT_DONOR_PORT: u16 = 443;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DonorTarget {
    pub host: String,
    pub port: u16,
}

impl DonorTarget {
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        DonorTarget {
            host: host.into(),
            port,
        }
    }

    pub fn https(host: impl Into<String>) -> Self {
        DonorTarget::new(host, DEFAULT_DONOR_PORT)
    }

    pub fn matches(&self, host: &str) -> bool {
        self.host.eq_ignore_ascii_case(host)
    }
}

#[cfg(test)]
mod tests {
    use super::{DonorTarget, DEFAULT_DONOR_PORT};

    #[test]
    fn a_donor_defaults_to_the_https_port() {
        assert_eq!(DonorTarget::https("www.apple.com").port, DEFAULT_DONOR_PORT);
    }

    #[test]
    fn hosts_are_compared_without_regard_to_case() {
        let donor = DonorTarget::https("www.Google.com");
        assert!(donor.matches("WWW.GOOGLE.COM"));
        assert!(!donor.matches("www.google.com.evil.test"));
    }
}

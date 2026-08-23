use std::net::IpAddr;

use crate::registry::refusal::PeerRefusal;

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PeerAddress(String);

impl PeerAddress {
    pub fn parse(value: &str) -> Result<Self, PeerRefusal> {
        value
            .parse::<IpAddr>()
            .map_err(|_| PeerRefusal::NotAnAddress)?;
        Ok(PeerAddress(value.to_owned()))
    }

    pub fn written(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::PeerAddress;
    use crate::registry::refusal::PeerRefusal;

    #[test]
    fn both_address_families_name_a_peer() {
        assert_eq!(
            PeerAddress::parse("192.168.1.7").unwrap().written(),
            "192.168.1.7"
        );
        assert_eq!(PeerAddress::parse("::1").unwrap().written(), "::1");
    }

    #[test]
    fn a_host_name_names_no_peer() {
        assert_eq!(
            PeerAddress::parse("example.com"),
            Err(PeerRefusal::NotAnAddress)
        );
        assert_eq!(PeerAddress::parse(""), Err(PeerRefusal::NotAnAddress));
    }
}

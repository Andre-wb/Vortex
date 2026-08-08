use crate::parse::step::Step;
use crate::socks::domain_name::DomainName;
use std::net::{Ipv4Addr, Ipv6Addr};

pub const KIND_IPV4: u8 = 0x01;
pub const KIND_DOMAIN: u8 = 0x03;
pub const KIND_IPV6: u8 = 0x04;

pub const IPV4_LEN: usize = 4;
pub const IPV6_LEN: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Address {
    Ipv4(Ipv4Addr),
    Domain(DomainName),
    Ipv6(Ipv6Addr),
}

impl Address {
    pub fn resolve(host: &str) -> Option<Self> {
        if let Ok(address) = host.parse::<Ipv4Addr>() {
            return Some(Address::Ipv4(address));
        }
        if let Ok(address) = host.parse::<Ipv6Addr>() {
            return Some(Address::Ipv6(address));
        }
        DomainName::parse(host.as_bytes()).map(Address::Domain)
    }

    pub fn parse(data: &[u8]) -> Step<Self> {
        let Some(kind) = data.first().copied() else {
            return Step::NeedMore;
        };
        match kind {
            KIND_IPV4 => fixed(data, IPV4_LEN).map(|bytes| {
                let octets: [u8; IPV4_LEN] = bytes.try_into().expect("длина проверена выше");
                Address::Ipv4(Ipv4Addr::from(octets))
            }),
            KIND_IPV6 => fixed(data, IPV6_LEN).map(|bytes| {
                let octets: [u8; IPV6_LEN] = bytes.try_into().expect("длина проверена выше");
                Address::Ipv6(Ipv6Addr::from(octets))
            }),
            KIND_DOMAIN => domain(data),
            _ => Step::Malformed,
        }
    }

    pub fn encode(&self, out: &mut Vec<u8>) {
        out.push(self.kind());
        match self {
            Address::Ipv4(address) => out.extend_from_slice(&address.octets()),
            Address::Ipv6(address) => out.extend_from_slice(&address.octets()),
            Address::Domain(name) => {
                out.push(name.length_byte());
                out.extend_from_slice(name.as_str().as_bytes());
            }
        }
    }

    pub fn kind(&self) -> u8 {
        match self {
            Address::Ipv4(_) => KIND_IPV4,
            Address::Domain(_) => KIND_DOMAIN,
            Address::Ipv6(_) => KIND_IPV6,
        }
    }

    pub fn kind_name(&self) -> &'static str {
        match self {
            Address::Ipv4(_) => "ipv4",
            Address::Domain(_) => "domain",
            Address::Ipv6(_) => "ipv6",
        }
    }

    pub fn host(&self) -> String {
        match self {
            Address::Ipv4(address) => address.to_string(),
            Address::Ipv6(address) => address.to_string(),
            Address::Domain(name) => name.as_str().to_owned(),
        }
    }
}

fn fixed(data: &[u8], len: usize) -> Step<&[u8]> {
    if data.len() < 1 + len {
        return Step::NeedMore;
    }
    Step::parsed(&data[1..1 + len], 1 + len)
}

fn domain(data: &[u8]) -> Step<Address> {
    let Some(len) = data.get(1).copied() else {
        return Step::NeedMore;
    };
    let len = usize::from(len);
    if len == 0 {
        return Step::Malformed;
    }
    if data.len() < 2 + len {
        return Step::NeedMore;
    }
    match DomainName::parse(&data[2..2 + len]) {
        Some(name) => Step::parsed(Address::Domain(name), 2 + len),
        None => Step::Malformed,
    }
}

#[cfg(test)]
mod tests {
    use super::{Address, KIND_DOMAIN, KIND_IPV4, KIND_IPV6};
    use crate::parse::step::Step;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn encoded(address: &Address) -> Vec<u8> {
        let mut out = Vec::new();
        address.encode(&mut out);
        out
    }

    #[test]
    fn a_dotted_quad_is_an_ipv4_address_and_not_a_name() {
        let address = Address::resolve("13.10.1.2").unwrap();
        assert_eq!(address, Address::Ipv4(Ipv4Addr::new(13, 10, 1, 2)));
        assert_eq!(encoded(&address), vec![KIND_IPV4, 13, 10, 1, 2]);
    }

    #[test]
    fn a_colon_form_is_an_ipv6_address() {
        let address = Address::resolve("2001:db8::1").unwrap();
        assert_eq!(
            address,
            Address::Ipv6("2001:db8::1".parse::<Ipv6Addr>().unwrap())
        );
        assert_eq!(encoded(&address).len(), 1 + 16);
        assert_eq!(encoded(&address)[0], KIND_IPV6);
    }

    #[test]
    fn anything_else_travels_as_a_name() {
        let address = Address::resolve("www.example.com").unwrap();
        assert_eq!(address.kind_name(), "domain");
        assert_eq!(encoded(&address)[..2], [KIND_DOMAIN, 15]);
    }

    #[test]
    fn a_name_that_could_never_be_a_host_is_refused_at_the_source() {
        for host in ["", "he re.com", "line\nbreak.com", "звезда.рф"] {
            assert_eq!(Address::resolve(host), None, "{host}");
        }
    }

    #[test]
    fn every_form_parses_back_to_what_was_encoded() {
        for host in ["13.10.1.2", "2001:db8::1", "www.example.com"] {
            let address = Address::resolve(host).unwrap();
            let bytes = encoded(&address);
            assert_eq!(
                Address::parse(&bytes),
                Step::parsed(address.clone(), bytes.len())
            );
            assert_eq!(address.host(), host);
        }
    }

    #[test]
    fn a_truncated_address_asks_for_more_instead_of_refusing() {
        let bytes = encoded(&Address::resolve("www.example.com").unwrap());
        for cut in 0..bytes.len() {
            assert!(Address::parse(&bytes[..cut]).needs_more(), "срез {cut}");
        }
    }

    #[test]
    fn an_unknown_address_kind_is_refused_at_once() {
        assert!(Address::parse(&[0x02, 0x00, 0x00]).is_malformed());
        assert!(Address::parse(&[0xFF]).is_malformed());
    }

    #[test]
    fn a_zero_length_name_is_refused() {
        assert!(Address::parse(&[KIND_DOMAIN, 0x00]).is_malformed());
    }

    #[test]
    fn a_name_with_bytes_no_host_ever_carries_is_refused() {
        let mut bytes = vec![KIND_DOMAIN, 5];
        bytes.extend_from_slice(b"a\x00b.c");
        assert!(Address::parse(&bytes).is_malformed());
    }

    #[test]
    fn the_bytes_after_the_address_are_left_for_the_caller() {
        let mut bytes = encoded(&Address::resolve("13.10.1.2").unwrap());
        bytes.extend_from_slice(b"tail");
        assert_eq!(
            Address::parse(&bytes),
            Step::parsed(Address::Ipv4(Ipv4Addr::new(13, 10, 1, 2)), 5)
        );
    }
}

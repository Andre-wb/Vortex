use crate::net::address;
use std::fmt;
use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Cidr {
    base: IpAddr,
    bits: u8,
}

impl Cidr {
    pub fn parse(value: &str) -> Option<Cidr> {
        let (host, width) = value.trim().split_once('/')?;
        let base = address::parse(host)?;
        let bits: u8 = width.trim().parse().ok()?;
        Cidr::new(base, bits)
    }

    pub fn new(base: IpAddr, bits: u8) -> Option<Cidr> {
        if bits > width_of(&base) {
            return None;
        }
        Some(Cidr {
            base: masked(base, bits),
            bits,
        })
    }

    pub fn contains(&self, address: &IpAddr) -> bool {
        let candidate = address::unmap(*address);
        if width_of(&candidate) != width_of(&self.base) {
            return false;
        }
        masked(candidate, self.bits) == self.base
    }

    pub fn base(&self) -> IpAddr {
        self.base
    }

    pub fn bits(&self) -> u8 {
        self.bits
    }
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.base, self.bits)
    }
}

fn width_of(address: &IpAddr) -> u8 {
    match address {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    }
}

fn masked(address: IpAddr, bits: u8) -> IpAddr {
    match address {
        IpAddr::V4(four) => {
            let raw = u32::from(four);
            let kept = if bits == 0 {
                0
            } else {
                raw & (u32::MAX << (32 - bits))
            };
            IpAddr::V4(kept.into())
        }
        IpAddr::V6(six) => {
            let raw = u128::from(six);
            let kept = if bits == 0 {
                0
            } else {
                raw & (u128::MAX << (128 - bits))
            };
            IpAddr::V6(kept.into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Cidr;
    use crate::net::address;

    fn ip(value: &str) -> std::net::IpAddr {
        address::parse(value).unwrap()
    }

    #[test]
    fn a_network_holds_the_addresses_inside_it_and_no_others() {
        let network = Cidr::parse("149.154.160.0/20").unwrap();
        assert!(network.contains(&ip("149.154.160.0")));
        assert!(network.contains(&ip("149.154.167.42")));
        assert!(network.contains(&ip("149.154.175.255")));
        assert!(!network.contains(&ip("149.154.176.0")));
        assert!(!network.contains(&ip("149.154.159.255")));
    }

    #[test]
    fn the_string_prefix_that_was_used_before_admitted_addresses_a_network_does_not() {
        let network = Cidr::parse("172.16.0.0/12").unwrap();
        assert!(network.contains(&ip("172.20.1.1")));
        assert!(network.contains(&ip("172.31.255.255")));
        assert!(!network.contains(&ip("172.2.3.4")));
        assert!(!network.contains(&ip("172.200.1.1")));
        assert!(!network.contains(&ip("172.255.1.1")));
    }

    #[test]
    fn a_host_address_written_with_bits_set_below_the_mask_names_its_network() {
        let network = Cidr::parse("185.228.168.9/24").unwrap();
        assert_eq!(network.to_string(), "185.228.168.0/24");
        assert!(network.contains(&ip("185.228.168.1")));
    }

    #[test]
    fn the_two_families_never_answer_for_each_other() {
        let four = Cidr::parse("10.0.0.0/8").unwrap();
        let six = Cidr::parse("fc00::/7").unwrap();
        assert!(!four.contains(&ip("fc00::1")));
        assert!(!six.contains(&ip("10.0.0.1")));
    }

    #[test]
    fn a_mapped_address_is_matched_by_the_network_of_the_address_it_maps() {
        let network = Cidr::parse("10.0.0.0/8").unwrap();
        assert!(network.contains(&ip("::ffff:10.1.2.3")));
    }

    #[test]
    fn everything_and_nothing_are_both_expressible() {
        assert!(Cidr::parse("0.0.0.0/0").unwrap().contains(&ip("1.2.3.4")));
        let single = Cidr::parse("1.2.3.4/32").unwrap();
        assert!(single.contains(&ip("1.2.3.4")));
        assert!(!single.contains(&ip("1.2.3.5")));
    }

    #[test]
    fn what_is_not_a_network_is_not_read_as_one() {
        assert_eq!(Cidr::parse("10.0.0.0"), None);
        assert_eq!(Cidr::parse("10.0.0.0/33"), None);
        assert_eq!(Cidr::parse("fc00::/129"), None);
        assert_eq!(Cidr::parse("10.0.0.0/x"), None);
        assert_eq!(Cidr::parse("/8"), None);
    }
}

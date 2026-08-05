//! Разбор и проверка вхождения адреса в сеть CIDR.

use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpNetwork {
    address: IpAddr,
    prefix_len: u8,
}

impl IpNetwork {
    /// Разбор записи `10.0.0.0/8`, `::1/128` или одиночного адреса.
    pub fn parse(entry: &str) -> Option<IpNetwork> {
        let (addr_part, prefix_part) = match entry.split_once('/') {
            Some((addr, prefix)) => (addr, Some(prefix)),
            None => (entry, None),
        };
        let address: IpAddr = addr_part.trim().parse().ok()?;
        let max_prefix = match address {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        let prefix_len = match prefix_part {
            Some(raw) => {
                let value: u8 = raw.trim().parse().ok()?;
                if value > max_prefix {
                    return None;
                }
                value
            }
            None => max_prefix,
        };
        Some(IpNetwork {
            address,
            prefix_len,
        })
    }

    pub fn contains(&self, candidate: &IpAddr) -> bool {
        match (self.address, candidate) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                prefix_matches(&net.octets(), &ip.octets(), self.prefix_len)
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                prefix_matches(&net.octets(), &ip.octets(), self.prefix_len)
            }
            // Разные семейства адресов никогда не совпадают.
            _ => false,
        }
    }

    pub fn prefix_len(&self) -> u8 {
        self.prefix_len
    }
}

/// Совпадают ли первые `prefix_len` бит.
fn prefix_matches(network: &[u8], candidate: &[u8], prefix_len: u8) -> bool {
    let full_bytes = (prefix_len / 8) as usize;
    if network[..full_bytes] != candidate[..full_bytes] {
        return false;
    }
    let remaining_bits = prefix_len % 8;
    if remaining_bits == 0 {
        return true;
    }
    let mask = 0xffu8 << (8 - remaining_bits);
    network[full_bytes] & mask == candidate[full_bytes] & mask
}

/// Разбор списка записей; некорректные молча отбрасываются.
pub fn parse_networks<I, S>(entries: I) -> Vec<IpNetwork>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    entries
        .into_iter()
        .filter_map(|entry| IpNetwork::parse(entry.as_ref()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{parse_networks, IpNetwork};
    use std::net::IpAddr;

    fn ip(raw: &str) -> IpAddr {
        raw.parse().unwrap()
    }

    #[test]
    fn cidr_containment_works() {
        let net = IpNetwork::parse("192.168.1.0/24").unwrap();
        assert!(net.contains(&ip("192.168.1.55")));
        assert!(!net.contains(&ip("192.168.2.55")));
    }

    #[test]
    fn non_byte_aligned_prefix_works() {
        let net = IpNetwork::parse("10.0.0.0/12").unwrap();
        assert!(net.contains(&ip("10.15.255.1")));
        assert!(!net.contains(&ip("10.16.0.1")));
    }

    #[test]
    fn bare_address_is_a_host_route() {
        let net = IpNetwork::parse("10.0.0.5").unwrap();
        assert_eq!(net.prefix_len(), 32);
        assert!(net.contains(&ip("10.0.0.5")));
        assert!(!net.contains(&ip("10.0.0.6")));
    }

    #[test]
    fn ipv6_is_supported_and_families_do_not_mix() {
        let net = IpNetwork::parse("fd00::/8").unwrap();
        assert!(net.contains(&ip("fd00::1")));
        assert!(!net.contains(&ip("10.0.0.1")));
    }

    #[test]
    fn invalid_entries_are_dropped() {
        assert!(IpNetwork::parse("не-адрес").is_none());
        assert!(IpNetwork::parse("10.0.0.0/99").is_none());
        assert_eq!(parse_networks(["10.0.0.0/8", "мусор"]).len(), 1);
    }
}

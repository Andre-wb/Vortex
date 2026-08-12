use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub fn is_local(address: &IpAddr) -> bool {
    match crate::net::address::unmap(*address) {
        IpAddr::V4(four) => is_local_v4(&four),
        IpAddr::V6(six) => is_local_v6(&six),
    }
}

fn is_local_v4(address: &Ipv4Addr) -> bool {
    address.is_loopback()
        || address.is_private()
        || address.is_link_local()
        || address.is_unspecified()
        || address.is_broadcast()
}

fn is_local_v6(address: &Ipv6Addr) -> bool {
    address.is_loopback()
        || address.is_unspecified()
        || is_unique_local(address)
        || is_link_local(address)
}

fn is_unique_local(address: &Ipv6Addr) -> bool {
    address.segments()[0] & 0xfe00 == 0xfc00
}

fn is_link_local(address: &Ipv6Addr) -> bool {
    address.segments()[0] & 0xffc0 == 0xfe80
}

#[cfg(test)]
mod tests {
    use super::is_local;
    use crate::net::address;

    fn local(value: &str) -> bool {
        is_local(&address::parse(value).unwrap())
    }

    #[test]
    fn the_machine_itself_is_never_an_external_client() {
        assert!(local("127.0.0.1"));
        assert!(local("127.13.2.9"));
        assert!(local("::1"));
        assert!(local("::ffff:127.0.0.1"));
    }

    #[test]
    fn a_peer_on_the_same_network_is_not_an_external_client() {
        assert!(local("10.0.0.1"));
        assert!(local("192.168.1.10"));
        assert!(local("169.254.1.1"));
        assert!(local("fe80::1"));
        assert!(local("fc00::1"));
        assert!(local("fd00::1"));
    }

    #[test]
    fn the_private_range_is_the_whole_range_and_only_it() {
        assert!(local("172.16.0.1"));
        assert!(local("172.20.1.1"));
        assert!(local("172.31.255.255"));
        assert!(!local("172.2.3.4"));
        assert!(!local("172.15.255.255"));
        assert!(!local("172.32.0.1"));
        assert!(!local("172.200.1.1"));
        assert!(!local("172.255.1.1"));
    }

    #[test]
    fn a_public_address_is_an_external_client() {
        assert!(!local("203.0.113.7"));
        assert!(!local("8.8.8.8"));
        assert!(!local("149.154.167.1"));
        assert!(!local("2001:db8::1"));
    }
}

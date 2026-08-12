use std::net::IpAddr;

pub fn parse(value: &str) -> Option<IpAddr> {
    let trimmed = strip_zone(strip_brackets(value.trim()));
    if trimmed.is_empty() {
        return None;
    }
    trimmed.parse::<IpAddr>().ok().map(unmap)
}

pub fn unmap(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(six) => match six.to_ipv4_mapped() {
            Some(four) => IpAddr::V4(four),
            None => IpAddr::V6(six),
        },
        four => four,
    }
}

fn strip_brackets(value: &str) -> &str {
    value
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or(value)
}

fn strip_zone(value: &str) -> &str {
    match value.split_once('%') {
        Some((address, _)) => address,
        None => value,
    }
}

#[cfg(test)]
mod tests {
    use super::parse;
    use std::net::IpAddr;

    #[test]
    fn a_plain_address_is_read_in_both_families() {
        assert_eq!(parse("203.0.113.7"), "203.0.113.7".parse::<IpAddr>().ok());
        assert_eq!(parse("2001:db8::1"), "2001:db8::1".parse::<IpAddr>().ok());
    }

    #[test]
    fn a_mapped_address_is_the_same_address_as_the_one_it_maps() {
        assert_eq!(parse("::ffff:127.0.0.1"), parse("127.0.0.1"));
        assert_eq!(parse("::ffff:10.0.0.1"), parse("10.0.0.1"));
    }

    #[test]
    fn the_brackets_and_the_zone_a_peer_address_carries_are_not_part_of_it() {
        assert_eq!(parse("[::1]"), parse("::1"));
        assert_eq!(parse("fe80::1%en0"), parse("fe80::1"));
        assert_eq!(parse("  203.0.113.7  "), parse("203.0.113.7"));
    }

    #[test]
    fn what_is_not_an_address_is_not_read_as_one() {
        assert_eq!(parse(""), None);
        assert_eq!(parse("   "), None);
        assert_eq!(parse("localhost"), None);
        assert_eq!(parse("203.0.113.7:443"), None);
        assert_eq!(parse("203.0.113"), None);
        assert_eq!(parse("203.0.113.256"), None);
    }
}

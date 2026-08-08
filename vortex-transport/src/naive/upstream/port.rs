pub const MAX_PORT_DIGITS: usize = 5;

pub fn parse(value: &str) -> Option<u16> {
    if value.is_empty() || value.len() > MAX_PORT_DIGITS {
        return None;
    }
    if !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    value.parse::<u16>().ok().filter(|port| *port != 0)
}

#[cfg(test)]
mod tests {
    use super::parse;

    #[test]
    fn a_decimal_port_is_read() {
        assert_eq!(parse("8000"), Some(8000));
        assert_eq!(parse("1"), Some(1));
        assert_eq!(parse("65535"), Some(65535));
    }

    #[test]
    fn a_port_that_is_not_plain_digits_is_refused() {
        for value in [
            "", "+80", "-80", "8_0", " 80", "80 ", "0x50", "80\n", "０８",
        ] {
            assert_eq!(parse(value), None, "{value}");
        }
    }

    #[test]
    fn a_port_outside_the_range_is_refused() {
        assert_eq!(parse("0"), None);
        assert_eq!(parse("00000"), None);
        assert_eq!(parse("65536"), None);
        assert_eq!(parse("123456"), None);
    }
}

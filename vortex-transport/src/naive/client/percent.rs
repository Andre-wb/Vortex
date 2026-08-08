use std::fmt::Write;

pub fn encode_userinfo(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if unreserved(byte) {
            encoded.push(char::from(byte));
        } else {
            let _ = write!(encoded, "%{byte:02X}");
        }
    }
    encoded
}

fn unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
}

#[cfg(test)]
mod tests {
    use super::encode_userinfo;

    #[test]
    fn an_unreserved_value_passes_through_untouched() {
        assert_eq!(encode_userinfo("a3f9c2b1"), "a3f9c2b1");
        assert_eq!(encode_userinfo("xK-_9Zq.~"), "xK-_9Zq.~");
    }

    #[test]
    fn the_characters_that_cut_a_url_apart_are_encoded() {
        assert_eq!(encode_userinfo("p@ss"), "p%40ss");
        assert_eq!(encode_userinfo("p:ss"), "p%3Ass");
        assert_eq!(encode_userinfo("p/ss"), "p%2Fss");
        assert_eq!(encode_userinfo("p?ss"), "p%3Fss");
        assert_eq!(encode_userinfo("p#ss"), "p%23ss");
    }

    #[test]
    fn an_encoded_password_can_no_longer_redirect_the_proxy() {
        assert_eq!(encode_userinfo("pass@evil.test/"), "pass%40evil.test%2F");
    }

    #[test]
    fn a_percent_is_encoded_so_that_decoding_is_reversible() {
        assert_eq!(encode_userinfo("100%"), "100%25");
        assert_eq!(encode_userinfo("%40"), "%2540");
    }

    #[test]
    fn a_value_outside_ascii_is_encoded_byte_by_byte_in_utf8() {
        assert_eq!(
            encode_userinfo("пароль"),
            "%D0%BF%D0%B0%D1%80%D0%BE%D0%BB%D1%8C"
        );
    }

    #[test]
    fn hexadecimal_is_written_in_upper_case() {
        assert_eq!(encode_userinfo(" "), "%20");
        assert_eq!(encode_userinfo("\u{7f}"), "%7F");
    }
}

pub fn decode_dropping_invalid(bytes: &[u8]) -> String {
    let mut decoded = String::with_capacity(bytes.len());
    let mut rest = bytes;
    loop {
        match std::str::from_utf8(rest) {
            Ok(tail) => {
                decoded.push_str(tail);
                return decoded;
            }
            Err(error) => {
                let (valid, after) = rest.split_at(error.valid_up_to());
                if let Ok(text) = std::str::from_utf8(valid) {
                    decoded.push_str(text);
                }
                match error.error_len() {
                    Some(skipped) => rest = &after[skipped..],
                    None => return decoded,
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::decode_dropping_invalid;

    #[test]
    fn valid_text_survives_unchanged() {
        assert_eq!(decode_dropping_invalid("привет".as_bytes()), "привет");
        assert_eq!(decode_dropping_invalid(b""), "");
    }

    #[test]
    fn broken_bytes_are_dropped_not_replaced() {
        assert_eq!(decode_dropping_invalid(&[0xff, 0xfe]), "");
        assert_eq!(decode_dropping_invalid(b"a\xffb"), "ab");
    }

    #[test]
    fn a_truncated_sequence_at_the_end_is_dropped() {
        assert_eq!(decode_dropping_invalid(&[b'a', 0xd0]), "a");
    }
}

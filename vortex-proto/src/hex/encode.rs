const DIGITS: &[u8; 16] = b"0123456789abcdef";

pub fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::encode;

    #[test]
    fn bytes_are_written_in_lower_case() {
        assert_eq!(encode(&[0xab, 0xcd, 0xef]), "abcdef");
    }

    #[test]
    fn nothing_encodes_to_an_empty_string() {
        assert_eq!(encode(&[]), "");
    }

    #[test]
    fn every_byte_takes_two_characters() {
        assert_eq!(encode(&[0x00, 0x0f]), "000f");
    }
}

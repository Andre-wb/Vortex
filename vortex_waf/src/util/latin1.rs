pub fn decode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| *byte as char).collect()
}

#[cfg(test)]
mod tests {
    use super::decode;

    #[test]
    fn every_byte_maps_to_a_character() {
        assert_eq!(decode(b"application/json"), "application/json");
        assert_eq!(decode(&[0xff, 0x41]), "\u{ff}A");
        assert_eq!(decode(&[]), "");
    }
}

use crate::hex::error::HexError;

pub fn decode_fixed<const N: usize>(text: &str) -> Result<[u8; N], HexError> {
    let bytes = decode(text)?;
    if bytes.len() != N {
        return Err(HexError::Length {
            expected: N,
            got: bytes.len(),
        });
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

pub fn decode(text: &str) -> Result<Vec<u8>, HexError> {
    let raw = text.as_bytes();
    if !raw.len().is_multiple_of(2) {
        return Err(HexError::NotHex);
    }
    let mut out = Vec::with_capacity(raw.len() / 2);
    for pair in raw.chunks_exact(2) {
        let high = digit(pair[0])?;
        let low = digit(pair[1])?;
        out.push((high << 4) | low);
    }
    Ok(out)
}

fn digit(byte: u8) -> Result<u8, HexError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(HexError::NotHex),
    }
}

#[cfg(test)]
mod tests {
    use super::{decode, decode_fixed};
    use crate::hex::error::HexError;

    #[test]
    fn a_key_sized_value_is_decoded() {
        let text = "00".repeat(32);
        assert_eq!(decode_fixed::<32>(&text).unwrap(), [0u8; 32]);
    }

    #[test]
    fn upper_and_lower_case_decode_alike() {
        assert_eq!(decode("AbCdEf").unwrap(), vec![0xab, 0xcd, 0xef]);
    }

    #[test]
    fn an_odd_number_of_characters_is_not_hex() {
        assert_eq!(decode("abc"), Err(HexError::NotHex));
    }

    #[test]
    fn whitespace_is_not_ignored() {
        assert_eq!(decode("ab cd"), Err(HexError::NotHex));
        assert_eq!(decode(" abcd "), Err(HexError::NotHex));
    }

    #[test]
    fn a_well_formed_value_of_the_wrong_size_is_measured_in_bytes() {
        assert_eq!(
            decode_fixed::<32>("abcd"),
            Err(HexError::Length {
                expected: 32,
                got: 2
            })
        );
    }

    #[test]
    fn an_empty_value_decodes_to_nothing() {
        assert_eq!(decode("").unwrap(), Vec::<u8>::new());
        assert_eq!(
            decode_fixed::<32>(""),
            Err(HexError::Length {
                expected: 32,
                got: 0
            })
        );
    }

    #[test]
    fn a_multibyte_character_is_not_hex() {
        assert_eq!(decode("фф"), Err(HexError::NotHex));
    }
}

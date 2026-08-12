pub const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
pub const GROUP_BYTES: usize = 5;
pub const GROUP_CHARS: usize = 8;

pub fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(encoded_length(bytes.len()));
    for group in bytes.chunks(GROUP_BYTES) {
        let mut buffer = [0u8; GROUP_BYTES];
        buffer[..group.len()].copy_from_slice(group);
        let packed = u64::from_be_bytes([
            0, 0, 0, buffer[0], buffer[1], buffer[2], buffer[3], buffer[4],
        ]);
        let chars = encoded_length(group.len());
        for slot in 0..chars {
            let shift = 35 - slot * 5;
            out.push(ALPHABET[((packed >> shift) & 0x1F) as usize] as char);
        }
    }
    out
}

pub fn decode(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() * GROUP_BYTES / GROUP_CHARS + 1);
    for group in text.to_ascii_lowercase().as_bytes().chunks(GROUP_CHARS) {
        let mut packed = 0u64;
        for slot in 0..GROUP_CHARS {
            let value = match group.get(slot) {
                Some(symbol) => ALPHABET.iter().position(|known| known == symbol)? as u64,
                None => 0,
            };
            packed |= value << (35 - slot * 5);
        }
        let bytes = decoded_length(group.len())?;
        let unpacked = packed.to_be_bytes();
        out.extend_from_slice(&unpacked[3..3 + bytes]);
    }
    Some(out)
}

pub fn encoded_length(bytes: usize) -> usize {
    bytes.div_ceil(GROUP_BYTES) * GROUP_CHARS - padding_for(bytes % GROUP_BYTES)
}

fn padding_for(tail: usize) -> usize {
    match tail {
        0 => 0,
        1 => 6,
        2 => 4,
        3 => 3,
        _ => 1,
    }
}

fn decoded_length(chars: usize) -> Option<usize> {
    match chars {
        8 => Some(5),
        7 => Some(4),
        5 => Some(3),
        4 => Some(2),
        2 => Some(1),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{decode, encode, encoded_length};

    #[test]
    fn the_published_examples_are_the_ones_we_produce() {
        assert_eq!(encode(b""), "");
        assert_eq!(encode(b"f"), "my");
        assert_eq!(encode(b"fo"), "mzxq");
        assert_eq!(encode(b"foo"), "mzxw6");
        assert_eq!(encode(b"foob"), "mzxw6yq");
        assert_eq!(encode(b"fooba"), "mzxw6ytb");
        assert_eq!(encode(b"foobar"), "mzxw6ytboi");
    }

    #[test]
    fn what_was_encoded_decodes_back_to_itself() {
        for length in 0..200usize {
            let payload: Vec<u8> = (0..length).map(|index| (index * 7 % 256) as u8).collect();
            assert_eq!(
                decode(&encode(&payload)),
                Some(payload.clone()),
                "длина {length}"
            );
        }
    }

    #[test]
    fn the_encoding_uses_only_letters_and_digits_a_label_may_carry() {
        let payload: Vec<u8> = (0..=255u8).collect();
        assert!(encode(&payload)
            .chars()
            .all(|symbol| symbol.is_ascii_lowercase() || ('2'..='7').contains(&symbol)));
    }

    #[test]
    fn the_length_of_the_encoding_is_known_before_it_is_made() {
        for length in 0..100usize {
            let payload = vec![0xABu8; length];
            assert_eq!(encode(&payload).len(), encoded_length(length));
        }
    }

    #[test]
    fn what_is_not_this_encoding_is_refused() {
        assert_eq!(decode("!!!!!!!!"), None);
        assert_eq!(decode("mzxw6==="), None);
        assert_eq!(decode("abc"), None);
        assert_eq!(decode("a"), None);
    }

    #[test]
    fn the_case_the_text_arrives_in_does_not_matter() {
        assert_eq!(decode("MZXW6YTB"), decode("mzxw6ytb"));
    }
}

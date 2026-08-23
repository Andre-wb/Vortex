use crate::hex::decode::decode;
use crate::hex::encode::encode;
use crate::message::limits::{MAX_CIPHERTEXT_HEX, MIN_CIPHERTEXT_HEX};
use crate::message::refusal::MessageRefusal;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MessageCiphertext(Vec<u8>);

impl MessageCiphertext {
    pub fn parse_hex(text: &str) -> Result<Self, MessageRefusal> {
        let trimmed = text.trim();
        if trimmed.is_empty() {
            return Err(MessageRefusal::CiphertextMissing);
        }
        if trimmed.len() < MIN_CIPHERTEXT_HEX {
            return Err(MessageRefusal::CiphertextShort);
        }
        if trimmed.len() > MAX_CIPHERTEXT_HEX {
            return Err(MessageRefusal::CiphertextLarge);
        }
        let bytes = decode(trimmed).map_err(|_| MessageRefusal::CiphertextHex)?;
        Ok(MessageCiphertext(bytes))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        encode(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::MessageCiphertext;
    use crate::message::limits::{MAX_CIPHERTEXT_HEX, MIN_CIPHERTEXT_HEX};
    use crate::message::refusal::MessageRefusal;

    #[test]
    fn the_shortest_accepted_ciphertext_survives_a_round_trip() {
        let text = "ab".repeat(MIN_CIPHERTEXT_HEX / 2);
        assert_eq!(MessageCiphertext::parse_hex(&text).unwrap().to_hex(), text);
    }

    #[test]
    fn an_empty_ciphertext_is_told_apart_from_a_short_one() {
        assert_eq!(
            MessageCiphertext::parse_hex(""),
            Err(MessageRefusal::CiphertextMissing)
        );
        assert_eq!(
            MessageCiphertext::parse_hex("   "),
            Err(MessageRefusal::CiphertextMissing)
        );
        assert_eq!(
            MessageCiphertext::parse_hex(&"ab".repeat(23)),
            Err(MessageRefusal::CiphertextShort)
        );
    }

    #[test]
    fn surrounding_whitespace_is_stripped_before_anything_is_measured() {
        let text = format!("  {}  ", "ab".repeat(24));
        assert_eq!(
            MessageCiphertext::parse_hex(&text).unwrap().to_hex(),
            "ab".repeat(24)
        );
    }

    #[test]
    fn whitespace_inside_the_value_is_not_hex() {
        assert_eq!(
            MessageCiphertext::parse_hex(&format!("ab {}", "ab".repeat(24))),
            Err(MessageRefusal::CiphertextHex)
        );
    }

    #[test]
    fn a_ciphertext_longer_than_the_frame_is_refused_before_it_is_decoded() {
        let text = "ab".repeat(MAX_CIPHERTEXT_HEX / 2 + 1);
        assert_eq!(
            MessageCiphertext::parse_hex(&text),
            Err(MessageRefusal::CiphertextLarge)
        );
    }

    #[test]
    fn a_ciphertext_of_exactly_the_frame_size_is_accepted() {
        let text = "ab".repeat(MAX_CIPHERTEXT_HEX / 2);
        assert_eq!(
            MessageCiphertext::parse_hex(&text)
                .unwrap()
                .as_bytes()
                .len(),
            MAX_CIPHERTEXT_HEX / 2
        );
    }

    #[test]
    fn an_odd_number_of_characters_is_not_hex() {
        assert_eq!(
            MessageCiphertext::parse_hex(&"a".repeat(49)),
            Err(MessageRefusal::CiphertextHex)
        );
    }
}

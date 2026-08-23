use crate::hex::decode::decode;
use crate::hex::encode::encode;
use crate::wrap::limits::CIPHERTEXT_MIN_BYTES;
use crate::wrap::refusal::WrapRefusal;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ciphertext(Vec<u8>);

impl Ciphertext {
    pub fn parse_hex(text: &str) -> Result<Self, WrapRefusal> {
        let bytes = decode(text).map_err(|_| WrapRefusal::CiphertextHex)?;
        if bytes.len() < CIPHERTEXT_MIN_BYTES {
            return Err(WrapRefusal::CiphertextLength);
        }
        Ok(Ciphertext(bytes))
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
    use super::Ciphertext;
    use crate::wrap::refusal::WrapRefusal;

    #[test]
    fn a_nonce_sized_value_is_the_shortest_accepted() {
        let text = "aa".repeat(12);
        assert_eq!(Ciphertext::parse_hex(&text).unwrap().to_hex(), text);
    }

    #[test]
    fn a_shorter_value_is_refused_by_length() {
        assert_eq!(
            Ciphertext::parse_hex(&"aa".repeat(11)),
            Err(WrapRefusal::CiphertextLength)
        );
    }

    #[test]
    fn whitespace_inside_the_value_is_not_hex() {
        let text = format!("{}  ", "aa".repeat(31));
        assert_eq!(text.len(), 64);
        assert_eq!(
            Ciphertext::parse_hex(&text),
            Err(WrapRefusal::CiphertextHex)
        );
    }

    #[test]
    fn an_odd_number_of_characters_is_not_hex() {
        assert_eq!(
            Ciphertext::parse_hex(&"a".repeat(25)),
            Err(WrapRefusal::CiphertextHex)
        );
    }

    #[test]
    fn a_room_key_envelope_survives_a_round_trip() {
        let text = "0f".repeat(60);
        let parsed = Ciphertext::parse_hex(&text).unwrap();
        assert_eq!(parsed.as_bytes().len(), 60);
        assert_eq!(parsed.to_hex(), text);
    }
}

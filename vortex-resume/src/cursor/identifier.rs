use crate::cursor::limits;
use crate::cursor::refusal::Refusal;

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ClientKey(String);

impl ClientKey {
    pub fn parse(value: &str) -> Result<Self, Refusal> {
        if value.is_empty() {
            return Err(Refusal::EmptyKey);
        }
        if value.chars().count() > limits::MAX_KEY_LENGTH {
            return Err(Refusal::OverLongKey);
        }
        if value
            .chars()
            .any(|c| c.is_control() || c.is_whitespace() || c == ':')
        {
            return Err(Refusal::KeyOutsideAlphabet);
        }
        Ok(ClientKey(value.to_owned()))
    }

    pub fn written(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::ClientKey;
    use crate::cursor::refusal::Refusal;

    #[test]
    fn a_hex_public_key_names_a_client() {
        let key = "ab".repeat(32);
        assert_eq!(ClientKey::parse(&key).unwrap().written(), key);
    }

    #[test]
    fn an_empty_key_names_no_client() {
        assert_eq!(ClientKey::parse(""), Err(Refusal::EmptyKey));
    }

    #[test]
    fn an_over_long_key_is_refused() {
        assert_eq!(
            ClientKey::parse(&"a".repeat(129)),
            Err(Refusal::OverLongKey)
        );
    }

    #[test]
    fn a_key_that_would_split_a_store_key_is_refused() {
        assert_eq!(
            ClientKey::parse("has space"),
            Err(Refusal::KeyOutsideAlphabet)
        );
        assert_eq!(
            ClientKey::parse("has:colon"),
            Err(Refusal::KeyOutsideAlphabet)
        );
        assert_eq!(
            ClientKey::parse("has\nbreak"),
            Err(Refusal::KeyOutsideAlphabet)
        );
    }
}

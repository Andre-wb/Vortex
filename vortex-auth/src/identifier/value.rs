use crate::identifier::cause::Cause;
use crate::identifier::refusal::IdentifierRefusal;
use crate::ports::entropy::Entropy;

pub const MAX_LEN: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Identifier(String);

impl Identifier {
    pub fn parse(label: &'static str, value: &str) -> Result<Self, IdentifierRefusal> {
        if value.is_empty() {
            return Err(IdentifierRefusal::new(label, Cause::Empty));
        }
        if value.len() > MAX_LEN {
            return Err(IdentifierRefusal::new(
                label,
                Cause::TooLong {
                    max: MAX_LEN,
                    got: value.len(),
                },
            ));
        }
        if !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        {
            return Err(IdentifierRefusal::new(label, Cause::NotAllowed));
        }
        Ok(Identifier(value.to_owned()))
    }

    pub fn draw(entropy: &dyn Entropy, bytes: usize) -> Self {
        let mut raw = vec![0u8; bytes];
        entropy.fill(&mut raw);
        Identifier(hex::encode(raw))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::{Identifier, MAX_LEN};
    use crate::identifier::cause::Cause;
    use crate::random::fixed_entropy::FixedEntropy;

    #[test]
    fn the_identifier_our_tokens_carry_is_accepted() {
        let value = Identifier::parse("токена", "0123456789abcdef0123456789abcdef").unwrap();
        assert_eq!(value.as_str(), "0123456789abcdef0123456789abcdef");
    }

    #[test]
    fn an_empty_identifier_is_refused() {
        let refusal = Identifier::parse("токена", "").unwrap_err();
        assert_eq!(refusal.cause(), &Cause::Empty);
    }

    #[test]
    fn an_identifier_longer_than_the_limit_is_refused() {
        let long = "a".repeat(MAX_LEN + 1);
        let refusal = Identifier::parse("токена", &long).unwrap_err();
        assert_eq!(
            refusal.cause(),
            &Cause::TooLong {
                max: MAX_LEN,
                got: MAX_LEN + 1
            }
        );
    }

    #[test]
    fn a_separator_never_travels_inside_the_identifier() {
        for hostile in ["aa:bb", "aa bb", "../evil"] {
            let refusal = Identifier::parse("токена", hostile).unwrap_err();
            assert_eq!(refusal.cause(), &Cause::NotAllowed);
        }
    }

    #[test]
    fn the_alphabet_of_a_url_safe_random_string_is_allowed_whole() {
        assert!(Identifier::parse("токена", "A-z_09").is_ok());
    }

    #[test]
    fn a_drawn_identifier_is_hex_of_the_requested_length() {
        let drawn = Identifier::draw(&FixedEntropy::counting_from(0), 16);
        assert_eq!(drawn.as_str().len(), 32);
        assert_eq!(&drawn.as_str()[..8], "00010203");
        assert!(Identifier::parse("челленджа", drawn.as_str()).is_ok());
    }
}

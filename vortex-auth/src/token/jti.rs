use crate::identifier::refusal::IdentifierRefusal;
use crate::identifier::value::Identifier;

const LABEL: &str = "токена";

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Jti(Identifier);

impl Jti {
    pub fn parse(value: &str) -> Result<Self, IdentifierRefusal> {
        Identifier::parse(LABEL, value).map(Jti)
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

#[cfg(test)]
mod tests {
    use super::Jti;
    use crate::identifier::cause::Cause;
    use crate::identifier::value::MAX_LEN;

    #[test]
    fn the_identifier_our_tokens_carry_is_accepted() {
        let jti = Jti::parse("0123456789abcdef0123456789abcdef").unwrap();
        assert_eq!(jti.as_str(), "0123456789abcdef0123456789abcdef");
    }

    #[test]
    fn an_empty_identifier_is_refused() {
        assert_eq!(Jti::parse("").unwrap_err().cause(), &Cause::Empty);
    }

    #[test]
    fn an_identifier_longer_than_the_limit_is_refused() {
        let long = "a".repeat(MAX_LEN + 1);
        assert_eq!(
            Jti::parse(&long).unwrap_err().cause(),
            &Cause::TooLong {
                max: MAX_LEN,
                got: MAX_LEN + 1
            }
        );
    }

    #[test]
    fn a_separator_never_travels_inside_the_identifier() {
        for hostile in ["aa:bb", "aa bb", "../evil"] {
            assert_eq!(Jti::parse(hostile).unwrap_err().cause(), &Cause::NotAllowed);
        }
    }

    #[test]
    fn the_alphabet_of_a_url_safe_random_string_is_allowed_whole() {
        assert!(Jti::parse("A-z_09").is_ok());
    }

    #[test]
    fn a_refusal_still_names_the_token_it_speaks_about() {
        assert_eq!(
            Jti::parse("").unwrap_err().to_string(),
            "идентификатор токена пуст"
        );
    }
}

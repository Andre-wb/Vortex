use vortex_auth::identifier::refusal::IdentifierRefusal;
use vortex_auth::identifier::value::Identifier;
use vortex_auth::ports::entropy::Entropy;

const LABEL: &str = "звонка";
const BYTES: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CallId(Identifier);

impl CallId {
    pub fn parse(value: &str) -> Result<Self, IdentifierRefusal> {
        Ok(CallId(Identifier::parse(LABEL, value)?))
    }

    pub fn draw(entropy: &dyn Entropy) -> Self {
        CallId(Identifier::draw(entropy, BYTES))
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

#[cfg(test)]
mod tests {
    use super::CallId;
    use vortex_auth::random::fixed_entropy::FixedEntropy;

    #[test]
    fn the_identifier_a_call_already_carries_is_accepted() {
        let value = "3f2b9c1d-4a5e-4c8b-9f10-2b3c4d5e6f70";
        assert_eq!(CallId::parse(value).unwrap().as_str(), value);
    }

    #[test]
    fn a_drawn_identifier_is_hex_and_never_repeats() {
        let entropy = FixedEntropy::counting_from(0);
        let first = CallId::draw(&entropy);
        let second = CallId::draw(&entropy);
        assert_eq!(first.as_str().len(), 32);
        assert_ne!(first, second);
    }

    #[test]
    fn an_identifier_outside_the_alphabet_names_no_call() {
        assert!(CallId::parse("").is_err());
        assert!(CallId::parse("a b").is_err());
        assert!(CallId::parse("call:1").is_err());
        assert!(CallId::parse(&"a".repeat(129)).is_err());
    }
}

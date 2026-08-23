use crate::identifier::refusal::IdentifierRefusal;
use crate::identifier::value::Identifier;
use crate::ports::entropy::Entropy;

const LABEL: &str = "челленджа";
const DRAWN_BYTES: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ChallengeId(Identifier);

impl ChallengeId {
    pub fn parse(value: &str) -> Result<Self, IdentifierRefusal> {
        Identifier::parse(LABEL, value).map(ChallengeId)
    }

    pub fn draw(entropy: &dyn Entropy) -> Self {
        ChallengeId(Identifier::draw(entropy, DRAWN_BYTES))
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

#[cfg(test)]
mod tests {
    use super::ChallengeId;
    use crate::random::fixed_entropy::FixedEntropy;

    #[test]
    fn a_drawn_identifier_is_the_thirty_two_hex_characters_the_client_already_sees() {
        let id = ChallengeId::draw(&FixedEntropy::counting_from(0));
        assert_eq!(id.as_str().len(), 32);
    }

    #[test]
    fn an_identifier_that_could_reshape_a_key_is_refused() {
        assert!(ChallengeId::parse("aa:bb").is_err());
        assert!(ChallengeId::parse("").is_err());
    }
}

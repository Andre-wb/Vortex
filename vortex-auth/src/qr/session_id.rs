use crate::identifier::refusal::IdentifierRefusal;
use crate::identifier::value::Identifier;
use crate::ports::entropy::Entropy;

const LABEL: &str = "QR-сессии";
const DRAWN_BYTES: usize = 24;

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct QrSessionId(Identifier);

impl QrSessionId {
    pub fn parse(value: &str) -> Result<Self, IdentifierRefusal> {
        Identifier::parse(LABEL, value).map(QrSessionId)
    }

    pub fn draw(entropy: &dyn Entropy) -> Self {
        QrSessionId(Identifier::draw(entropy, DRAWN_BYTES))
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

#[cfg(test)]
mod tests {
    use super::QrSessionId;
    use crate::random::fixed_entropy::FixedEntropy;

    #[test]
    fn a_drawn_session_is_the_forty_eight_hex_characters_the_qr_code_already_carries() {
        assert_eq!(
            QrSessionId::draw(&FixedEntropy::counting_from(0))
                .as_str()
                .len(),
            48
        );
    }

    #[test]
    fn a_session_that_could_reshape_a_key_is_refused() {
        assert!(QrSessionId::parse("aa:bb").is_err());
        assert!(QrSessionId::parse("").is_err());
    }
}

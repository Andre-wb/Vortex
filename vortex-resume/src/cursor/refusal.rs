use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    EmptyKey,
    OverLongKey,
    KeyOutsideAlphabet,
}

impl Refusal {
    pub fn message(&self) -> String {
        match self {
            Refusal::EmptyKey => "user_pubkey is required".to_owned(),
            Refusal::OverLongKey => format!(
                "user_pubkey longer than {} characters",
                super::limits::MAX_KEY_LENGTH
            ),
            Refusal::KeyOutsideAlphabet => {
                "user_pubkey holds a space, a colon or a control character".to_owned()
            }
        }
    }

    pub fn code(&self) -> &'static str {
        match self {
            Refusal::EmptyKey => "user_pubkey_required",
            Refusal::OverLongKey => "user_pubkey_long",
            Refusal::KeyOutsideAlphabet => "user_pubkey_alphabet",
        }
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message())
    }
}

impl std::error::Error for Refusal {}

#[cfg(test)]
mod tests {
    use super::Refusal;

    const EVERY: [Refusal; 3] = [
        Refusal::EmptyKey,
        Refusal::OverLongKey,
        Refusal::KeyOutsideAlphabet,
    ];

    #[test]
    fn every_refusal_can_be_told_to_a_client() {
        for refusal in EVERY {
            assert!(!refusal.message().is_empty());
            assert!(refusal.message().is_ascii());
            assert!(!refusal.code().is_empty());
        }
    }
}

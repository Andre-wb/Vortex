use crate::challenge::secret::ChallengeSecret;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Claim {
    Missing,
    WrongPurpose,
    WrongAccount,
    Taken(ChallengeSecret),
}

impl Claim {
    pub fn outcome(&self) -> &'static str {
        match self {
            Claim::Missing => "missing",
            Claim::WrongPurpose => "wrong_purpose",
            Claim::WrongAccount => "wrong_account",
            Claim::Taken(_) => "taken",
        }
    }

    pub fn secret(&self) -> Option<&ChallengeSecret> {
        match self {
            Claim::Taken(secret) => Some(secret),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Claim;
    use crate::challenge::secret::ChallengeSecret;
    use crate::random::fixed_entropy::FixedEntropy;

    #[test]
    fn only_a_taken_challenge_hands_out_the_bytes_the_authenticator_signed() {
        let secret = ChallengeSecret::draw(&FixedEntropy::counting_from(0));
        assert_eq!(Claim::Taken(secret.clone()).secret(), Some(&secret));
        assert!(Claim::Missing.secret().is_none());
        assert!(Claim::WrongPurpose.secret().is_none());
        assert!(Claim::WrongAccount.secret().is_none());
    }

    #[test]
    fn every_outcome_names_itself_for_the_caller() {
        assert_eq!(Claim::Missing.outcome(), "missing");
        assert_eq!(Claim::WrongPurpose.outcome(), "wrong_purpose");
        assert_eq!(Claim::WrongAccount.outcome(), "wrong_account");
    }
}

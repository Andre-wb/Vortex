use crate::challenge::secret::ChallengeSecret;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    SessionMissing,
    AlreadyConfirmed,
    ChallengeMissing,
    ChallengeMismatch,
    Ready(ChallengeSecret),
}

impl Answer {
    pub fn outcome(&self) -> &'static str {
        match self {
            Answer::SessionMissing => "session_missing",
            Answer::AlreadyConfirmed => "already_confirmed",
            Answer::ChallengeMissing => "challenge_missing",
            Answer::ChallengeMismatch => "challenge_mismatch",
            Answer::Ready(_) => "ready",
        }
    }

    pub fn secret(&self) -> Option<&ChallengeSecret> {
        match self {
            Answer::Ready(secret) => Some(secret),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Answer;
    use crate::challenge::secret::ChallengeSecret;
    use crate::random::fixed_entropy::FixedEntropy;

    #[test]
    fn only_a_ready_answer_hands_out_the_secret_the_phone_must_sign() {
        let secret = ChallengeSecret::draw(&FixedEntropy::counting_from(0));
        assert_eq!(Answer::Ready(secret.clone()).secret(), Some(&secret));
        assert!(Answer::SessionMissing.secret().is_none());
        assert!(Answer::AlreadyConfirmed.secret().is_none());
        assert!(Answer::ChallengeMissing.secret().is_none());
        assert!(Answer::ChallengeMismatch.secret().is_none());
    }

    #[test]
    fn every_outcome_names_itself_for_the_caller() {
        assert_eq!(Answer::SessionMissing.outcome(), "session_missing");
        assert_eq!(Answer::AlreadyConfirmed.outcome(), "already_confirmed");
        assert_eq!(Answer::ChallengeMissing.outcome(), "challenge_missing");
        assert_eq!(Answer::ChallengeMismatch.outcome(), "challenge_mismatch");
    }
}

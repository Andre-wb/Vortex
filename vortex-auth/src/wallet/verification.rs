use crate::wallet::message::LinkMessage;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verification {
    NoChallenge,
    NotBase64,
    Mismatch,
    Matched(LinkMessage),
}

impl Verification {
    pub fn outcome(&self) -> &'static str {
        match self {
            Verification::NoChallenge => "no_challenge",
            Verification::NotBase64 => "not_base64",
            Verification::Mismatch => "mismatch",
            Verification::Matched(_) => "matched",
        }
    }

    pub fn matched(&self) -> Option<&LinkMessage> {
        match self {
            Verification::Matched(message) => Some(message),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Verification;
    use crate::account::user_id::UserId;
    use crate::challenge::secret::ChallengeSecret;
    use crate::random::fixed_entropy::FixedEntropy;
    use crate::wallet::message::LinkMessage;

    #[test]
    fn only_a_match_hands_out_the_bytes_to_verify_against() {
        let message = LinkMessage::of(
            UserId::of(7).unwrap(),
            &ChallengeSecret::draw(&FixedEntropy::counting_from(0)),
        );
        assert_eq!(
            Verification::Matched(message.clone()).matched(),
            Some(&message)
        );
        assert!(Verification::Mismatch.matched().is_none());
        assert!(Verification::NoChallenge.matched().is_none());
        assert!(Verification::NotBase64.matched().is_none());
    }

    #[test]
    fn every_outcome_names_itself_for_the_caller() {
        assert_eq!(Verification::NoChallenge.outcome(), "no_challenge");
        assert_eq!(Verification::NotBase64.outcome(), "not_base64");
        assert_eq!(Verification::Mismatch.outcome(), "mismatch");
    }
}

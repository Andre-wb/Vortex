use crate::error::{Result, StateError};
use crate::passkey::record::PasskeyChallenge;
use crate::passkey::session::PasskeySession;
use crate::ports::passkey_challenges::PasskeyChallenges;
use crate::token::ttl::Ttl;

pub struct UnavailablePasskeyChallenges;

impl Default for UnavailablePasskeyChallenges {
    fn default() -> Self {
        UnavailablePasskeyChallenges::new()
    }
}

impl UnavailablePasskeyChallenges {
    pub fn new() -> Self {
        UnavailablePasskeyChallenges
    }
}

impl PasskeyChallenges for UnavailablePasskeyChallenges {
    fn open(
        &self,
        _session: &PasskeySession,
        _record: &PasskeyChallenge,
        _ttl: Ttl,
        _now: f64,
    ) -> Result<()> {
        Err(StateError::Unavailable)
    }

    fn consume(&self, _session: &PasskeySession, _now: f64) -> Result<Option<PasskeyChallenge>> {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::UnavailablePasskeyChallenges;
    use crate::account::user_id::UserId;
    use crate::challenge::secret::ChallengeSecret;
    use crate::error::StateError;
    use crate::passkey::lifetime::challenge_ttl;
    use crate::passkey::purpose::Purpose;
    use crate::passkey::record::PasskeyChallenge;
    use crate::passkey::session::PasskeySession;
    use crate::ports::passkey_challenges::PasskeyChallenges;
    use crate::random::fixed_entropy::FixedEntropy;

    #[test]
    fn a_challenge_that_cannot_be_shared_is_refused_rather_than_kept_for_one_worker() {
        let store = UnavailablePasskeyChallenges::new();
        let record = PasskeyChallenge::new(
            ChallengeSecret::draw(&FixedEntropy::counting_from(0)),
            Purpose::Registration(UserId::of(7).unwrap()),
        );
        assert_eq!(
            store.open(
                &PasskeySession::parse("aaaa").unwrap(),
                &record,
                challenge_ttl(),
                1_000.0
            ),
            Err(StateError::Unavailable)
        );
    }

    #[test]
    fn a_reader_who_cannot_ask_says_the_session_is_gone() {
        let store = UnavailablePasskeyChallenges::new();
        assert_eq!(
            store.consume(&PasskeySession::parse("aaaa").unwrap(), 1_000.0),
            Ok(None)
        );
    }
}

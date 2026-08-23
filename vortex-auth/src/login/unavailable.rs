use crate::challenge::id::ChallengeId;
use crate::error::{Result, StateError};
use crate::login::record::LoginChallenge;
use crate::ports::login_challenges::LoginChallenges;
use crate::token::ttl::Ttl;

pub struct UnavailableLoginChallenges;

impl Default for UnavailableLoginChallenges {
    fn default() -> Self {
        UnavailableLoginChallenges::new()
    }
}

impl UnavailableLoginChallenges {
    pub fn new() -> Self {
        UnavailableLoginChallenges
    }
}

impl LoginChallenges for UnavailableLoginChallenges {
    fn open(
        &self,
        _id: &ChallengeId,
        _record: &LoginChallenge,
        _ttl: Ttl,
        _now: f64,
    ) -> Result<()> {
        Err(StateError::Unavailable)
    }

    fn consume(&self, _id: &ChallengeId, _now: f64) -> Result<Option<LoginChallenge>> {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::UnavailableLoginChallenges;
    use crate::challenge::id::ChallengeId;
    use crate::challenge::secret::ChallengeSecret;
    use crate::error::StateError;
    use crate::login::binding::Binding;
    use crate::login::lifetime::account_ttl;
    use crate::login::record::LoginChallenge;
    use crate::ports::login_challenges::LoginChallenges;
    use crate::random::fixed_entropy::FixedEntropy;

    #[test]
    fn a_challenge_that_cannot_be_shared_is_refused_rather_than_kept_for_one_worker() {
        let store = UnavailableLoginChallenges::new();
        let record = LoginChallenge::new(
            ChallengeSecret::draw(&FixedEntropy::counting_from(0)),
            Binding::Decoy,
        );
        assert_eq!(
            store.open(
                &ChallengeId::parse("aaaa").unwrap(),
                &record,
                account_ttl(),
                1_000.0
            ),
            Err(StateError::Unavailable)
        );
    }

    #[test]
    fn a_reader_who_cannot_ask_says_the_challenge_is_gone() {
        let store = UnavailableLoginChallenges::new();
        assert_eq!(
            store.consume(&ChallengeId::parse("aaaa").unwrap(), 1_000.0),
            Ok(None)
        );
    }
}

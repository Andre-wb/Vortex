use crate::account::user_id::UserId;
use crate::challenge::secret::ChallengeSecret;
use crate::error::{Result, StateError};
use crate::ports::wallet_challenges::WalletChallenges;
use crate::token::ttl::Ttl;

pub struct UnavailableWalletChallenges;

impl Default for UnavailableWalletChallenges {
    fn default() -> Self {
        UnavailableWalletChallenges::new()
    }
}

impl UnavailableWalletChallenges {
    pub fn new() -> Self {
        UnavailableWalletChallenges
    }
}

impl WalletChallenges for UnavailableWalletChallenges {
    fn remember(
        &self,
        _user: UserId,
        _secret: &ChallengeSecret,
        _ttl: Ttl,
        _now: f64,
    ) -> Result<()> {
        Err(StateError::Unavailable)
    }

    fn find(&self, _user: UserId, _now: f64) -> Result<Option<ChallengeSecret>> {
        Ok(None)
    }

    fn burn(&self, _user: UserId) -> Result<()> {
        Err(StateError::Unavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::UnavailableWalletChallenges;
    use crate::account::user_id::UserId;
    use crate::challenge::secret::ChallengeSecret;
    use crate::error::StateError;
    use crate::ports::wallet_challenges::WalletChallenges;
    use crate::random::fixed_entropy::FixedEntropy;
    use crate::wallet::lifetime::challenge_ttl;

    #[test]
    fn a_challenge_that_cannot_be_shared_is_refused_rather_than_kept_for_one_worker() {
        let store = UnavailableWalletChallenges::new();
        let user = UserId::of(7).unwrap();
        let secret = ChallengeSecret::draw(&FixedEntropy::counting_from(0));
        assert_eq!(
            store.remember(user, &secret, challenge_ttl(), 1_000.0),
            Err(StateError::Unavailable)
        );
        assert_eq!(store.burn(user), Err(StateError::Unavailable));
    }

    #[test]
    fn a_reader_who_cannot_ask_says_the_account_holds_no_challenge() {
        let store = UnavailableWalletChallenges::new();
        assert_eq!(store.find(UserId::of(7).unwrap(), 1_000.0), Ok(None));
    }
}

use std::collections::HashMap;

use parking_lot::RwLock;

use crate::account::user_id::UserId;
use crate::challenge::secret::ChallengeSecret;
use crate::error::Result;
use crate::ports::wallet_challenges::WalletChallenges;
use crate::token::ttl::Ttl;

struct Held {
    secret: ChallengeSecret,
    until: f64,
}

pub struct MemoryWalletChallenges {
    held: RwLock<HashMap<i64, Held>>,
}

impl Default for MemoryWalletChallenges {
    fn default() -> Self {
        MemoryWalletChallenges::new()
    }
}

impl MemoryWalletChallenges {
    pub fn new() -> Self {
        MemoryWalletChallenges {
            held: RwLock::new(HashMap::new()),
        }
    }

    pub fn len(&self) -> usize {
        self.held.read().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl WalletChallenges for MemoryWalletChallenges {
    fn remember(&self, user: UserId, secret: &ChallengeSecret, ttl: Ttl, now: f64) -> Result<()> {
        let mut held = self.held.write();
        held.retain(|_, kept| kept.until > now);
        held.insert(
            user.value(),
            Held {
                secret: secret.clone(),
                until: now + ttl.as_seconds() as f64,
            },
        );
        Ok(())
    }

    fn find(&self, user: UserId, now: f64) -> Result<Option<ChallengeSecret>> {
        Ok(match self.held.read().get(&user.value()) {
            Some(kept) if kept.until > now => Some(kept.secret.clone()),
            _ => None,
        })
    }

    fn burn(&self, user: UserId) -> Result<()> {
        self.held.write().remove(&user.value());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::MemoryWalletChallenges;
    use crate::account::user_id::UserId;
    use crate::challenge::secret::ChallengeSecret;
    use crate::ports::wallet_challenges::WalletChallenges;
    use crate::random::fixed_entropy::FixedEntropy;
    use crate::wallet::lifetime::challenge_ttl;

    fn user(value: i64) -> UserId {
        UserId::of(value).unwrap()
    }

    fn secret(first: u8) -> ChallengeSecret {
        ChallengeSecret::draw(&FixedEntropy::counting_from(first))
    }

    #[test]
    fn a_challenge_is_found_by_the_account_that_asked_for_it() {
        let store = MemoryWalletChallenges::new();
        let issued = secret(1);
        store
            .remember(user(7), &issued, challenge_ttl(), 1_000.0)
            .unwrap();
        assert_eq!(store.find(user(7), 1_000.0).unwrap(), Some(issued));
        assert_eq!(store.find(user(8), 1_000.0).unwrap(), None);
    }

    #[test]
    fn an_expired_challenge_reads_as_no_challenge_at_all() {
        let store = MemoryWalletChallenges::new();
        store
            .remember(user(7), &secret(1), challenge_ttl(), 1_000.0)
            .unwrap();
        assert!(store.find(user(7), 1_299.0).unwrap().is_some());
        assert!(store.find(user(7), 1_300.0).unwrap().is_none());
    }

    #[test]
    fn asking_again_replaces_the_challenge_the_account_holds() {
        let store = MemoryWalletChallenges::new();
        store
            .remember(user(7), &secret(1), challenge_ttl(), 1_000.0)
            .unwrap();
        let second = secret(200);
        store
            .remember(user(7), &second, challenge_ttl(), 1_010.0)
            .unwrap();
        assert_eq!(store.find(user(7), 1_010.0).unwrap(), Some(second));
    }

    #[test]
    fn a_burnt_challenge_is_gone() {
        let store = MemoryWalletChallenges::new();
        store
            .remember(user(7), &secret(1), challenge_ttl(), 1_000.0)
            .unwrap();
        store.burn(user(7)).unwrap();
        assert!(store.find(user(7), 1_000.0).unwrap().is_none());
    }

    #[test]
    fn writing_forgets_what_has_already_expired() {
        let store = MemoryWalletChallenges::new();
        store
            .remember(user(7), &secret(1), challenge_ttl(), 1_000.0)
            .unwrap();
        store
            .remember(user(8), &secret(9), challenge_ttl(), 2_000.0)
            .unwrap();
        assert_eq!(store.len(), 1);
    }
}

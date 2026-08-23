use std::collections::HashMap;

use parking_lot::RwLock;

use crate::challenge::id::ChallengeId;
use crate::error::Result;
use crate::login::record::LoginChallenge;
use crate::ports::login_challenges::LoginChallenges;
use crate::token::ttl::Ttl;

struct Held {
    record: LoginChallenge,
    until: f64,
}

pub struct MemoryLoginChallenges {
    held: RwLock<HashMap<String, Held>>,
}

impl Default for MemoryLoginChallenges {
    fn default() -> Self {
        MemoryLoginChallenges::new()
    }
}

impl MemoryLoginChallenges {
    pub fn new() -> Self {
        MemoryLoginChallenges {
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

impl LoginChallenges for MemoryLoginChallenges {
    fn open(&self, id: &ChallengeId, record: &LoginChallenge, ttl: Ttl, now: f64) -> Result<()> {
        let mut held = self.held.write();
        held.retain(|_, kept| kept.until > now);
        held.insert(
            id.as_str().to_owned(),
            Held {
                record: record.clone(),
                until: now + ttl.as_seconds() as f64,
            },
        );
        Ok(())
    }

    fn consume(&self, id: &ChallengeId, now: f64) -> Result<Option<LoginChallenge>> {
        let taken = self.held.write().remove(id.as_str());
        Ok(match taken {
            Some(kept) if kept.until > now => Some(kept.record),
            _ => None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::MemoryLoginChallenges;
    use crate::challenge::id::ChallengeId;
    use crate::challenge::secret::ChallengeSecret;
    use crate::login::binding::Binding;
    use crate::login::lifetime::account_ttl;
    use crate::login::record::LoginChallenge;
    use crate::ports::login_challenges::LoginChallenges;
    use crate::random::fixed_entropy::FixedEntropy;

    fn id(value: &str) -> ChallengeId {
        ChallengeId::parse(value).unwrap()
    }

    fn record() -> LoginChallenge {
        LoginChallenge::new(
            ChallengeSecret::draw(&FixedEntropy::counting_from(0)),
            Binding::Decoy,
        )
    }

    #[test]
    fn a_challenge_is_handed_back_once_and_only_once() {
        let store = MemoryLoginChallenges::new();
        let kept = record();
        store
            .open(&id("aaaa"), &kept, account_ttl(), 1_000.0)
            .unwrap();

        assert_eq!(store.consume(&id("aaaa"), 1_000.0).unwrap(), Some(kept));
        assert_eq!(store.consume(&id("aaaa"), 1_000.0).unwrap(), None);
    }

    #[test]
    fn an_expired_challenge_is_taken_away_and_reads_as_missing() {
        let store = MemoryLoginChallenges::new();
        store
            .open(&id("aaaa"), &record(), account_ttl(), 1_000.0)
            .unwrap();
        assert_eq!(store.consume(&id("aaaa"), 1_060.0).unwrap(), None);
        assert!(store.is_empty());
    }

    #[test]
    fn two_challenges_never_answer_for_each_other() {
        let store = MemoryLoginChallenges::new();
        store
            .open(&id("aaaa"), &record(), account_ttl(), 1_000.0)
            .unwrap();
        assert_eq!(store.consume(&id("bbbb"), 1_000.0).unwrap(), None);
        assert!(store.consume(&id("aaaa"), 1_000.0).unwrap().is_some());
    }

    #[test]
    fn opening_forgets_what_has_already_expired() {
        let store = MemoryLoginChallenges::new();
        store
            .open(&id("aaaa"), &record(), account_ttl(), 1_000.0)
            .unwrap();
        store
            .open(&id("bbbb"), &record(), account_ttl(), 2_000.0)
            .unwrap();
        assert_eq!(store.len(), 1);
    }
}

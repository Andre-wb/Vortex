use std::collections::HashMap;

use parking_lot::RwLock;

use crate::error::Result;
use crate::passkey::record::PasskeyChallenge;
use crate::passkey::session::PasskeySession;
use crate::ports::passkey_challenges::PasskeyChallenges;
use crate::token::ttl::Ttl;

struct Held {
    record: PasskeyChallenge,
    until: f64,
}

pub struct MemoryPasskeyChallenges {
    held: RwLock<HashMap<String, Held>>,
}

impl Default for MemoryPasskeyChallenges {
    fn default() -> Self {
        MemoryPasskeyChallenges::new()
    }
}

impl MemoryPasskeyChallenges {
    pub fn new() -> Self {
        MemoryPasskeyChallenges {
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

impl PasskeyChallenges for MemoryPasskeyChallenges {
    fn open(
        &self,
        session: &PasskeySession,
        record: &PasskeyChallenge,
        ttl: Ttl,
        now: f64,
    ) -> Result<()> {
        let mut held = self.held.write();
        held.retain(|_, kept| kept.until > now);
        held.insert(
            session.as_str().to_owned(),
            Held {
                record: record.clone(),
                until: now + ttl.as_seconds() as f64,
            },
        );
        Ok(())
    }

    fn consume(&self, session: &PasskeySession, now: f64) -> Result<Option<PasskeyChallenge>> {
        let taken = self.held.write().remove(session.as_str());
        Ok(match taken {
            Some(kept) if kept.until > now => Some(kept.record),
            _ => None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::MemoryPasskeyChallenges;
    use crate::account::user_id::UserId;
    use crate::challenge::secret::ChallengeSecret;
    use crate::passkey::lifetime::challenge_ttl;
    use crate::passkey::purpose::Purpose;
    use crate::passkey::record::PasskeyChallenge;
    use crate::passkey::session::PasskeySession;
    use crate::ports::passkey_challenges::PasskeyChallenges;
    use crate::random::fixed_entropy::FixedEntropy;

    fn session(value: &str) -> PasskeySession {
        PasskeySession::parse(value).unwrap()
    }

    fn record() -> PasskeyChallenge {
        PasskeyChallenge::new(
            ChallengeSecret::draw(&FixedEntropy::counting_from(0)),
            Purpose::Registration(UserId::of(7).unwrap()),
        )
    }

    #[test]
    fn a_challenge_is_handed_back_once_and_only_once() {
        let store = MemoryPasskeyChallenges::new();
        let kept = record();
        store
            .open(&session("aaaa"), &kept, challenge_ttl(), 1_000.0)
            .unwrap();

        assert_eq!(
            store.consume(&session("aaaa"), 1_000.0).unwrap(),
            Some(kept)
        );
        assert_eq!(store.consume(&session("aaaa"), 1_000.0).unwrap(), None);
    }

    #[test]
    fn an_expired_challenge_is_taken_away_and_reads_as_missing() {
        let store = MemoryPasskeyChallenges::new();
        store
            .open(&session("aaaa"), &record(), challenge_ttl(), 1_000.0)
            .unwrap();
        assert_eq!(store.consume(&session("aaaa"), 1_300.0).unwrap(), None);
        assert!(store.is_empty());
    }

    #[test]
    fn two_sessions_never_answer_for_each_other() {
        let store = MemoryPasskeyChallenges::new();
        store
            .open(&session("aaaa"), &record(), challenge_ttl(), 1_000.0)
            .unwrap();
        assert_eq!(store.consume(&session("bbbb"), 1_000.0).unwrap(), None);
        assert!(store.consume(&session("aaaa"), 1_000.0).unwrap().is_some());
    }

    #[test]
    fn opening_forgets_what_has_already_expired() {
        let store = MemoryPasskeyChallenges::new();
        store
            .open(&session("aaaa"), &record(), challenge_ttl(), 1_000.0)
            .unwrap();
        store
            .open(&session("bbbb"), &record(), challenge_ttl(), 2_000.0)
            .unwrap();
        assert_eq!(store.len(), 1);
    }
}

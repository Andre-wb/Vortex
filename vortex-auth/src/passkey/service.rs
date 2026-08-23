use std::sync::Arc;

use crate::account::user_id::UserId;
use crate::challenge::secret::ChallengeSecret;
use crate::error::Result;
use crate::passkey::claim::Claim;
use crate::passkey::lifetime::challenge_ttl;
use crate::passkey::purpose::Purpose;
use crate::passkey::record::PasskeyChallenge;
use crate::passkey::session::PasskeySession;
use crate::ports::clock::Clock;
use crate::ports::entropy::Entropy;
use crate::ports::passkey_challenges::PasskeyChallenges;

pub struct PasskeyService {
    challenges: Arc<dyn PasskeyChallenges>,
    clock: Arc<dyn Clock>,
    entropy: Arc<dyn Entropy>,
}

impl PasskeyService {
    pub fn new(
        challenges: Arc<dyn PasskeyChallenges>,
        clock: Arc<dyn Clock>,
        entropy: Arc<dyn Entropy>,
    ) -> Self {
        PasskeyService {
            challenges,
            clock,
            entropy,
        }
    }

    pub fn open(&self, secret: ChallengeSecret, purpose: Purpose) -> Result<PasskeySession> {
        let session = PasskeySession::draw(self.entropy.as_ref());
        let record = PasskeyChallenge::new(secret, purpose);
        self.challenges.open(
            &session,
            &record,
            challenge_ttl(),
            self.clock.unix_seconds(),
        )?;
        Ok(session)
    }

    pub fn claim_registration(&self, session: &PasskeySession, user: UserId) -> Result<Claim> {
        Ok(match self.take(session)? {
            None => Claim::Missing,
            Some(record) => match record.purpose() {
                Purpose::Login => Claim::WrongPurpose,
                Purpose::Registration(owner) if owner != user => Claim::WrongAccount,
                Purpose::Registration(_) => Claim::Taken(record.secret().clone()),
            },
        })
    }

    pub fn claim_login(&self, session: &PasskeySession) -> Result<Claim> {
        Ok(match self.take(session)? {
            None => Claim::Missing,
            Some(record) if record.purpose().is_login() => Claim::Taken(record.secret().clone()),
            Some(_) => Claim::WrongPurpose,
        })
    }

    fn take(&self, session: &PasskeySession) -> Result<Option<PasskeyChallenge>> {
        self.challenges.consume(session, self.clock.unix_seconds())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::PasskeyService;
    use crate::account::user_id::UserId;
    use crate::challenge::secret::ChallengeSecret;
    use crate::error::StateError;
    use crate::passkey::claim::Claim;
    use crate::passkey::memory::MemoryPasskeyChallenges;
    use crate::passkey::purpose::Purpose;
    use crate::passkey::unavailable::UnavailablePasskeyChallenges;
    use crate::random::fixed_entropy::FixedEntropy;
    use crate::time::manual_clock::ManualClock;

    fn service(clock: Arc<ManualClock>) -> PasskeyService {
        PasskeyService::new(
            Arc::new(MemoryPasskeyChallenges::new()),
            clock,
            Arc::new(FixedEntropy::counting_from(0)),
        )
    }

    fn secret() -> ChallengeSecret {
        ChallengeSecret::draw(&FixedEntropy::counting_from(200))
    }

    fn user(value: i64) -> UserId {
        UserId::of(value).unwrap()
    }

    #[test]
    fn the_registration_challenge_comes_back_to_the_account_that_asked_for_it() {
        let service = service(Arc::new(ManualClock::at(1_000.0)));
        let issued = secret();
        let session = service
            .open(issued.clone(), Purpose::Registration(user(7)))
            .unwrap();

        assert_eq!(
            service.claim_registration(&session, user(7)).unwrap(),
            Claim::Taken(issued)
        );
    }

    #[test]
    fn a_registration_challenge_of_one_account_is_not_claimed_by_another() {
        let service = service(Arc::new(ManualClock::at(1_000.0)));
        let session = service
            .open(secret(), Purpose::Registration(user(7)))
            .unwrap();
        assert_eq!(
            service.claim_registration(&session, user(8)).unwrap(),
            Claim::WrongAccount
        );
    }

    #[test]
    fn a_login_challenge_is_never_spent_as_a_registration_one() {
        let service = service(Arc::new(ManualClock::at(1_000.0)));
        let session = service.open(secret(), Purpose::Login).unwrap();
        assert_eq!(
            service.claim_registration(&session, user(7)).unwrap(),
            Claim::WrongPurpose
        );
    }

    #[test]
    fn a_registration_challenge_is_never_spent_as_a_login_one() {
        let service = service(Arc::new(ManualClock::at(1_000.0)));
        let session = service
            .open(secret(), Purpose::Registration(user(7)))
            .unwrap();
        assert_eq!(service.claim_login(&session).unwrap(), Claim::WrongPurpose);
    }

    #[test]
    fn a_challenge_is_spent_once_even_when_it_was_claimed_wrongly() {
        let service = service(Arc::new(ManualClock::at(1_000.0)));
        let session = service.open(secret(), Purpose::Login).unwrap();

        assert_eq!(
            service.claim_registration(&session, user(7)).unwrap(),
            Claim::WrongPurpose
        );
        assert_eq!(service.claim_login(&session).unwrap(), Claim::Missing);
    }

    #[test]
    fn a_challenge_older_than_its_lifetime_reads_as_missing() {
        let clock = Arc::new(ManualClock::at(1_000.0));
        let service = service(clock.clone());
        let session = service.open(secret(), Purpose::Login).unwrap();

        clock.advance(300.0);
        assert_eq!(service.claim_login(&session).unwrap(), Claim::Missing);
    }

    #[test]
    fn two_openings_never_share_a_session() {
        let service = service(Arc::new(ManualClock::at(1_000.0)));
        let first = service.open(secret(), Purpose::Login).unwrap();
        let second = service.open(secret(), Purpose::Login).unwrap();
        assert_ne!(first.as_str(), second.as_str());
    }

    #[test]
    fn without_shared_state_a_challenge_is_refused_instead_of_kept_for_one_worker() {
        let service = PasskeyService::new(
            Arc::new(UnavailablePasskeyChallenges::new()),
            Arc::new(ManualClock::at(1_000.0)),
            Arc::new(FixedEntropy::counting_from(0)),
        );
        assert_eq!(
            service.open(secret(), Purpose::Login),
            Err(StateError::Unavailable)
        );
    }
}

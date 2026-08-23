use std::sync::Arc;

use crate::account::user_id::UserId;
use crate::challenge::id::ChallengeId;
use crate::challenge::secret::ChallengeSecret;
use crate::error::Result;
use crate::login::binding::Binding;
use crate::login::claim::{AccountClaim, SessionClaim};
use crate::login::issued::IssuedChallenge;
use crate::login::key::LoginPublicKey;
use crate::login::lifetime::{account_ttl, qr_ttl};
use crate::login::record::LoginChallenge;
use crate::ports::clock::Clock;
use crate::ports::entropy::Entropy;
use crate::ports::login_challenges::LoginChallenges;
use crate::qr::session_id::QrSessionId;
use crate::token::ttl::Ttl;

pub struct LoginChallengeService {
    challenges: Arc<dyn LoginChallenges>,
    clock: Arc<dyn Clock>,
    entropy: Arc<dyn Entropy>,
}

impl LoginChallengeService {
    pub fn new(
        challenges: Arc<dyn LoginChallenges>,
        clock: Arc<dyn Clock>,
        entropy: Arc<dyn Entropy>,
    ) -> Self {
        LoginChallengeService {
            challenges,
            clock,
            entropy,
        }
    }

    pub fn issue_for_account(
        &self,
        user: UserId,
        pubkey: LoginPublicKey,
    ) -> Result<IssuedChallenge> {
        self.issue(Binding::Account { user, pubkey }, account_ttl())
    }

    pub fn issue_decoy(&self) -> Result<IssuedChallenge> {
        self.issue(Binding::Decoy, account_ttl())
    }

    pub fn issue_for_session(&self, session: &QrSessionId) -> Result<IssuedChallenge> {
        self.issue(Binding::QrSession(session.clone()), qr_ttl())
    }

    pub fn claim_for_account(&self, id: &ChallengeId, supplied: &str) -> Result<AccountClaim> {
        let record = match self.take(id)? {
            Some(record) => record,
            None => return Ok(AccountClaim::Missing),
        };
        if record.binding().is_decoy() {
            return Ok(AccountClaim::Missing);
        }
        Ok(match record.binding().account() {
            Some(user) if record.binding().answers_key(supplied) => AccountClaim::Taken {
                secret: record.secret().clone(),
                user,
            },
            _ => AccountClaim::Mismatch,
        })
    }

    pub fn claim_for_session(
        &self,
        id: &ChallengeId,
        session: &QrSessionId,
    ) -> Result<SessionClaim> {
        let record = match self.take(id)? {
            Some(record) => record,
            None => return Ok(SessionClaim::Missing),
        };
        Ok(if record.binding().answers_session(session) {
            SessionClaim::Taken(record.secret().clone())
        } else {
            SessionClaim::Mismatch
        })
    }

    fn issue(&self, binding: Binding, ttl: Ttl) -> Result<IssuedChallenge> {
        let id = ChallengeId::draw(self.entropy.as_ref());
        let secret = ChallengeSecret::draw(self.entropy.as_ref());
        let record = LoginChallenge::new(secret.clone(), binding);
        self.challenges
            .open(&id, &record, ttl, self.clock.unix_seconds())?;
        Ok(IssuedChallenge::new(id, secret, ttl.as_seconds()))
    }

    fn take(&self, id: &ChallengeId) -> Result<Option<LoginChallenge>> {
        self.challenges.consume(id, self.clock.unix_seconds())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::LoginChallengeService;
    use crate::account::user_id::UserId;
    use crate::challenge::id::ChallengeId;
    use crate::error::StateError;
    use crate::login::claim::{AccountClaim, SessionClaim};
    use crate::login::key::LoginPublicKey;
    use crate::login::memory::MemoryLoginChallenges;
    use crate::login::unavailable::UnavailableLoginChallenges;
    use crate::qr::session_id::QrSessionId;
    use crate::random::fixed_entropy::FixedEntropy;
    use crate::time::manual_clock::ManualClock;

    const KEY: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn service(clock: Arc<ManualClock>) -> LoginChallengeService {
        LoginChallengeService::new(
            Arc::new(MemoryLoginChallenges::new()),
            clock,
            Arc::new(FixedEntropy::counting_from(0)),
        )
    }

    fn key() -> LoginPublicKey {
        LoginPublicKey::parse(KEY).unwrap()
    }

    fn user() -> UserId {
        UserId::of(7).unwrap()
    }

    #[test]
    fn the_challenge_of_an_account_comes_back_with_that_account() {
        let service = service(Arc::new(ManualClock::at(1_000.0)));
        let issued = service.issue_for_account(user(), key()).unwrap();

        let claim = service.claim_for_account(issued.id(), KEY).unwrap();
        assert_eq!(claim.user(), Some(user()));
        assert_eq!(claim.secret(), Some(issued.secret()));
        assert_eq!(issued.expires_in(), 60);
    }

    #[test]
    fn a_challenge_is_spent_once() {
        let service = service(Arc::new(ManualClock::at(1_000.0)));
        let issued = service.issue_for_account(user(), key()).unwrap();

        assert!(service
            .claim_for_account(issued.id(), KEY)
            .unwrap()
            .secret()
            .is_some());
        assert_eq!(
            service.claim_for_account(issued.id(), KEY).unwrap(),
            AccountClaim::Missing
        );
    }

    #[test]
    fn another_key_never_claims_the_challenge() {
        let service = service(Arc::new(ManualClock::at(1_000.0)));
        let issued = service.issue_for_account(user(), key()).unwrap();
        assert_eq!(
            service
                .claim_for_account(issued.id(), &KEY.replace('0', "1"))
                .unwrap(),
            AccountClaim::Mismatch
        );
    }

    #[test]
    fn a_decoy_is_indistinguishable_from_a_challenge_that_never_existed() {
        let service = service(Arc::new(ManualClock::at(1_000.0)));
        let decoy = service.issue_decoy().unwrap();

        assert_eq!(decoy.expires_in(), 60);
        assert_eq!(
            service.claim_for_account(decoy.id(), KEY).unwrap(),
            AccountClaim::Missing
        );
        assert_eq!(
            service
                .claim_for_account(&ChallengeId::parse("neverissued").unwrap(), KEY)
                .unwrap(),
            AccountClaim::Missing
        );
    }

    #[test]
    fn a_qr_challenge_is_never_spent_as_an_account_one() {
        let service = service(Arc::new(ManualClock::at(1_000.0)));
        let session = QrSessionId::parse("abcdabcd").unwrap();
        let issued = service.issue_for_session(&session).unwrap();

        assert_eq!(issued.expires_in(), 300);
        assert_eq!(
            service.claim_for_account(issued.id(), KEY).unwrap(),
            AccountClaim::Mismatch
        );
    }

    #[test]
    fn a_qr_challenge_answers_only_the_session_it_was_bound_to() {
        let service = service(Arc::new(ManualClock::at(1_000.0)));
        let mine = QrSessionId::parse("abcdabcd").unwrap();
        let issued = service.issue_for_session(&mine).unwrap();

        assert_eq!(
            service
                .claim_for_session(issued.id(), &QrSessionId::parse("dcbadcba").unwrap())
                .unwrap(),
            SessionClaim::Mismatch
        );
    }

    #[test]
    fn a_session_claim_hands_back_the_secret_the_phone_must_answer() {
        let service = service(Arc::new(ManualClock::at(1_000.0)));
        let session = QrSessionId::parse("abcdabcd").unwrap();
        let issued = service.issue_for_session(&session).unwrap();

        assert_eq!(
            service.claim_for_session(issued.id(), &session).unwrap(),
            SessionClaim::Taken(issued.secret().clone())
        );
    }

    #[test]
    fn a_challenge_older_than_its_lifetime_reads_as_missing() {
        let clock = Arc::new(ManualClock::at(1_000.0));
        let service = service(clock.clone());
        let issued = service.issue_for_account(user(), key()).unwrap();

        clock.advance(60.0);
        assert_eq!(
            service.claim_for_account(issued.id(), KEY).unwrap(),
            AccountClaim::Missing
        );
    }

    #[test]
    fn without_shared_state_a_challenge_is_refused_instead_of_kept_for_one_worker() {
        let service = LoginChallengeService::new(
            Arc::new(UnavailableLoginChallenges::new()),
            Arc::new(ManualClock::at(1_000.0)),
            Arc::new(FixedEntropy::counting_from(0)),
        );
        assert_eq!(
            service.issue_for_account(user(), key()),
            Err(StateError::Unavailable)
        );
        assert_eq!(service.issue_decoy(), Err(StateError::Unavailable));
    }
}

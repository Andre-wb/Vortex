use std::sync::Arc;

use crate::account::user_id::UserId;
use crate::error::Result;
use crate::login::claim::SessionClaim;
use crate::login::service::LoginChallengeService;
use crate::ports::clock::Clock;
use crate::ports::entropy::Entropy;
use crate::ports::qr_sessions::QrSessions;
use crate::qr::answer::Answer;
use crate::qr::confirmation::Confirmation;
use crate::qr::handover::Handover;
use crate::qr::lifetime::session_ttl;
use crate::qr::opened::OpenedSession;
use crate::qr::record::QrSession;
use crate::qr::session_id::QrSessionId;

pub struct QrLoginService {
    challenges: Arc<LoginChallengeService>,
    sessions: Arc<dyn QrSessions>,
    clock: Arc<dyn Clock>,
    entropy: Arc<dyn Entropy>,
}

impl QrLoginService {
    pub fn new(
        challenges: Arc<LoginChallengeService>,
        sessions: Arc<dyn QrSessions>,
        clock: Arc<dyn Clock>,
        entropy: Arc<dyn Entropy>,
    ) -> Self {
        QrLoginService {
            challenges,
            sessions,
            clock,
            entropy,
        }
    }

    pub fn open(&self) -> Result<OpenedSession> {
        let session = QrSessionId::draw(self.entropy.as_ref());
        let issued = self.challenges.issue_for_session(&session)?;
        let record = QrSession::pending(issued.id().clone());
        self.sessions
            .open(&session, &record, session_ttl(), self.clock.unix_seconds())?;
        Ok(OpenedSession::new(
            session,
            issued.id().clone(),
            issued.secret().clone(),
            issued.expires_in(),
        ))
    }

    pub fn answer(&self, session: &QrSessionId) -> Result<Answer> {
        let held = match self.sessions.find(session, self.clock.unix_seconds())? {
            Some(held) => held,
            None => return Ok(Answer::SessionMissing),
        };
        if !held.state().is_pending() {
            return Ok(Answer::AlreadyConfirmed);
        }
        Ok(
            match self
                .challenges
                .claim_for_session(held.challenge(), session)?
            {
                SessionClaim::Missing => Answer::ChallengeMissing,
                SessionClaim::Mismatch => Answer::ChallengeMismatch,
                SessionClaim::Taken(secret) => Answer::Ready(secret),
            },
        )
    }

    pub fn confirm(&self, session: &QrSessionId, user: UserId) -> Result<Confirmation> {
        self.sessions
            .confirm(session, user, self.clock.unix_seconds())
    }

    pub fn hand_over(&self, session: &QrSessionId) -> Result<Handover> {
        self.sessions.hand_over(session, self.clock.unix_seconds())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::QrLoginService;
    use crate::account::user_id::UserId;
    use crate::error::StateError;
    use crate::login::memory::MemoryLoginChallenges;
    use crate::login::service::LoginChallengeService;
    use crate::login::unavailable::UnavailableLoginChallenges;
    use crate::qr::answer::Answer;
    use crate::qr::confirmation::Confirmation;
    use crate::qr::handover::Handover;
    use crate::qr::memory::MemoryQrSessions;
    use crate::qr::session_id::QrSessionId;
    use crate::random::fixed_entropy::FixedEntropy;
    use crate::time::manual_clock::ManualClock;

    fn service(clock: Arc<ManualClock>) -> QrLoginService {
        let entropy = Arc::new(FixedEntropy::counting_from(0));
        let challenges = Arc::new(LoginChallengeService::new(
            Arc::new(MemoryLoginChallenges::new()),
            clock.clone(),
            entropy.clone(),
        ));
        QrLoginService::new(
            challenges,
            Arc::new(MemoryQrSessions::new()),
            clock,
            entropy,
        )
    }

    fn user() -> UserId {
        UserId::of(7).unwrap()
    }

    #[test]
    fn the_desktop_gets_a_session_the_phone_can_answer() {
        let service = service(Arc::new(ManualClock::at(1_000.0)));
        let opened = service.open().unwrap();

        assert_eq!(opened.expires_in(), 300);
        assert_eq!(
            service.answer(opened.session()).unwrap(),
            Answer::Ready(opened.secret().clone())
        );
    }

    #[test]
    fn a_session_nobody_opened_is_missing() {
        let service = service(Arc::new(ManualClock::at(1_000.0)));
        assert_eq!(
            service
                .answer(&QrSessionId::parse("neveropened").unwrap())
                .unwrap(),
            Answer::SessionMissing
        );
    }

    #[test]
    fn the_challenge_behind_a_session_is_answered_only_once() {
        let service = service(Arc::new(ManualClock::at(1_000.0)));
        let opened = service.open().unwrap();

        assert!(service.answer(opened.session()).unwrap().secret().is_some());
        assert_eq!(
            service.answer(opened.session()).unwrap(),
            Answer::ChallengeMissing
        );
    }

    #[test]
    fn a_session_already_confirmed_is_never_answered_again() {
        let service = service(Arc::new(ManualClock::at(1_000.0)));
        let opened = service.open().unwrap();
        service.answer(opened.session()).unwrap();
        service.confirm(opened.session(), user()).unwrap();

        assert_eq!(
            service.answer(opened.session()).unwrap(),
            Answer::AlreadyConfirmed
        );
    }

    #[test]
    fn a_session_is_confirmed_once_and_handed_over_once() {
        let service = service(Arc::new(ManualClock::at(1_000.0)));
        let opened = service.open().unwrap();

        assert_eq!(
            service.hand_over(opened.session()).unwrap(),
            Handover::Pending
        );
        assert_eq!(
            service.confirm(opened.session(), user()).unwrap(),
            Confirmation::Confirmed
        );
        assert_eq!(
            service.confirm(opened.session(), user()).unwrap(),
            Confirmation::AlreadyConfirmed
        );
        assert_eq!(
            service.hand_over(opened.session()).unwrap(),
            Handover::Taken(user())
        );
        assert_eq!(
            service.hand_over(opened.session()).unwrap(),
            Handover::Missing
        );
    }

    #[test]
    fn two_sessions_never_share_an_identifier_or_a_challenge() {
        let service = service(Arc::new(ManualClock::at(1_000.0)));
        let first = service.open().unwrap();
        let second = service.open().unwrap();

        assert_ne!(first.session().as_str(), second.session().as_str());
        assert_ne!(first.challenge().as_str(), second.challenge().as_str());
        assert_ne!(first.secret(), second.secret());
    }

    #[test]
    fn a_session_older_than_its_lifetime_is_missing() {
        let clock = Arc::new(ManualClock::at(1_000.0));
        let service = service(clock.clone());
        let opened = service.open().unwrap();

        clock.advance(300.0);
        assert_eq!(
            service.answer(opened.session()).unwrap(),
            Answer::SessionMissing
        );
        assert_eq!(
            service.hand_over(opened.session()).unwrap(),
            Handover::Missing
        );
    }

    #[test]
    fn without_shared_state_a_session_is_refused_instead_of_kept_for_one_worker() {
        let clock = Arc::new(ManualClock::at(1_000.0));
        let entropy = Arc::new(FixedEntropy::counting_from(0));
        let service = QrLoginService::new(
            Arc::new(LoginChallengeService::new(
                Arc::new(UnavailableLoginChallenges::new()),
                clock.clone(),
                entropy.clone(),
            )),
            Arc::new(MemoryQrSessions::new()),
            clock,
            entropy,
        );
        assert_eq!(service.open(), Err(StateError::Unavailable));
    }
}

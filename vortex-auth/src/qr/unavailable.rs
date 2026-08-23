use crate::account::user_id::UserId;
use crate::error::{Result, StateError};
use crate::ports::qr_sessions::QrSessions;
use crate::qr::confirmation::Confirmation;
use crate::qr::handover::Handover;
use crate::qr::record::QrSession;
use crate::qr::session_id::QrSessionId;
use crate::token::ttl::Ttl;

pub struct UnavailableQrSessions;

impl Default for UnavailableQrSessions {
    fn default() -> Self {
        UnavailableQrSessions::new()
    }
}

impl UnavailableQrSessions {
    pub fn new() -> Self {
        UnavailableQrSessions
    }
}

impl QrSessions for UnavailableQrSessions {
    fn open(
        &self,
        _session: &QrSessionId,
        _record: &QrSession,
        _ttl: Ttl,
        _now: f64,
    ) -> Result<()> {
        Err(StateError::Unavailable)
    }

    fn find(&self, _session: &QrSessionId, _now: f64) -> Result<Option<QrSession>> {
        Ok(None)
    }

    fn confirm(&self, _session: &QrSessionId, _user: UserId, _now: f64) -> Result<Confirmation> {
        Ok(Confirmation::Missing)
    }

    fn hand_over(&self, _session: &QrSessionId, _now: f64) -> Result<Handover> {
        Ok(Handover::Missing)
    }
}

#[cfg(test)]
mod tests {
    use super::UnavailableQrSessions;
    use crate::account::user_id::UserId;
    use crate::challenge::id::ChallengeId;
    use crate::error::StateError;
    use crate::ports::qr_sessions::QrSessions;
    use crate::qr::confirmation::Confirmation;
    use crate::qr::handover::Handover;
    use crate::qr::lifetime::session_ttl;
    use crate::qr::record::QrSession;
    use crate::qr::session_id::QrSessionId;

    fn session() -> QrSessionId {
        QrSessionId::parse("aaaa").unwrap()
    }

    #[test]
    fn a_session_that_cannot_be_shared_is_refused_rather_than_kept_for_one_worker() {
        let store = UnavailableQrSessions::new();
        let record = QrSession::pending(ChallengeId::parse("aaaa").unwrap());
        assert_eq!(
            store.open(&session(), &record, session_ttl(), 1_000.0),
            Err(StateError::Unavailable)
        );
    }

    #[test]
    fn a_reader_who_cannot_ask_says_the_session_is_gone() {
        let store = UnavailableQrSessions::new();
        assert_eq!(store.find(&session(), 1_000.0), Ok(None));
        assert_eq!(
            store.confirm(&session(), UserId::of(7).unwrap(), 1_000.0),
            Ok(Confirmation::Missing)
        );
        assert_eq!(store.hand_over(&session(), 1_000.0), Ok(Handover::Missing));
    }
}

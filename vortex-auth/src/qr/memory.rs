use std::collections::HashMap;

use parking_lot::RwLock;

use crate::account::user_id::UserId;
use crate::error::Result;
use crate::ports::qr_sessions::QrSessions;
use crate::qr::confirmation::Confirmation;
use crate::qr::handover::Handover;
use crate::qr::record::QrSession;
use crate::qr::session_id::QrSessionId;
use crate::token::ttl::Ttl;

struct Held {
    record: QrSession,
    until: f64,
}

pub struct MemoryQrSessions {
    held: RwLock<HashMap<String, Held>>,
}

impl Default for MemoryQrSessions {
    fn default() -> Self {
        MemoryQrSessions::new()
    }
}

impl MemoryQrSessions {
    pub fn new() -> Self {
        MemoryQrSessions {
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

impl QrSessions for MemoryQrSessions {
    fn open(&self, session: &QrSessionId, record: &QrSession, ttl: Ttl, now: f64) -> Result<()> {
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

    fn find(&self, session: &QrSessionId, now: f64) -> Result<Option<QrSession>> {
        Ok(match self.held.read().get(session.as_str()) {
            Some(kept) if kept.until > now => Some(kept.record.clone()),
            _ => None,
        })
    }

    fn confirm(&self, session: &QrSessionId, user: UserId, now: f64) -> Result<Confirmation> {
        let mut held = self.held.write();
        let kept = match held.get_mut(session.as_str()) {
            Some(kept) if kept.until > now => kept,
            _ => return Ok(Confirmation::Missing),
        };
        if !kept.record.state().is_pending() {
            return Ok(Confirmation::AlreadyConfirmed);
        }
        kept.record = kept.record.confirmed_by(user);
        Ok(Confirmation::Confirmed)
    }

    fn hand_over(&self, session: &QrSessionId, now: f64) -> Result<Handover> {
        let mut held = self.held.write();
        let kept = match held.get(session.as_str()) {
            Some(kept) if kept.until > now => kept,
            _ => return Ok(Handover::Missing),
        };
        match kept.record.state().confirmed_by() {
            Some(user) => {
                held.remove(session.as_str());
                Ok(Handover::Taken(user))
            }
            None => Ok(Handover::Pending),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::MemoryQrSessions;
    use crate::account::user_id::UserId;
    use crate::challenge::id::ChallengeId;
    use crate::ports::qr_sessions::QrSessions;
    use crate::qr::confirmation::Confirmation;
    use crate::qr::handover::Handover;
    use crate::qr::lifetime::session_ttl;
    use crate::qr::record::QrSession;
    use crate::qr::session_id::QrSessionId;

    fn session(value: &str) -> QrSessionId {
        QrSessionId::parse(value).unwrap()
    }

    fn record() -> QrSession {
        QrSession::pending(ChallengeId::parse("0123456789abcdef0123456789abcdef").unwrap())
    }

    fn user() -> UserId {
        UserId::of(7).unwrap()
    }

    #[test]
    fn a_session_nobody_opened_is_missing_everywhere() {
        let store = MemoryQrSessions::new();
        assert_eq!(store.find(&session("aaaa"), 1_000.0).unwrap(), None);
        assert_eq!(
            store.confirm(&session("aaaa"), user(), 1_000.0).unwrap(),
            Confirmation::Missing
        );
        assert_eq!(
            store.hand_over(&session("aaaa"), 1_000.0).unwrap(),
            Handover::Missing
        );
    }

    #[test]
    fn a_pending_session_is_not_handed_over() {
        let store = MemoryQrSessions::new();
        store
            .open(&session("aaaa"), &record(), session_ttl(), 1_000.0)
            .unwrap();
        assert_eq!(
            store.hand_over(&session("aaaa"), 1_000.0).unwrap(),
            Handover::Pending
        );
    }

    #[test]
    fn a_session_is_confirmed_once_and_handed_over_once() {
        let store = MemoryQrSessions::new();
        store
            .open(&session("aaaa"), &record(), session_ttl(), 1_000.0)
            .unwrap();

        assert_eq!(
            store.confirm(&session("aaaa"), user(), 1_000.0).unwrap(),
            Confirmation::Confirmed
        );
        assert_eq!(
            store.confirm(&session("aaaa"), user(), 1_000.0).unwrap(),
            Confirmation::AlreadyConfirmed
        );
        assert_eq!(
            store.hand_over(&session("aaaa"), 1_000.0).unwrap(),
            Handover::Taken(user())
        );
        assert_eq!(
            store.hand_over(&session("aaaa"), 1_000.0).unwrap(),
            Handover::Missing
        );
    }

    #[test]
    fn confirming_keeps_the_challenge_the_session_was_opened_with() {
        let store = MemoryQrSessions::new();
        store
            .open(&session("aaaa"), &record(), session_ttl(), 1_000.0)
            .unwrap();
        store.confirm(&session("aaaa"), user(), 1_000.0).unwrap();

        let kept = store.find(&session("aaaa"), 1_000.0).unwrap().unwrap();
        assert_eq!(kept.challenge(), record().challenge());
        assert_eq!(kept.state().confirmed_by(), Some(user()));
    }

    #[test]
    fn an_expired_session_reads_as_missing() {
        let store = MemoryQrSessions::new();
        store
            .open(&session("aaaa"), &record(), session_ttl(), 1_000.0)
            .unwrap();
        assert_eq!(store.find(&session("aaaa"), 1_300.0).unwrap(), None);
        assert_eq!(
            store.confirm(&session("aaaa"), user(), 1_300.0).unwrap(),
            Confirmation::Missing
        );
    }

    #[test]
    fn opening_forgets_what_has_already_expired() {
        let store = MemoryQrSessions::new();
        store
            .open(&session("aaaa"), &record(), session_ttl(), 1_000.0)
            .unwrap();
        store
            .open(&session("bbbb"), &record(), session_ttl(), 2_000.0)
            .unwrap();
        assert_eq!(store.len(), 1);
    }
}

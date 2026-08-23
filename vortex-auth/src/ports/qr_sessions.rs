use crate::account::user_id::UserId;
use crate::error::Result;
use crate::qr::confirmation::Confirmation;
use crate::qr::handover::Handover;
use crate::qr::record::QrSession;
use crate::qr::session_id::QrSessionId;
use crate::token::ttl::Ttl;

pub trait QrSessions: Send + Sync {
    fn open(&self, session: &QrSessionId, record: &QrSession, ttl: Ttl, now: f64) -> Result<()>;

    fn find(&self, session: &QrSessionId, now: f64) -> Result<Option<QrSession>>;

    fn confirm(&self, session: &QrSessionId, user: UserId, now: f64) -> Result<Confirmation>;

    fn hand_over(&self, session: &QrSessionId, now: f64) -> Result<Handover>;
}

use crate::error::Result;
use crate::passkey::record::PasskeyChallenge;
use crate::passkey::session::PasskeySession;
use crate::token::ttl::Ttl;

pub trait PasskeyChallenges: Send + Sync {
    fn open(
        &self,
        session: &PasskeySession,
        record: &PasskeyChallenge,
        ttl: Ttl,
        now: f64,
    ) -> Result<()>;

    fn consume(&self, session: &PasskeySession, now: f64) -> Result<Option<PasskeyChallenge>>;
}

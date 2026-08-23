use crate::challenge::id::ChallengeId;
use crate::error::Result;
use crate::login::record::LoginChallenge;
use crate::token::ttl::Ttl;

pub trait LoginChallenges: Send + Sync {
    fn open(&self, id: &ChallengeId, record: &LoginChallenge, ttl: Ttl, now: f64) -> Result<()>;

    fn consume(&self, id: &ChallengeId, now: f64) -> Result<Option<LoginChallenge>>;
}

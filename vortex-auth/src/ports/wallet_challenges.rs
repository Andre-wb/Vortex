use crate::account::user_id::UserId;
use crate::challenge::secret::ChallengeSecret;
use crate::error::Result;
use crate::token::ttl::Ttl;

pub trait WalletChallenges: Send + Sync {
    fn remember(&self, user: UserId, secret: &ChallengeSecret, ttl: Ttl, now: f64) -> Result<()>;

    fn find(&self, user: UserId, now: f64) -> Result<Option<ChallengeSecret>>;

    fn burn(&self, user: UserId) -> Result<()>;
}

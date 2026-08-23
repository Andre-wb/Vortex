use crate::account::user_id::UserId;
use crate::error::Result;
use crate::token::ttl::Ttl;

pub trait PasswordMarkers: Send + Sync {
    fn arm(&self, user: UserId, ttl: Ttl, now: f64) -> Result<()>;

    fn armed(&self, user: UserId, now: f64) -> bool;

    fn disarm(&self, user: UserId) -> Result<()>;
}

use crate::error::Result;
use crate::token::jti::Jti;
use crate::token::ttl::Ttl;

pub trait Denylist: Send + Sync {
    fn remember(&self, jti: &Jti, ttl: Ttl, now: f64) -> Result<()>;

    fn holds(&self, jti: &Jti, now: f64) -> bool;
}

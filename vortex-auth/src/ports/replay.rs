use crate::error::Result;
use crate::token::jti::Jti;
use crate::token::ttl::Ttl;

pub trait ReplayGuard: Send + Sync {
    fn seen(&self, jti: &Jti, now: f64) -> Result<bool>;

    fn remember_if_new(&self, jti: &Jti, ttl: Ttl, now: f64) -> Result<bool>;
}

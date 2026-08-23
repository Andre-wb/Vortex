use crate::call::call_id::CallId;
use crate::error::Result;

pub trait RingClaims: Send + Sync {
    fn claim(&self, call: &CallId, until: f64, now: f64) -> Result<bool>;
}

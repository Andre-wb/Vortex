use crate::attempt::limit::Limit;
use crate::attempt::subject::Subject;
use crate::attempt::window::Window;
use crate::error::Result;

pub trait AttemptLimiter: Send + Sync {
    fn allow(&self, subject: &Subject, limit: Limit, window: Window, now: f64) -> Result<bool>;
}

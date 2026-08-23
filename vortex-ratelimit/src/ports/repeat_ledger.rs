use crate::antispam::digest::Digest;
use crate::attempt::subject::Subject;
use crate::attempt::window::Window;
use crate::error::Result;

pub trait RepeatLedger: Send + Sync {
    fn record(&self, subject: &Subject, digest: &Digest, window: Window, now: f64) -> Result<u32>;
}

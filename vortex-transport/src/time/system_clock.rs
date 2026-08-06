use crate::ports::clock::Clock;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl SystemClock {
    pub fn new() -> Self {
        SystemClock
    }
}

impl Clock for SystemClock {
    fn unix_seconds(&self) -> i64 {
        match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(elapsed) => elapsed.as_secs() as i64,
            Err(err) => -(err.duration().as_secs() as i64),
        }
    }
}

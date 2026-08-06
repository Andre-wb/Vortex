use crate::ports::clock::Clock;
use std::sync::atomic::{AtomicI64, Ordering};

#[derive(Debug)]
pub struct ManualClock {
    seconds: AtomicI64,
}

impl ManualClock {
    pub fn at(seconds: i64) -> Self {
        ManualClock {
            seconds: AtomicI64::new(seconds),
        }
    }

    pub fn set(&self, seconds: i64) {
        self.seconds.store(seconds, Ordering::SeqCst);
    }

    pub fn advance(&self, seconds: i64) {
        self.seconds.fetch_add(seconds, Ordering::SeqCst);
    }
}

impl Clock for ManualClock {
    fn unix_seconds(&self) -> i64 {
        self.seconds.load(Ordering::SeqCst)
    }
}

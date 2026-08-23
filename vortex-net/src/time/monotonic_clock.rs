use crate::ports::clock::Clock;
use std::time::Instant;

pub struct MonotonicClock {
    origin: Instant,
}

impl MonotonicClock {
    pub fn new() -> Self {
        MonotonicClock {
            origin: Instant::now(),
        }
    }
}

impl Default for MonotonicClock {
    fn default() -> Self {
        MonotonicClock::new()
    }
}

impl Clock for MonotonicClock {
    fn monotonic_seconds(&self) -> f64 {
        self.origin.elapsed().as_secs_f64()
    }
}

use std::time::{SystemTime, UNIX_EPOCH};

use crate::ports::clock::Clock;

#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl SystemClock {
    pub fn new() -> Self {
        SystemClock
    }
}

impl Clock for SystemClock {
    fn unix_seconds(&self) -> f64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|since| since.as_secs_f64())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::SystemClock;
    use crate::ports::clock::Clock;

    #[test]
    fn the_wall_clock_reads_a_moment_after_the_epoch() {
        assert!(SystemClock::new().unix_seconds() > 1_700_000_000.0);
    }
}

//! Часы, читающие системное время.

use crate::domain::timestamp::Timestamp;
use crate::ports::clock::Clock;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl SystemClock {
    pub fn new() -> Self {
        SystemClock
    }
}

impl Clock for SystemClock {
    fn now(&self) -> Timestamp {
        let millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0);
        Timestamp::from_unix_millis(millis)
    }
}

#[cfg(test)]
mod tests {
    use super::SystemClock;
    use crate::ports::clock::Clock;

    #[test]
    fn returns_a_recent_moment() {
        // Заведомо позже 2020-01-01.
        assert!(SystemClock::new().now().unix_secs() > 1_577_836_800);
    }
}

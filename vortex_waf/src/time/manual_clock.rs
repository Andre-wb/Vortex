//! Управляемые часы для тестов: время двигают вручную.

use crate::domain::timestamp::Timestamp;
use crate::ports::clock::Clock;
use std::sync::RwLock;

#[derive(Debug)]
pub struct ManualClock {
    current: RwLock<Timestamp>,
}

impl ManualClock {
    pub fn new(start: Timestamp) -> Self {
        ManualClock {
            current: RwLock::new(start),
        }
    }

    /// Часы, стартующие с 2026-01-01T00:00:00Z.
    pub fn at_epoch() -> Self {
        ManualClock::new(Timestamp::from_unix_secs(1_767_225_600))
    }

    pub fn advance_secs(&self, secs: u64) {
        let mut guard = self.current.write().expect("ManualClock отравлен");
        *guard = guard.plus_secs(secs);
    }

    pub fn set(&self, moment: Timestamp) {
        *self.current.write().expect("ManualClock отравлен") = moment;
    }
}

impl Default for ManualClock {
    fn default() -> Self {
        ManualClock::at_epoch()
    }
}

impl Clock for ManualClock {
    fn now(&self) -> Timestamp {
        *self.current.read().expect("ManualClock отравлен")
    }
}

#[cfg(test)]
mod tests {
    use super::ManualClock;
    use crate::ports::clock::Clock;

    #[test]
    fn time_moves_only_on_demand() {
        let clock = ManualClock::at_epoch();
        let t0 = clock.now();
        assert_eq!(clock.now(), t0);
        clock.advance_secs(90);
        assert_eq!(clock.now().unix_secs(), t0.unix_secs() + 90);
    }
}

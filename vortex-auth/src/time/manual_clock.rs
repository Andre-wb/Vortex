use parking_lot::RwLock;

use crate::ports::clock::Clock;

pub struct ManualClock {
    at: RwLock<f64>,
}

impl ManualClock {
    pub fn at(seconds: f64) -> Self {
        ManualClock {
            at: RwLock::new(seconds),
        }
    }

    pub fn advance(&self, seconds: f64) {
        *self.at.write() += seconds;
    }
}

impl Clock for ManualClock {
    fn unix_seconds(&self) -> f64 {
        *self.at.read()
    }
}

#[cfg(test)]
mod tests {
    use super::ManualClock;
    use crate::ports::clock::Clock;

    #[test]
    fn a_hand_moved_clock_reads_what_it_was_set_to() {
        let clock = ManualClock::at(1_000.0);
        assert_eq!(clock.unix_seconds(), 1_000.0);
        clock.advance(30.0);
        assert_eq!(clock.unix_seconds(), 1_030.0);
    }
}

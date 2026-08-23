use crate::ports::clock::Clock;
use parking_lot::RwLock;

pub struct ManualClock {
    seconds: RwLock<f64>,
}

impl ManualClock {
    pub fn at(seconds: f64) -> Self {
        ManualClock {
            seconds: RwLock::new(seconds),
        }
    }

    pub fn set(&self, seconds: f64) {
        *self.seconds.write() = seconds;
    }

    pub fn advance(&self, seconds: f64) {
        *self.seconds.write() += seconds;
    }
}

impl Clock for ManualClock {
    fn monotonic_seconds(&self) -> f64 {
        *self.seconds.read()
    }
}

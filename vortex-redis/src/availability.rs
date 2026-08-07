use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use parking_lot::Mutex;

pub struct Availability {
    recovery: Duration,
    degraded_until: Mutex<Option<Instant>>,
    failures: AtomicU64,
    recoveries: AtomicU64,
}

impl Availability {
    pub fn new(recovery: Duration) -> Self {
        Availability {
            recovery,
            degraded_until: Mutex::new(None),
            failures: AtomicU64::new(0),
            recoveries: AtomicU64::new(0),
        }
    }

    pub fn is_degraded(&self) -> bool {
        let mut degraded_until = self.degraded_until.lock();
        match *degraded_until {
            None => false,
            Some(deadline) if Instant::now() < deadline => true,
            Some(_) => {
                *degraded_until = None;
                self.recoveries.fetch_add(1, Ordering::Relaxed);
                false
            }
        }
    }

    pub fn note_failure(&self) {
        let mut degraded_until = self.degraded_until.lock();
        if degraded_until.is_none() {
            self.failures.fetch_add(1, Ordering::Relaxed);
        }
        *degraded_until = Some(Instant::now() + self.recovery);
    }

    pub fn note_success(&self) {
        if self.degraded_until.lock().take().is_some() {
            self.recoveries.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn failures(&self) -> u64 {
        self.failures.load(Ordering::Relaxed)
    }

    pub fn recoveries(&self) -> u64 {
        self.recoveries.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::Availability;
    use std::time::Duration;

    #[test]
    fn a_fresh_backbone_is_healthy() {
        let availability = Availability::new(Duration::from_secs(5));
        assert!(!availability.is_degraded());
        assert_eq!(availability.failures(), 0);
    }

    #[test]
    fn a_failure_opens_the_circuit_for_the_recovery_window() {
        let availability = Availability::new(Duration::from_secs(60));
        availability.note_failure();
        assert!(availability.is_degraded());
    }

    #[test]
    fn the_circuit_closes_once_the_window_passes() {
        let availability = Availability::new(Duration::from_millis(10));
        availability.note_failure();
        std::thread::sleep(Duration::from_millis(20));
        assert!(!availability.is_degraded());
        assert_eq!(availability.recoveries(), 1);
    }

    #[test]
    fn a_success_closes_the_circuit_immediately() {
        let availability = Availability::new(Duration::from_secs(60));
        availability.note_failure();
        availability.note_success();
        assert!(!availability.is_degraded());
    }

    #[test]
    fn a_burst_of_failures_counts_as_one_outage() {
        let availability = Availability::new(Duration::from_secs(60));
        availability.note_failure();
        availability.note_failure();
        availability.note_failure();
        assert_eq!(availability.failures(), 1);
    }
}

use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Default)]
pub struct Counters {
    inspected: AtomicU64,
    detected: AtomicU64,
}

impl Counters {
    pub fn inspected(&self) {
        self.inspected.fetch_add(1, Ordering::Relaxed);
    }

    pub fn detected(&self) {
        self.detected.fetch_add(1, Ordering::Relaxed);
    }

    pub fn total_inspected(&self) -> u64 {
        self.inspected.load(Ordering::Relaxed)
    }

    pub fn total_detected(&self) -> u64 {
        self.detected.load(Ordering::Relaxed)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stats {
    pub total_probes_detected: u64,
    pub total_requests_inspected: u64,
    pub known_probe_ips: usize,
    pub fingerprint_cache_size: usize,
}

#[cfg(test)]
mod tests {
    use super::Counters;

    #[test]
    fn a_detector_that_saw_nothing_counted_nothing() {
        let counters = Counters::default();
        assert_eq!(counters.total_inspected(), 0);
        assert_eq!(counters.total_detected(), 0);
    }

    #[test]
    fn every_request_is_counted_and_only_the_probes_among_them_are_counted_twice() {
        let counters = Counters::default();
        counters.inspected();
        counters.inspected();
        counters.detected();
        assert_eq!(counters.total_inspected(), 2);
        assert_eq!(counters.total_detected(), 1);
    }
}

use crate::active_probe::config::{DEFAULT_MAX_TRACKED_REQUESTS, DEFAULT_REQUEST_MEMORY};
use crate::ports::probe_sightings::ProbeSightings;
use std::collections::HashMap;
use std::sync::RwLock;

pub struct MemorySightings {
    capacity: usize,
    memory: f64,
    seen: RwLock<HashMap<String, f64>>,
}

impl Default for MemorySightings {
    fn default() -> Self {
        MemorySightings::new(DEFAULT_MAX_TRACKED_REQUESTS, DEFAULT_REQUEST_MEMORY)
    }
}

impl MemorySightings {
    pub fn new(capacity: usize, memory: f64) -> Self {
        MemorySightings {
            capacity,
            memory,
            seen: RwLock::new(HashMap::new()),
        }
    }
}

impl ProbeSightings for MemorySightings {
    fn remember(&self, fingerprint: &str, now: f64) -> Option<f64> {
        let mut seen = self.seen.write().unwrap();
        let before = seen.insert(fingerprint.to_owned(), now);
        if seen.len() > self.capacity {
            let cutoff = now - self.memory;
            seen.retain(|_, at| *at > cutoff);
        }
        before
    }

    fn forget_stale(&self, cutoff: f64) {
        self.seen.write().unwrap().retain(|_, at| *at > cutoff);
    }

    fn len(&self) -> usize {
        self.seen.read().unwrap().len()
    }
}

#[cfg(test)]
mod tests {
    use super::MemorySightings;
    use crate::ports::probe_sightings::ProbeSightings;

    #[test]
    fn a_request_seen_for_the_first_time_has_no_moment_before_it() {
        let seen = MemorySightings::default();
        assert_eq!(seen.remember("abcd", 100.0), None);
        assert_eq!(seen.len(), 1);
    }

    #[test]
    fn the_same_request_seen_again_reports_when_it_was_seen_before() {
        let seen = MemorySightings::default();
        seen.remember("abcd", 100.0);
        assert_eq!(seen.remember("abcd", 101.5), Some(100.0));
        assert_eq!(seen.remember("abcd", 102.0), Some(101.5));
        assert_eq!(seen.len(), 1);
    }

    #[test]
    fn what_is_older_than_the_memory_is_forgotten_when_it_is_asked_for() {
        let seen = MemorySightings::default();
        seen.remember("abcd", 100.0);
        seen.remember("efgh", 500.0);
        seen.forget_stale(300.0);
        assert_eq!(seen.len(), 1);
        assert_eq!(seen.remember("efgh", 501.0), Some(500.0));
        assert_eq!(seen.remember("abcd", 501.0), None);
    }

    #[test]
    fn the_store_never_grows_past_the_room_it_was_given() {
        let seen = MemorySightings::new(4, 10.0);
        for tick in 0..100 {
            seen.remember(&format!("fp{tick}"), 1000.0 + tick as f64);
        }
        assert!(seen.len() <= 11, "накопилось {}", seen.len());
    }
}

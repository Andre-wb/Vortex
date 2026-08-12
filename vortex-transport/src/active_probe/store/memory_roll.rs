use crate::active_probe::config::{DEFAULT_MAX_TRACKED_PROBES, DEFAULT_PROBE_MEMORY};
use crate::ports::probe_roll::ProbeRoll;
use std::collections::HashMap;
use std::sync::RwLock;

pub struct MemoryRoll {
    capacity: usize,
    memory: f64,
    peers: RwLock<HashMap<String, f64>>,
}

impl Default for MemoryRoll {
    fn default() -> Self {
        MemoryRoll::new(DEFAULT_MAX_TRACKED_PROBES, DEFAULT_PROBE_MEMORY)
    }
}

impl MemoryRoll {
    pub fn new(capacity: usize, memory: f64) -> Self {
        MemoryRoll {
            capacity,
            memory,
            peers: RwLock::new(HashMap::new()),
        }
    }
}

impl ProbeRoll for MemoryRoll {
    fn record(&self, peer: &str, now: f64) -> bool {
        let mut peers = self.peers.write().unwrap();
        let first_time = peers.insert(peer.to_owned(), now).is_none();
        if peers.len() > self.capacity {
            let cutoff = now - self.memory;
            peers.retain(|_, at| *at > cutoff);
        }
        while peers.len() > self.capacity {
            let oldest = peers
                .iter()
                .min_by(|left, right| left.1.total_cmp(right.1))
                .map(|(name, _)| name.clone());
            match oldest {
                Some(name) => {
                    peers.remove(&name);
                }
                None => break,
            }
        }
        first_time
    }

    fn holds(&self, peer: &str) -> bool {
        self.peers.read().unwrap().contains_key(peer)
    }

    fn forget_stale(&self, cutoff: f64) {
        self.peers.write().unwrap().retain(|_, at| *at > cutoff);
    }

    fn len(&self) -> usize {
        self.peers.read().unwrap().len()
    }
}

#[cfg(test)]
mod tests {
    use super::MemoryRoll;
    use crate::ports::probe_roll::ProbeRoll;

    #[test]
    fn a_peer_recorded_once_is_known_afterwards() {
        let roll = MemoryRoll::default();
        assert!(roll.record("203.0.113.7", 100.0));
        assert!(roll.holds("203.0.113.7"));
        assert!(!roll.holds("203.0.113.8"));
    }

    #[test]
    fn recording_the_same_peer_twice_does_not_count_it_twice() {
        let roll = MemoryRoll::default();
        assert!(roll.record("203.0.113.7", 100.0));
        assert!(!roll.record("203.0.113.7", 200.0));
        assert_eq!(roll.len(), 1);
    }

    #[test]
    fn a_peer_nobody_saw_for_a_long_time_is_forgotten() {
        let roll = MemoryRoll::default();
        roll.record("203.0.113.7", 100.0);
        roll.forget_stale(500.0);
        assert!(!roll.holds("203.0.113.7"));
        assert!(roll.is_empty());
    }

    #[test]
    fn the_roll_never_grows_past_the_room_it_was_given() {
        let roll = MemoryRoll::new(8, 3600.0);
        for tick in 0..1000 {
            roll.record(&format!("203.0.113.{tick}"), 100.0 + tick as f64);
        }
        assert!(roll.len() <= 8, "накопилось {}", roll.len());
    }

    #[test]
    fn what_is_dropped_when_the_roll_is_full_is_the_thing_seen_longest_ago() {
        let roll = MemoryRoll::new(2, 3600.0);
        roll.record("first", 100.0);
        roll.record("second", 200.0);
        roll.record("third", 300.0);
        assert!(!roll.holds("first"));
        assert!(roll.holds("second"));
        assert!(roll.holds("third"));
    }
}

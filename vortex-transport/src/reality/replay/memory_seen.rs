use crate::ports::seen_envelopes::SeenEnvelopes;
use std::collections::HashMap;
use std::sync::Mutex;

pub const DEFAULT_CAPACITY: usize = 100_000;

#[derive(Debug)]
pub struct MemorySeenEnvelopes {
    entries: Mutex<HashMap<Vec<u8>, i64>>,
    capacity: usize,
}

impl Default for MemorySeenEnvelopes {
    fn default() -> Self {
        MemorySeenEnvelopes::with_capacity(DEFAULT_CAPACITY)
    }
}

impl MemorySeenEnvelopes {
    pub fn new() -> Self {
        MemorySeenEnvelopes::default()
    }

    pub fn with_capacity(capacity: usize) -> Self {
        MemorySeenEnvelopes {
            entries: Mutex::new(HashMap::new()),
            capacity,
        }
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<Vec<u8>, i64>> {
        self.entries.lock().expect("кэш конвертов отравлен")
    }
}

impl SeenEnvelopes for MemorySeenEnvelopes {
    fn prune(&self, now: i64) {
        self.lock().retain(|_, expires_at| *expires_at > now);
    }

    fn remember(&self, envelope: &[u8], expires_at: i64) -> bool {
        let mut entries = self.lock();
        if entries.contains_key(envelope) {
            return false;
        }
        if entries.len() >= self.capacity {
            return false;
        }
        entries.insert(envelope.to_vec(), expires_at);
        true
    }

    fn len(&self) -> usize {
        self.lock().len()
    }
}

#[cfg(test)]
mod tests {
    use super::MemorySeenEnvelopes;
    use crate::ports::seen_envelopes::SeenEnvelopes;

    #[test]
    fn remembers_an_envelope_once() {
        let seen = MemorySeenEnvelopes::new();
        assert!(seen.remember(b"envelope", 100));
        assert!(!seen.remember(b"envelope", 100));
    }

    #[test]
    fn pruning_drops_only_expired_entries() {
        let seen = MemorySeenEnvelopes::new();
        seen.remember(b"old", 50);
        seen.remember(b"fresh", 150);
        seen.prune(100);
        assert_eq!(seen.len(), 1);
        assert!(!seen.remember(b"fresh", 150));
        assert!(seen.remember(b"old", 150));
    }

    #[test]
    fn expiry_is_exclusive_at_the_boundary() {
        let seen = MemorySeenEnvelopes::new();
        seen.remember(b"edge", 100);
        seen.prune(100);
        assert!(seen.is_empty());
    }

    #[test]
    fn a_full_cache_refuses_new_envelopes_instead_of_forgetting_old_ones() {
        let seen = MemorySeenEnvelopes::with_capacity(1);
        assert!(seen.remember(b"first", 100));
        assert!(!seen.remember(b"second", 100));
        seen.prune(200);
        assert!(seen.remember(b"second", 300));
    }
}

use std::collections::HashMap;

use parking_lot::RwLock;

use crate::error::Result;
use crate::ports::replay::ReplayGuard;
use crate::token::jti::Jti;
use crate::token::ttl::Ttl;

pub struct MemoryReplayGuard {
    spent: RwLock<HashMap<String, f64>>,
}

impl Default for MemoryReplayGuard {
    fn default() -> Self {
        MemoryReplayGuard::new()
    }
}

impl MemoryReplayGuard {
    pub fn new() -> Self {
        MemoryReplayGuard {
            spent: RwLock::new(HashMap::new()),
        }
    }

    pub fn len(&self) -> usize {
        self.spent.read().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn forget_everything(&self) {
        self.spent.write().clear();
    }
}

impl ReplayGuard for MemoryReplayGuard {
    fn seen(&self, jti: &Jti, now: f64) -> Result<bool> {
        Ok(match self.spent.read().get(jti.as_str()) {
            Some(until) => *until > now,
            None => false,
        })
    }

    fn remember_if_new(&self, jti: &Jti, ttl: Ttl, now: f64) -> Result<bool> {
        let mut spent = self.spent.write();
        spent.retain(|_, until| *until > now);
        if spent.contains_key(jti.as_str()) {
            return Ok(false);
        }
        spent.insert(jti.as_str().to_owned(), now + ttl.as_seconds() as f64);
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::MemoryReplayGuard;
    use crate::handoff::lifetime::remembered_ttl;
    use crate::ports::replay::ReplayGuard;
    use crate::token::jti::Jti;

    fn jti(value: &str) -> Jti {
        Jti::parse(value).unwrap()
    }

    #[test]
    fn the_first_arrival_is_recorded_and_the_second_is_not() {
        let guard = MemoryReplayGuard::new();
        assert!(guard
            .remember_if_new(&jti("once"), remembered_ttl(), 1_000.0)
            .unwrap());
        assert!(!guard
            .remember_if_new(&jti("once"), remembered_ttl(), 1_000.0)
            .unwrap());
    }

    #[test]
    fn what_was_spent_is_forgotten_when_no_clock_skew_could_still_cover_it() {
        let guard = MemoryReplayGuard::new();
        guard
            .remember_if_new(&jti("stale"), remembered_ttl(), 1_000.0)
            .unwrap();
        assert!(guard.seen(&jti("stale"), 1_599.0).unwrap());
        assert!(!guard.seen(&jti("stale"), 1_600.0).unwrap());
    }

    #[test]
    fn writing_forgets_what_has_already_expired() {
        let guard = MemoryReplayGuard::new();
        guard
            .remember_if_new(&jti("old"), remembered_ttl(), 1_000.0)
            .unwrap();
        guard
            .remember_if_new(&jti("new"), remembered_ttl(), 2_000.0)
            .unwrap();
        assert_eq!(guard.len(), 1);
    }

    #[test]
    fn a_cleared_guard_remembers_nothing() {
        let guard = MemoryReplayGuard::new();
        guard
            .remember_if_new(&jti("gone"), remembered_ttl(), 1_000.0)
            .unwrap();
        guard.forget_everything();
        assert!(guard.is_empty());
        assert!(!guard.seen(&jti("gone"), 1_000.0).unwrap());
    }
}

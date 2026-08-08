use std::collections::VecDeque;

use crate::latency::stats::Stats;

#[derive(Debug, Clone, PartialEq)]
pub struct History {
    samples: VecDeque<f64>,
    limit: usize,
    blocked: bool,
}

impl History {
    pub fn new(limit: usize) -> Self {
        History {
            samples: VecDeque::new(),
            limit: limit.max(1),
            blocked: false,
        }
    }

    pub fn push(&mut self, latency_ms: f64) {
        self.samples.push_back(latency_ms);
        while self.samples.len() > self.limit {
            self.samples.pop_front();
        }
    }

    pub fn samples(&self) -> Vec<f64> {
        self.samples.iter().copied().collect()
    }

    pub fn len(&self) -> usize {
        self.samples.len()
    }

    pub fn is_empty(&self) -> bool {
        self.samples.is_empty()
    }

    pub fn stats(&self) -> Stats {
        Stats::of(&self.samples())
    }

    pub fn was_blocked(&self) -> bool {
        self.blocked
    }

    pub fn remember_blocked(&mut self, blocked: bool) -> bool {
        let changed = self.blocked != blocked;
        self.blocked = blocked;
        changed
    }
}

#[cfg(test)]
mod tests {
    use super::History;

    #[test]
    fn the_history_never_grows_past_the_limit_it_was_given() {
        let mut history = History::new(3);
        for tick in 0..10 {
            history.push(tick as f64);
        }
        assert_eq!(history.len(), 3);
        assert_eq!(history.samples(), vec![7.0, 8.0, 9.0]);
    }

    #[test]
    fn a_history_that_holds_nothing_still_holds_one_sample() {
        let mut history = History::new(0);
        history.push(5.0);
        assert_eq!(history.samples(), vec![5.0]);
    }

    #[test]
    fn a_verdict_that_did_not_change_is_not_reported_twice() {
        let mut history = History::new(3);
        assert!(history.remember_blocked(true));
        assert!(!history.remember_blocked(true));
        assert!(history.remember_blocked(false));
        assert!(!history.remember_blocked(false));
    }

    #[test]
    fn a_fresh_history_has_not_been_blocked() {
        assert!(!History::new(3).was_blocked());
        assert!(History::new(3).is_empty());
    }
}

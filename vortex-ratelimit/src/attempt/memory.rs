use std::collections::HashMap;

use parking_lot::RwLock;

use crate::attempt::limit::Limit;
use crate::attempt::subject::Subject;
use crate::attempt::window::Window;
use crate::error::Result;
use crate::ports::attempt_limiter::AttemptLimiter;
use crate::ports::window_reset::WindowReset;

pub const MAX_TRACKED_SUBJECTS: usize = 50_000;

struct Counted {
    width: f64,
    stamps: Vec<f64>,
}

impl Counted {
    fn of(width: f64) -> Self {
        Counted {
            width,
            stamps: Vec::new(),
        }
    }

    fn forget_before(&mut self, now: f64) {
        let width = self.width;
        self.stamps.retain(|stamp| now - stamp < width);
    }
}

pub struct MemoryAttemptLimiter {
    counted: RwLock<HashMap<Subject, Counted>>,
    ceiling: usize,
}

impl Default for MemoryAttemptLimiter {
    fn default() -> Self {
        MemoryAttemptLimiter::new()
    }
}

impl MemoryAttemptLimiter {
    pub fn new() -> Self {
        MemoryAttemptLimiter::holding(MAX_TRACKED_SUBJECTS)
    }

    pub fn holding(ceiling: usize) -> Self {
        MemoryAttemptLimiter {
            counted: RwLock::new(HashMap::new()),
            ceiling: ceiling.max(1),
        }
    }

    pub fn forget_stale(&self, now: f64) {
        let mut counted = self.counted.write();
        counted.retain(|_, seen| {
            seen.forget_before(now);
            !seen.stamps.is_empty()
        });
    }

    pub fn tracked_subjects(&self) -> usize {
        self.counted.read().len()
    }
}

impl AttemptLimiter for MemoryAttemptLimiter {
    fn allow(&self, subject: &Subject, limit: Limit, window: Window, now: f64) -> Result<bool> {
        if self.tracked_subjects() >= self.ceiling {
            self.forget_stale(now);
        }

        let mut counted = self.counted.write();
        let seen = counted
            .entry(subject.clone())
            .or_insert_with(|| Counted::of(window.width()));
        seen.width = window.width();
        seen.forget_before(now);

        if seen.stamps.len() >= limit.value() as usize {
            return Ok(false);
        }
        seen.stamps.push(now);
        Ok(true)
    }
}

impl WindowReset for MemoryAttemptLimiter {
    fn forget(&self, subject: &Subject) -> Result<()> {
        self.counted.write().remove(subject);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::MemoryAttemptLimiter;
    use crate::attempt::limit::Limit;
    use crate::attempt::subject::Subject;
    use crate::attempt::window::Window;
    use crate::ports::attempt_limiter::AttemptLimiter;
    use crate::ports::window_reset::WindowReset;

    const BASE: f64 = 1_000.0;

    fn minute() -> Window {
        Window::seconds(60).unwrap()
    }

    fn three() -> Limit {
        Limit::of(3).unwrap()
    }

    fn address(value: &str) -> Subject {
        Subject::of("entry-attempts", value)
    }

    #[test]
    fn attempts_under_the_limit_are_allowed() {
        let limiter = MemoryAttemptLimiter::new();
        for _ in 0..3 {
            assert!(limiter
                .allow(&address("10.0.0.1"), three(), minute(), BASE)
                .unwrap());
        }
    }

    #[test]
    fn the_attempt_after_the_limit_is_refused() {
        let limiter = MemoryAttemptLimiter::new();
        for _ in 0..3 {
            limiter
                .allow(&address("10.0.0.1"), three(), minute(), BASE)
                .unwrap();
        }
        assert!(!limiter
            .allow(&address("10.0.0.1"), three(), minute(), BASE)
            .unwrap());
    }

    #[test]
    fn a_refused_attempt_does_not_push_the_window_forward() {
        let limiter = MemoryAttemptLimiter::new();
        for _ in 0..3 {
            limiter
                .allow(&address("10.0.0.1"), three(), minute(), BASE)
                .unwrap();
        }
        assert!(!limiter
            .allow(&address("10.0.0.1"), three(), minute(), BASE + 30.0)
            .unwrap());
        assert!(limiter
            .allow(&address("10.0.0.1"), three(), minute(), BASE + 60.0)
            .unwrap());
    }

    #[test]
    fn one_noisy_address_does_not_silence_another() {
        let limiter = MemoryAttemptLimiter::new();
        for _ in 0..3 {
            limiter
                .allow(&address("10.0.0.1"), three(), minute(), BASE)
                .unwrap();
        }
        assert!(limiter
            .allow(&address("10.0.0.2"), three(), minute(), BASE)
            .unwrap());
    }

    #[test]
    fn two_buckets_never_share_one_window() {
        let limiter = MemoryAttemptLimiter::new();
        for _ in 0..3 {
            limiter
                .allow(&Subject::of("entry-attempts", "7"), three(), minute(), BASE)
                .unwrap();
        }
        assert!(limiter
            .allow(&Subject::of("totp-attempts", "7"), three(), minute(), BASE)
            .unwrap());
    }

    #[test]
    fn stale_subjects_are_forgotten_instead_of_growing_without_bound() {
        let limiter = MemoryAttemptLimiter::new();
        for index in 0..100 {
            limiter
                .allow(
                    &address(&format!("10.0.0.{index}")),
                    three(),
                    minute(),
                    BASE,
                )
                .unwrap();
        }
        assert_eq!(limiter.tracked_subjects(), 100);
        limiter.forget_stale(BASE + 60.0);
        assert_eq!(limiter.tracked_subjects(), 0);
    }

    #[test]
    fn a_forgotten_subject_starts_its_window_from_scratch() {
        let limiter = MemoryAttemptLimiter::new();
        for _ in 0..3 {
            limiter
                .allow(&address("10.0.0.1"), three(), minute(), BASE)
                .unwrap();
        }
        assert!(!limiter
            .allow(&address("10.0.0.1"), three(), minute(), BASE)
            .unwrap());
        limiter.forget(&address("10.0.0.1")).unwrap();
        assert!(limiter
            .allow(&address("10.0.0.1"), three(), minute(), BASE)
            .unwrap());
    }

    #[test]
    fn forgetting_one_subject_leaves_every_other_window_counted() {
        let limiter = MemoryAttemptLimiter::new();
        for _ in 0..3 {
            limiter
                .allow(&address("10.0.0.1"), three(), minute(), BASE)
                .unwrap();
            limiter
                .allow(&address("10.0.0.2"), three(), minute(), BASE)
                .unwrap();
        }
        limiter.forget(&address("10.0.0.1")).unwrap();
        assert!(!limiter
            .allow(&address("10.0.0.2"), three(), minute(), BASE)
            .unwrap());
    }

    #[test]
    fn reaching_the_ceiling_forgets_the_stale_instead_of_refusing_the_attempt() {
        let limiter = MemoryAttemptLimiter::holding(4);
        for index in 0..4 {
            limiter
                .allow(
                    &address(&format!("10.0.0.{index}")),
                    three(),
                    minute(),
                    BASE,
                )
                .unwrap();
        }
        assert!(limiter
            .allow(&address("10.0.1.1"), three(), minute(), BASE + 60.0)
            .unwrap());
        assert_eq!(limiter.tracked_subjects(), 1);
    }
}

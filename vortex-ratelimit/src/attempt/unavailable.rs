use crate::attempt::limit::Limit;
use crate::attempt::subject::Subject;
use crate::attempt::window::Window;
use crate::error::{CountError, Result};
use crate::ports::attempt_limiter::AttemptLimiter;
use crate::ports::window_reset::WindowReset;

pub struct UnavailableAttemptLimiter;

impl Default for UnavailableAttemptLimiter {
    fn default() -> Self {
        UnavailableAttemptLimiter::new()
    }
}

impl UnavailableAttemptLimiter {
    pub fn new() -> Self {
        UnavailableAttemptLimiter
    }
}

impl AttemptLimiter for UnavailableAttemptLimiter {
    fn allow(&self, _subject: &Subject, _limit: Limit, _window: Window, _now: f64) -> Result<bool> {
        Err(CountError::Unavailable)
    }
}

impl WindowReset for UnavailableAttemptLimiter {
    fn forget(&self, _subject: &Subject) -> Result<()> {
        Err(CountError::Unavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::UnavailableAttemptLimiter;
    use crate::attempt::limit::Limit;
    use crate::attempt::subject::Subject;
    use crate::attempt::window::Window;
    use crate::error::CountError;
    use crate::ports::attempt_limiter::AttemptLimiter;
    use crate::ports::window_reset::WindowReset;

    #[test]
    fn an_attempt_nobody_can_count_is_never_reported_as_allowed() {
        let limiter = UnavailableAttemptLimiter::new();
        assert_eq!(
            limiter.allow(
                &Subject::of("entry-attempts", "10.0.0.1"),
                Limit::of(10).unwrap(),
                Window::seconds(60).unwrap(),
                1_000.0
            ),
            Err(CountError::Unavailable)
        );
    }

    #[test]
    fn a_window_nobody_can_reach_is_never_reported_as_forgotten() {
        let limiter = UnavailableAttemptLimiter::new();
        assert_eq!(
            limiter.forget(&Subject::of("flood-window", "1:7")),
            Err(CountError::Unavailable)
        );
    }
}

use std::sync::Arc;

use crate::attempt::limit::Limit;
use crate::attempt::member::Member;
use crate::attempt::subject::Subject;
use crate::attempt::verdict::Verdict;
use crate::attempt::window::Window;
use crate::ports::attempt_limiter::AttemptLimiter;

pub fn judge(
    limiter: &Arc<dyn AttemptLimiter>,
    bucket: &'static str,
    member: &Member,
    limit: Limit,
    window: Window,
    now: f64,
) -> Verdict {
    let subject = Subject::of(bucket, member.as_str());
    match limiter.allow(&subject, limit, window, now) {
        Ok(true) => Verdict::Allowed,
        Ok(false) => Verdict::OverTheLimit,
        Err(_) => Verdict::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::judge;
    use crate::attempt::limit::Limit;
    use crate::attempt::member::Member;
    use crate::attempt::memory::MemoryAttemptLimiter;
    use crate::attempt::unavailable::UnavailableAttemptLimiter;
    use crate::attempt::verdict::Verdict;
    use crate::attempt::window::Window;
    use crate::ports::attempt_limiter::AttemptLimiter;

    fn member() -> Member {
        Member::parse("10.0.0.1").unwrap()
    }

    #[test]
    fn attempts_up_to_the_limit_are_allowed_and_the_next_one_is_not() {
        let limiter: Arc<dyn AttemptLimiter> = Arc::new(MemoryAttemptLimiter::new());
        let limit = Limit::of(2).unwrap();
        let window = Window::seconds(60).unwrap();
        for _ in 0..2 {
            assert_eq!(
                judge(&limiter, "bucket", &member(), limit, window, 1_000.0),
                Verdict::Allowed
            );
        }
        assert_eq!(
            judge(&limiter, "bucket", &member(), limit, window, 1_000.0),
            Verdict::OverTheLimit
        );
    }

    #[test]
    fn an_attempt_nobody_can_count_is_refused_rather_than_waved_through() {
        let limiter: Arc<dyn AttemptLimiter> = Arc::new(UnavailableAttemptLimiter::new());
        assert_eq!(
            judge(
                &limiter,
                "bucket",
                &member(),
                Limit::of(2).unwrap(),
                Window::seconds(60).unwrap(),
                1_000.0
            ),
            Verdict::Unavailable
        );
    }
}

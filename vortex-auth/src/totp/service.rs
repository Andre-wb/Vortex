use std::sync::Arc;

use crate::account::user_id::UserId;
use crate::ports::clock::Clock;
use crate::totp::limits::{limit, window};
use vortex_ratelimit::attempt::subject::Subject;
use vortex_ratelimit::attempt::verdict::Verdict;
use vortex_ratelimit::ports::attempt_limiter::AttemptLimiter;

pub const BUCKET: &str = "totp-attempts";

pub struct TotpRateService {
    attempts: Arc<dyn AttemptLimiter>,
    clock: Arc<dyn Clock>,
}

impl TotpRateService {
    pub fn new(attempts: Arc<dyn AttemptLimiter>, clock: Arc<dyn Clock>) -> Self {
        TotpRateService { attempts, clock }
    }

    pub fn allow(&self, user: UserId) -> Verdict {
        let subject = Subject::of(BUCKET, user.value().to_string());
        match self
            .attempts
            .allow(&subject, limit(), window(), self.clock.unix_seconds())
        {
            Ok(true) => Verdict::Allowed,
            Ok(false) => Verdict::OverTheLimit,
            Err(_) => Verdict::Unavailable,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::TotpRateService;
    use crate::account::user_id::UserId;
    use crate::time::manual_clock::ManualClock;
    use vortex_ratelimit::attempt::memory::MemoryAttemptLimiter;
    use vortex_ratelimit::attempt::unavailable::UnavailableAttemptLimiter;
    use vortex_ratelimit::attempt::verdict::Verdict;

    fn service() -> (TotpRateService, Arc<ManualClock>) {
        let clock = Arc::new(ManualClock::at(1_000.0));
        (
            TotpRateService::new(Arc::new(MemoryAttemptLimiter::new()), clock.clone()),
            clock,
        )
    }

    fn user(value: i64) -> UserId {
        UserId::of(value).unwrap()
    }

    #[test]
    fn five_tries_at_the_code_pass_and_the_sixth_does_not() {
        let (service, _) = service();
        for _ in 0..5 {
            assert_eq!(service.allow(user(7)), Verdict::Allowed);
        }
        assert_eq!(service.allow(user(7)), Verdict::OverTheLimit);
    }

    #[test]
    fn one_account_never_spends_the_tries_of_another() {
        let (service, _) = service();
        for _ in 0..5 {
            service.allow(user(7));
        }
        assert_eq!(service.allow(user(8)), Verdict::Allowed);
    }

    #[test]
    fn the_five_minute_window_slides_forward_with_the_clock() {
        let (service, clock) = service();
        for _ in 0..5 {
            service.allow(user(7));
        }
        clock.advance(299.0);
        assert_eq!(service.allow(user(7)), Verdict::OverTheLimit);
        clock.advance(1.0);
        assert_eq!(service.allow(user(7)), Verdict::Allowed);
    }

    #[test]
    fn a_try_nobody_can_count_is_refused_rather_than_waved_through() {
        let service = TotpRateService::new(
            Arc::new(UnavailableAttemptLimiter::new()),
            Arc::new(ManualClock::at(1_000.0)),
        );
        assert_eq!(service.allow(user(7)), Verdict::Unavailable);
    }
}

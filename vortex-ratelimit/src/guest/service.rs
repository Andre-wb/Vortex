use std::sync::Arc;

use crate::attempt::counting::judge;
use crate::attempt::member::Member;
use crate::attempt::verdict::Verdict;
use crate::guest::limits::{limit, window};
use crate::ports::attempt_limiter::AttemptLimiter;

pub const BUCKET: &str = "guest-logins";

pub struct GuestLoginRateService {
    attempts: Arc<dyn AttemptLimiter>,
}

impl GuestLoginRateService {
    pub fn new(attempts: Arc<dyn AttemptLimiter>) -> Self {
        GuestLoginRateService { attempts }
    }

    pub fn allow(&self, address: &Member, now: f64) -> Verdict {
        judge(&self.attempts, BUCKET, address, limit(), window(), now)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::GuestLoginRateService;
    use crate::attempt::member::Member;
    use crate::attempt::memory::MemoryAttemptLimiter;
    use crate::attempt::unavailable::UnavailableAttemptLimiter;
    use crate::attempt::verdict::Verdict;

    const NOW: f64 = 1_000.0;

    fn service() -> GuestLoginRateService {
        GuestLoginRateService::new(Arc::new(MemoryAttemptLimiter::new()))
    }

    fn address(value: &str) -> Member {
        Member::parse(value).unwrap()
    }

    #[test]
    fn thirty_guest_logins_a_minute_pass_and_the_thirty_first_does_not() {
        let service = service();
        let source = address("10.0.0.1");
        for _ in 0..30 {
            assert_eq!(service.allow(&source, NOW), Verdict::Allowed);
        }
        assert_eq!(service.allow(&source, NOW), Verdict::OverTheLimit);
    }

    #[test]
    fn one_noisy_address_never_locks_out_another() {
        let service = service();
        for _ in 0..30 {
            service.allow(&address("10.0.0.1"), NOW);
        }
        assert_eq!(service.allow(&address("10.0.0.2"), NOW), Verdict::Allowed);
    }

    #[test]
    fn the_window_slides_forward_with_the_clock() {
        let service = service();
        let source = address("10.0.0.1");
        for _ in 0..30 {
            service.allow(&source, NOW);
        }
        assert_eq!(service.allow(&source, NOW + 59.0), Verdict::OverTheLimit);
        assert_eq!(service.allow(&source, NOW + 60.0), Verdict::Allowed);
    }

    #[test]
    fn a_login_nobody_can_count_is_refused_rather_than_waved_through() {
        let service = GuestLoginRateService::new(Arc::new(UnavailableAttemptLimiter::new()));
        assert_eq!(
            service.allow(&address("10.0.0.1"), NOW),
            Verdict::Unavailable
        );
    }
}

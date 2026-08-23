use std::sync::Arc;

use crate::attempt::counting::judge;
use crate::attempt::member::Member;
use crate::attempt::verdict::Verdict;
use crate::ports::attempt_limiter::AttemptLimiter;
use crate::push::limits::{registration_limit, wake_limit, window};

pub const REGISTRATION_BUCKET: &str = "push-registrations";
pub const WAKE_BUCKET: &str = "push-wakes";

pub struct PushRateService {
    attempts: Arc<dyn AttemptLimiter>,
}

impl PushRateService {
    pub fn new(attempts: Arc<dyn AttemptLimiter>) -> Self {
        PushRateService { attempts }
    }

    pub fn allow_registration(&self, address: &Member, now: f64) -> Verdict {
        judge(
            &self.attempts,
            REGISTRATION_BUCKET,
            address,
            registration_limit(),
            window(),
            now,
        )
    }

    pub fn allow_wake(&self, address: &Member, now: f64) -> Verdict {
        judge(
            &self.attempts,
            WAKE_BUCKET,
            address,
            wake_limit(),
            window(),
            now,
        )
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::PushRateService;
    use crate::attempt::member::Member;
    use crate::attempt::memory::MemoryAttemptLimiter;
    use crate::attempt::unavailable::UnavailableAttemptLimiter;
    use crate::attempt::verdict::Verdict;

    const NOW: f64 = 1_000.0;

    fn service() -> PushRateService {
        PushRateService::new(Arc::new(MemoryAttemptLimiter::new()))
    }

    fn address(value: &str) -> Member {
        Member::parse(value).unwrap()
    }

    #[test]
    fn sixty_registrations_a_minute_pass_and_the_sixty_first_does_not() {
        let service = service();
        let client = address("10.0.0.1");
        for _ in 0..60 {
            assert_eq!(service.allow_registration(&client, NOW), Verdict::Allowed);
        }
        assert_eq!(
            service.allow_registration(&client, NOW),
            Verdict::OverTheLimit
        );
    }

    #[test]
    fn registrations_and_wakes_are_counted_apart() {
        let service = service();
        let client = address("10.0.0.1");
        for _ in 0..60 {
            service.allow_registration(&client, NOW);
        }
        assert_eq!(service.allow_wake(&client, NOW), Verdict::Allowed);
    }

    #[test]
    fn six_hundred_wakes_a_minute_pass_and_the_six_hundred_and_first_does_not() {
        let service = service();
        let client = address("10.0.0.1");
        for _ in 0..600 {
            assert_eq!(service.allow_wake(&client, NOW), Verdict::Allowed);
        }
        assert_eq!(service.allow_wake(&client, NOW), Verdict::OverTheLimit);
    }

    #[test]
    fn a_call_nobody_can_count_is_refused_rather_than_waved_through() {
        let service = PushRateService::new(Arc::new(UnavailableAttemptLimiter::new()));
        assert_eq!(
            service.allow_registration(&address("10.0.0.1"), NOW),
            Verdict::Unavailable
        );
        assert_eq!(
            service.allow_wake(&address("10.0.0.1"), NOW),
            Verdict::Unavailable
        );
    }
}

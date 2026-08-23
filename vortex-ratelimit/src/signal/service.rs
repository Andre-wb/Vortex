use std::sync::Arc;

use crate::attempt::counting::judge;
use crate::attempt::member::Member;
use crate::attempt::verdict::Verdict;
use crate::ports::attempt_limiter::AttemptLimiter;
use crate::signal::limits::{limit, window};

pub const BUCKET: &str = "signal-messages";

pub struct SignalRateService {
    attempts: Arc<dyn AttemptLimiter>,
}

impl SignalRateService {
    pub fn new(attempts: Arc<dyn AttemptLimiter>) -> Self {
        SignalRateService { attempts }
    }

    pub fn allow(&self, user_id: i64, now: f64) -> Verdict {
        judge(
            &self.attempts,
            BUCKET,
            &Member::of_account(user_id),
            limit(),
            window(),
            now,
        )
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::SignalRateService;
    use crate::attempt::memory::MemoryAttemptLimiter;
    use crate::attempt::unavailable::UnavailableAttemptLimiter;
    use crate::attempt::verdict::Verdict;

    const NOW: f64 = 1_000.0;

    fn service() -> SignalRateService {
        SignalRateService::new(Arc::new(MemoryAttemptLimiter::new()))
    }

    #[test]
    fn one_hundred_messages_a_second_pass_and_the_next_one_does_not() {
        let service = service();
        for _ in 0..100 {
            assert_eq!(service.allow(7, NOW), Verdict::Allowed);
        }
        assert_eq!(service.allow(7, NOW), Verdict::OverTheLimit);
    }

    #[test]
    fn one_noisy_account_never_silences_another() {
        let service = service();
        for _ in 0..100 {
            service.allow(7, NOW);
        }
        assert_eq!(service.allow(8, NOW), Verdict::Allowed);
    }

    #[test]
    fn the_window_slides_forward_with_the_clock() {
        let service = service();
        for _ in 0..100 {
            service.allow(7, NOW);
        }
        assert_eq!(service.allow(7, NOW + 0.5), Verdict::OverTheLimit);
        assert_eq!(service.allow(7, NOW + 1.0), Verdict::Allowed);
    }

    #[test]
    fn a_message_nobody_can_count_is_refused_rather_than_waved_through() {
        let service = SignalRateService::new(Arc::new(UnavailableAttemptLimiter::new()));
        assert_eq!(service.allow(7, NOW), Verdict::Unavailable);
    }
}

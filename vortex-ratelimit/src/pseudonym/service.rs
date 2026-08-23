use std::sync::Arc;

use crate::attempt::counting::judge;
use crate::attempt::member::Member;
use crate::attempt::verdict::Verdict;
use crate::ports::attempt_limiter::AttemptLimiter;
use crate::pseudonym::limits::{operator_limit, operator_window};

pub const BUCKET: &str = "pseudonym-resolves";

pub struct PseudonymRateService {
    attempts: Arc<dyn AttemptLimiter>,
}

impl PseudonymRateService {
    pub fn new(attempts: Arc<dyn AttemptLimiter>) -> Self {
        PseudonymRateService { attempts }
    }

    pub fn allow(&self, resolves: u32, seconds: u64, now: f64) -> Verdict {
        match (operator_limit(resolves), operator_window(seconds)) {
            (Some(limit), Some(window)) => judge(
                &self.attempts,
                BUCKET,
                &Member::everyone(),
                limit,
                window,
                now,
            ),
            _ => Verdict::OverTheLimit,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::PseudonymRateService;
    use crate::attempt::memory::MemoryAttemptLimiter;
    use crate::attempt::unavailable::UnavailableAttemptLimiter;
    use crate::attempt::verdict::Verdict;

    const NOW: f64 = 1_000.0;

    fn service() -> PseudonymRateService {
        PseudonymRateService::new(Arc::new(MemoryAttemptLimiter::new()))
    }

    #[test]
    fn every_caller_spends_from_one_shared_budget() {
        let service = service();
        for _ in 0..3 {
            assert_eq!(service.allow(3, 60, NOW), Verdict::Allowed);
        }
        assert_eq!(service.allow(3, 60, NOW), Verdict::OverTheLimit);
    }

    #[test]
    fn the_window_slides_forward_with_the_clock() {
        let service = service();
        for _ in 0..3 {
            service.allow(3, 60, NOW);
        }
        assert_eq!(service.allow(3, 60, NOW + 59.0), Verdict::OverTheLimit);
        assert_eq!(service.allow(3, 60, NOW + 60.0), Verdict::Allowed);
    }

    #[test]
    fn a_limit_or_a_window_of_zero_lets_nobody_through() {
        let service = service();
        assert_eq!(service.allow(0, 60, NOW), Verdict::OverTheLimit);
        assert_eq!(service.allow(100, 0, NOW), Verdict::OverTheLimit);
    }

    #[test]
    fn a_resolve_nobody_can_count_is_refused_rather_than_waved_through() {
        let service = PseudonymRateService::new(Arc::new(UnavailableAttemptLimiter::new()));
        assert_eq!(service.allow(100, 60, NOW), Verdict::Unavailable);
    }
}

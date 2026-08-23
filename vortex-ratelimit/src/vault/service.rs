use std::sync::Arc;

use crate::attempt::counting::judge;
use crate::attempt::member::Member;
use crate::attempt::verdict::Verdict;
use crate::ports::attempt_limiter::AttemptLimiter;
use crate::vault::limits::{limit, window};

pub const BUCKET: &str = "vault-reads";

pub struct VaultRateService {
    attempts: Arc<dyn AttemptLimiter>,
}

impl VaultRateService {
    pub fn new(attempts: Arc<dyn AttemptLimiter>) -> Self {
        VaultRateService { attempts }
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

    use super::VaultRateService;
    use crate::attempt::memory::MemoryAttemptLimiter;
    use crate::attempt::unavailable::UnavailableAttemptLimiter;
    use crate::attempt::verdict::Verdict;

    const NOW: f64 = 1_000.0;

    fn service() -> VaultRateService {
        VaultRateService::new(Arc::new(MemoryAttemptLimiter::new()))
    }

    #[test]
    fn thirty_lookups_a_minute_pass_and_the_thirty_first_does_not() {
        let service = service();
        for _ in 0..30 {
            assert_eq!(service.allow(7, NOW), Verdict::Allowed);
        }
        assert_eq!(service.allow(7, NOW), Verdict::OverTheLimit);
    }

    #[test]
    fn one_account_never_spends_the_lookups_of_another() {
        let service = service();
        for _ in 0..30 {
            service.allow(7, NOW);
        }
        assert_eq!(service.allow(8, NOW), Verdict::Allowed);
    }

    #[test]
    fn the_window_slides_forward_with_the_clock() {
        let service = service();
        for _ in 0..30 {
            service.allow(7, NOW);
        }
        assert_eq!(service.allow(7, NOW + 59.0), Verdict::OverTheLimit);
        assert_eq!(service.allow(7, NOW + 60.0), Verdict::Allowed);
    }

    #[test]
    fn a_lookup_nobody_can_count_is_refused_rather_than_waved_through() {
        let service = VaultRateService::new(Arc::new(UnavailableAttemptLimiter::new()));
        assert_eq!(service.allow(7, NOW), Verdict::Unavailable);
    }
}

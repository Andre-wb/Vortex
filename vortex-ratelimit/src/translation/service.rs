use std::sync::Arc;

use crate::attempt::counting::judge;
use crate::attempt::member::Member;
use crate::attempt::verdict::Verdict;
use crate::ports::attempt_limiter::AttemptLimiter;
use crate::translation::limits::{limit, window};

pub const BUCKET: &str = "translations";

pub struct TranslationRateService {
    attempts: Arc<dyn AttemptLimiter>,
}

impl TranslationRateService {
    pub fn new(attempts: Arc<dyn AttemptLimiter>) -> Self {
        TranslationRateService { attempts }
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

    use super::TranslationRateService;
    use crate::attempt::memory::MemoryAttemptLimiter;
    use crate::attempt::unavailable::UnavailableAttemptLimiter;
    use crate::attempt::verdict::Verdict;

    const NOW: f64 = 1_000.0;

    fn service() -> TranslationRateService {
        TranslationRateService::new(Arc::new(MemoryAttemptLimiter::new()))
    }

    #[test]
    fn fifty_translations_an_hour_pass_and_the_fifty_first_does_not() {
        let service = service();
        for _ in 0..50 {
            assert_eq!(service.allow(7, NOW), Verdict::Allowed);
        }
        assert_eq!(service.allow(7, NOW), Verdict::OverTheLimit);
    }

    #[test]
    fn one_account_never_spends_the_translations_of_another() {
        let service = service();
        for _ in 0..50 {
            service.allow(7, NOW);
        }
        assert_eq!(service.allow(8, NOW), Verdict::Allowed);
    }

    #[test]
    fn the_hour_slides_forward_with_the_clock() {
        let service = service();
        for _ in 0..50 {
            service.allow(7, NOW);
        }
        assert_eq!(service.allow(7, NOW + 3_599.0), Verdict::OverTheLimit);
        assert_eq!(service.allow(7, NOW + 3_600.0), Verdict::Allowed);
    }

    #[test]
    fn a_translation_nobody_can_count_is_refused_rather_than_waved_through() {
        let service = TranslationRateService::new(Arc::new(UnavailableAttemptLimiter::new()));
        assert_eq!(service.allow(7, NOW), Verdict::Unavailable);
    }
}

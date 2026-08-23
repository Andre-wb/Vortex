use std::sync::Arc;

use crate::attempt::counting::judge;
use crate::attempt::member::Member;
use crate::attempt::verdict::Verdict;
use crate::ports::attempt_limiter::AttemptLimiter;
use crate::preview::limits::{limit, window};

pub const ACCOUNT_BUCKET: &str = "previews-by-account";
pub const ADDRESS_BUCKET: &str = "previews-by-address";

pub struct PreviewRateService {
    attempts: Arc<dyn AttemptLimiter>,
}

impl PreviewRateService {
    pub fn new(attempts: Arc<dyn AttemptLimiter>) -> Self {
        PreviewRateService { attempts }
    }

    pub fn allow_account(&self, user_id: i64, now: f64) -> Verdict {
        judge(
            &self.attempts,
            ACCOUNT_BUCKET,
            &Member::of_account(user_id),
            limit(),
            window(),
            now,
        )
    }

    pub fn allow_address(&self, address: &Member, now: f64) -> Verdict {
        judge(
            &self.attempts,
            ADDRESS_BUCKET,
            address,
            limit(),
            window(),
            now,
        )
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::PreviewRateService;
    use crate::attempt::member::Member;
    use crate::attempt::memory::MemoryAttemptLimiter;
    use crate::attempt::unavailable::UnavailableAttemptLimiter;
    use crate::attempt::verdict::Verdict;

    const NOW: f64 = 1_000.0;

    fn service() -> PreviewRateService {
        PreviewRateService::new(Arc::new(MemoryAttemptLimiter::new()))
    }

    fn address(value: &str) -> Member {
        Member::parse(value).unwrap()
    }

    #[test]
    fn thirty_previews_a_minute_pass_for_one_account_and_the_thirty_first_does_not() {
        let service = service();
        for _ in 0..30 {
            assert_eq!(service.allow_account(7, NOW), Verdict::Allowed);
        }
        assert_eq!(service.allow_account(7, NOW), Verdict::OverTheLimit);
    }

    #[test]
    fn thirty_previews_a_minute_pass_for_one_address_and_the_thirty_first_does_not() {
        let service = service();
        let client = address("10.0.0.1");
        for _ in 0..30 {
            assert_eq!(service.allow_address(&client, NOW), Verdict::Allowed);
        }
        assert_eq!(service.allow_address(&client, NOW), Verdict::OverTheLimit);
    }

    #[test]
    fn an_account_and_an_address_are_counted_apart() {
        let service = service();
        for _ in 0..30 {
            service.allow_account(7, NOW);
        }
        assert_eq!(
            service.allow_address(&address("10.0.0.1"), NOW),
            Verdict::Allowed
        );
    }

    #[test]
    fn a_preview_nobody_can_count_is_refused_rather_than_waved_through() {
        let service = PreviewRateService::new(Arc::new(UnavailableAttemptLimiter::new()));
        assert_eq!(service.allow_account(7, NOW), Verdict::Unavailable);
        assert_eq!(
            service.allow_address(&address("10.0.0.1"), NOW),
            Verdict::Unavailable
        );
    }
}

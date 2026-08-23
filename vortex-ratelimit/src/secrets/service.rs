use std::sync::Arc;

use crate::attempt::counting::judge;
use crate::attempt::member::Member;
use crate::attempt::verdict::Verdict;
use crate::ports::attempt_limiter::AttemptLimiter;
use crate::secrets::limits::{operator_limit, window};

pub const ADDRESS_BUCKET: &str = "secrets-by-address";
pub const ACCOUNT_BUCKET: &str = "secrets-by-account";

pub struct TransportSecretsRateService {
    attempts: Arc<dyn AttemptLimiter>,
}

impl TransportSecretsRateService {
    pub fn new(attempts: Arc<dyn AttemptLimiter>) -> Self {
        TransportSecretsRateService { attempts }
    }

    pub fn allow_address(&self, address: &Member, requests: u32, now: f64) -> Verdict {
        self.count(ADDRESS_BUCKET, address, requests, now)
    }

    pub fn allow_account(&self, user_id: i64, requests: u32, now: f64) -> Verdict {
        self.count(ACCOUNT_BUCKET, &Member::of_account(user_id), requests, now)
    }

    fn count(&self, bucket: &'static str, member: &Member, requests: u32, now: f64) -> Verdict {
        match operator_limit(requests) {
            Some(limit) => judge(&self.attempts, bucket, member, limit, window(), now),
            None => Verdict::OverTheLimit,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::TransportSecretsRateService;
    use crate::attempt::member::Member;
    use crate::attempt::memory::MemoryAttemptLimiter;
    use crate::attempt::unavailable::UnavailableAttemptLimiter;
    use crate::attempt::verdict::Verdict;

    const NOW: f64 = 1_000.0;

    fn service() -> TransportSecretsRateService {
        TransportSecretsRateService::new(Arc::new(MemoryAttemptLimiter::new()))
    }

    fn address(value: &str) -> Member {
        Member::parse(value).unwrap()
    }

    #[test]
    fn the_operator_limit_holds_for_an_hour() {
        let service = service();
        let client = address("10.0.0.1");
        for _ in 0..3 {
            assert_eq!(service.allow_address(&client, 3, NOW), Verdict::Allowed);
        }
        assert_eq!(
            service.allow_address(&client, 3, NOW),
            Verdict::OverTheLimit
        );
        assert_eq!(
            service.allow_address(&client, 3, NOW + 3_599.0),
            Verdict::OverTheLimit
        );
        assert_eq!(
            service.allow_address(&client, 3, NOW + 3_600.0),
            Verdict::Allowed
        );
    }

    #[test]
    fn an_address_and_an_account_are_counted_apart() {
        let service = service();
        for _ in 0..3 {
            service.allow_address(&address("10.0.0.1"), 3, NOW);
        }
        assert_eq!(service.allow_account(7, 3, NOW), Verdict::Allowed);
    }

    #[test]
    fn a_limit_of_zero_lets_nobody_through() {
        let service = service();
        assert_eq!(
            service.allow_address(&address("10.0.0.1"), 0, NOW),
            Verdict::OverTheLimit
        );
        assert_eq!(service.allow_account(7, 0, NOW), Verdict::OverTheLimit);
    }

    #[test]
    fn a_request_nobody_can_count_is_refused_rather_than_waved_through() {
        let service = TransportSecretsRateService::new(Arc::new(UnavailableAttemptLimiter::new()));
        assert_eq!(
            service.allow_address(&address("10.0.0.1"), 10, NOW),
            Verdict::Unavailable
        );
        assert_eq!(service.allow_account(7, 10, NOW), Verdict::Unavailable);
    }
}

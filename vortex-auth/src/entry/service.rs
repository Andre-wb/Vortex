use std::sync::Arc;

use crate::entry::address::ClientAddress;
use crate::entry::limits::{login_limit, registration_limit, window};
use crate::ports::clock::Clock;
use vortex_ratelimit::attempt::limit::Limit;
use vortex_ratelimit::attempt::subject::Subject;
use vortex_ratelimit::attempt::verdict::Verdict;
use vortex_ratelimit::ports::attempt_limiter::AttemptLimiter;

pub const BUCKET: &str = "entry-attempts";

pub struct EntryRateService {
    attempts: Arc<dyn AttemptLimiter>,
    clock: Arc<dyn Clock>,
}

impl EntryRateService {
    pub fn new(attempts: Arc<dyn AttemptLimiter>, clock: Arc<dyn Clock>) -> Self {
        EntryRateService { attempts, clock }
    }

    pub fn allow_login(&self, address: &ClientAddress) -> Verdict {
        self.judge(address, login_limit())
    }

    pub fn allow_registration(&self, address: &ClientAddress) -> Verdict {
        self.judge(address, registration_limit())
    }

    fn judge(&self, address: &ClientAddress, limit: Limit) -> Verdict {
        let subject = Subject::of(BUCKET, address.as_str());
        match self
            .attempts
            .allow(&subject, limit, window(), self.clock.unix_seconds())
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

    use super::EntryRateService;
    use crate::entry::address::ClientAddress;
    use crate::time::manual_clock::ManualClock;
    use vortex_ratelimit::attempt::memory::MemoryAttemptLimiter;
    use vortex_ratelimit::attempt::unavailable::UnavailableAttemptLimiter;
    use vortex_ratelimit::attempt::verdict::Verdict;

    fn address(value: &str) -> ClientAddress {
        ClientAddress::parse(value).unwrap()
    }

    fn service() -> (EntryRateService, Arc<ManualClock>) {
        let clock = Arc::new(ManualClock::at(1_000.0));
        (
            EntryRateService::new(Arc::new(MemoryAttemptLimiter::new()), clock.clone()),
            clock,
        )
    }

    #[test]
    fn ten_logins_a_minute_pass_and_the_eleventh_does_not() {
        let (service, _) = service();
        let client = address("10.0.0.1");
        for _ in 0..10 {
            assert_eq!(service.allow_login(&client), Verdict::Allowed);
        }
        assert_eq!(service.allow_login(&client), Verdict::OverTheLimit);
    }

    #[test]
    fn five_registrations_a_minute_pass_and_the_sixth_does_not() {
        let (service, _) = service();
        let client = address("10.0.0.1");
        for _ in 0..5 {
            assert_eq!(service.allow_registration(&client), Verdict::Allowed);
        }
        assert_eq!(service.allow_registration(&client), Verdict::OverTheLimit);
    }

    #[test]
    fn logins_and_registrations_from_one_address_share_one_window() {
        let (service, _) = service();
        let client = address("10.0.0.1");
        for _ in 0..5 {
            assert_eq!(service.allow_registration(&client), Verdict::Allowed);
        }
        for _ in 0..5 {
            assert_eq!(service.allow_login(&client), Verdict::Allowed);
        }
        assert_eq!(service.allow_login(&client), Verdict::OverTheLimit);
    }

    #[test]
    fn one_noisy_address_never_locks_out_another() {
        let (service, _) = service();
        for _ in 0..10 {
            service.allow_login(&address("10.0.0.1"));
        }
        assert_eq!(service.allow_login(&address("10.0.0.2")), Verdict::Allowed);
    }

    #[test]
    fn the_window_slides_forward_with_the_clock() {
        let (service, clock) = service();
        let client = address("10.0.0.1");
        for _ in 0..10 {
            service.allow_login(&client);
        }
        clock.advance(59.0);
        assert_eq!(service.allow_login(&client), Verdict::OverTheLimit);
        clock.advance(1.0);
        assert_eq!(service.allow_login(&client), Verdict::Allowed);
    }

    #[test]
    fn an_attempt_nobody_can_count_is_refused_rather_than_waved_through() {
        let service = EntryRateService::new(
            Arc::new(UnavailableAttemptLimiter::new()),
            Arc::new(ManualClock::at(1_000.0)),
        );
        assert_eq!(
            service.allow_login(&address("10.0.0.1")),
            Verdict::Unavailable
        );
        assert_eq!(
            service.allow_registration(&address("10.0.0.1")),
            Verdict::Unavailable
        );
    }
}

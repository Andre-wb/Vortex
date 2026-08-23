use std::sync::Arc;

use crate::attempt::counting::judge;
use crate::attempt::member::Member;
use crate::attempt::verdict::Verdict;
use crate::ports::attempt_limiter::AttemptLimiter;
use crate::replication::limits::{limit, window};

pub const BUCKET: &str = "replication-posts";

pub struct ReplicationRateService {
    attempts: Arc<dyn AttemptLimiter>,
}

impl ReplicationRateService {
    pub fn new(attempts: Arc<dyn AttemptLimiter>) -> Self {
        ReplicationRateService { attempts }
    }

    pub fn allow(&self, address: &Member, now: f64) -> Verdict {
        judge(&self.attempts, BUCKET, address, limit(), window(), now)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::ReplicationRateService;
    use crate::attempt::member::Member;
    use crate::attempt::memory::MemoryAttemptLimiter;
    use crate::attempt::unavailable::UnavailableAttemptLimiter;
    use crate::attempt::verdict::Verdict;

    const NOW: f64 = 1_000.0;

    fn service() -> ReplicationRateService {
        ReplicationRateService::new(Arc::new(MemoryAttemptLimiter::new()))
    }

    fn address(value: &str) -> Member {
        Member::parse(value).unwrap()
    }

    #[test]
    fn a_hundred_and_twenty_envelopes_pass_and_the_next_one_does_not() {
        let service = service();
        let origin = address("10.0.0.1");
        for _ in 0..120 {
            assert_eq!(service.allow(&origin, NOW), Verdict::Allowed);
        }
        assert_eq!(service.allow(&origin, NOW), Verdict::OverTheLimit);
    }

    #[test]
    fn one_noisy_origin_never_silences_another() {
        let service = service();
        for _ in 0..120 {
            service.allow(&address("10.0.0.1"), NOW);
        }
        assert_eq!(service.allow(&address("10.0.0.2"), NOW), Verdict::Allowed);
    }

    #[test]
    fn a_delivery_nobody_can_count_is_refused_rather_than_waved_through() {
        let service = ReplicationRateService::new(Arc::new(UnavailableAttemptLimiter::new()));
        assert_eq!(
            service.allow(&address("10.0.0.1"), NOW),
            Verdict::Unavailable
        );
    }
}

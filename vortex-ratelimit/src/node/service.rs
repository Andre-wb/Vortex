use std::sync::Arc;

use crate::attempt::counting::judge;
use crate::attempt::member::Member;
use crate::attempt::verdict::Verdict;
use crate::node::limits::{limit, window};
use crate::ports::attempt_limiter::AttemptLimiter;

pub const BUCKET: &str = "node-requests";

pub struct NodeRateService {
    attempts: Arc<dyn AttemptLimiter>,
}

impl NodeRateService {
    pub fn new(attempts: Arc<dyn AttemptLimiter>) -> Self {
        NodeRateService { attempts }
    }

    pub fn allow(&self, address: &Member, now: f64) -> Verdict {
        judge(&self.attempts, BUCKET, address, limit(), window(), now)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::NodeRateService;
    use crate::attempt::member::Member;
    use crate::attempt::memory::MemoryAttemptLimiter;
    use crate::attempt::unavailable::UnavailableAttemptLimiter;
    use crate::attempt::verdict::Verdict;

    const NOW: f64 = 1_000.0;

    fn service() -> NodeRateService {
        NodeRateService::new(Arc::new(MemoryAttemptLimiter::new()))
    }

    fn node(value: &str) -> Member {
        Member::parse(value).unwrap()
    }

    #[test]
    fn a_hundred_requests_a_minute_pass_and_the_hundred_and_first_does_not() {
        let service = service();
        let peer = node("node-7");
        for _ in 0..100 {
            assert_eq!(service.allow(&peer, NOW), Verdict::Allowed);
        }
        assert_eq!(service.allow(&peer, NOW), Verdict::OverTheLimit);
    }

    #[test]
    fn one_purpose_never_spends_the_budget_of_another() {
        let service = service();
        for _ in 0..100 {
            service.allow(&node("gossip:10.0.0.1"), NOW);
        }
        assert_eq!(
            service.allow(&node("manifest:10.0.0.1"), NOW),
            Verdict::Allowed
        );
    }

    #[test]
    fn a_request_nobody_can_count_is_refused_rather_than_waved_through() {
        let service = NodeRateService::new(Arc::new(UnavailableAttemptLimiter::new()));
        assert_eq!(service.allow(&node("node-7"), NOW), Verdict::Unavailable);
    }
}

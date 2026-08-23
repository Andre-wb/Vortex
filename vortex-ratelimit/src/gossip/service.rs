use std::sync::Arc;

use crate::attempt::counting::judge;
use crate::attempt::member::Member;
use crate::attempt::verdict::Verdict;
use crate::gossip::limits::{limit, window};
use crate::ports::attempt_limiter::AttemptLimiter;

pub const BUCKET: &str = "gossip-requests";

pub struct GossipRateService {
    attempts: Arc<dyn AttemptLimiter>,
}

impl GossipRateService {
    pub fn new(attempts: Arc<dyn AttemptLimiter>) -> Self {
        GossipRateService { attempts }
    }

    pub fn allow(&self, address: &Member, now: f64) -> Verdict {
        judge(&self.attempts, BUCKET, address, limit(), window(), now)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::GossipRateService;
    use crate::attempt::member::Member;
    use crate::attempt::memory::MemoryAttemptLimiter;
    use crate::attempt::unavailable::UnavailableAttemptLimiter;
    use crate::attempt::verdict::Verdict;

    const NOW: f64 = 1_000.0;

    fn service() -> GossipRateService {
        GossipRateService::new(Arc::new(MemoryAttemptLimiter::new()))
    }

    fn address(value: &str) -> Member {
        Member::parse(value).unwrap()
    }

    #[test]
    fn ten_packets_a_minute_pass_and_the_eleventh_does_not() {
        let service = service();
        let peer = address("10.0.0.1");
        for _ in 0..10 {
            assert_eq!(service.allow(&peer, NOW), Verdict::Allowed);
        }
        assert_eq!(service.allow(&peer, NOW), Verdict::OverTheLimit);
    }

    #[test]
    fn one_noisy_peer_never_silences_another() {
        let service = service();
        for _ in 0..10 {
            service.allow(&address("10.0.0.1"), NOW);
        }
        assert_eq!(service.allow(&address("10.0.0.2"), NOW), Verdict::Allowed);
    }

    #[test]
    fn the_window_slides_forward_with_the_clock() {
        let service = service();
        let peer = address("10.0.0.1");
        for _ in 0..10 {
            service.allow(&peer, NOW);
        }
        assert_eq!(service.allow(&peer, NOW + 59.0), Verdict::OverTheLimit);
        assert_eq!(service.allow(&peer, NOW + 60.0), Verdict::Allowed);
    }

    #[test]
    fn a_packet_nobody_can_count_is_refused_rather_than_waved_through() {
        let service = GossipRateService::new(Arc::new(UnavailableAttemptLimiter::new()));
        assert_eq!(
            service.allow(&address("10.0.0.1"), NOW),
            Verdict::Unavailable
        );
    }
}

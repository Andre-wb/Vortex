use std::sync::Arc;

use crate::antispam::limits::{link_limit, link_window};
use crate::antispam::outcome::SpamOutcome;
use crate::attempt::membership::Membership;
use crate::attempt::subject::Subject;
use crate::ports::attempt_limiter::AttemptLimiter;
use crate::ports::window_reset::WindowReset;

pub const BUCKET: &str = "antispam-links";

pub struct LinkSpamService {
    links: Arc<dyn AttemptLimiter>,
    reset: Arc<dyn WindowReset>,
}

impl LinkSpamService {
    pub fn new(links: Arc<dyn AttemptLimiter>, reset: Arc<dyn WindowReset>) -> Self {
        LinkSpamService { links, reset }
    }

    pub fn judge(&self, membership: Membership, now: f64) -> SpamOutcome {
        let subject = Subject::of(BUCKET, membership.member().as_str());

        match self.links.allow(&subject, link_limit(), link_window(), now) {
            Ok(true) => SpamOutcome::Clean,
            Ok(false) => {
                let _ = self.reset.forget(&subject);
                SpamOutcome::Spam
            }
            Err(_) => SpamOutcome::Unavailable,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::LinkSpamService;
    use crate::antispam::outcome::SpamOutcome;
    use crate::attempt::membership::Membership;
    use crate::attempt::memory::MemoryAttemptLimiter;
    use crate::attempt::unavailable::UnavailableAttemptLimiter;

    const NOW: f64 = 1_000.0;

    fn service() -> LinkSpamService {
        let limiter = Arc::new(MemoryAttemptLimiter::new());
        LinkSpamService::new(limiter.clone(), limiter)
    }

    #[test]
    fn two_links_pass_and_the_third_is_spam() {
        let service = service();
        let membership = Membership::of(1, 7);
        assert_eq!(service.judge(membership, NOW), SpamOutcome::Clean);
        assert_eq!(service.judge(membership, NOW), SpamOutcome::Clean);
        assert_eq!(service.judge(membership, NOW), SpamOutcome::Spam);
    }

    #[test]
    fn a_caught_member_starts_the_window_from_scratch() {
        let service = service();
        let membership = Membership::of(1, 7);
        for _ in 0..3 {
            service.judge(membership, NOW);
        }
        assert_eq!(service.judge(membership, NOW), SpamOutcome::Clean);
    }

    #[test]
    fn a_link_outside_the_window_starts_the_count_again() {
        let service = service();
        let membership = Membership::of(1, 7);
        service.judge(membership, NOW);
        service.judge(membership, NOW);
        assert_eq!(service.judge(membership, NOW + 60.0), SpamOutcome::Clean);
    }

    #[test]
    fn one_member_never_answers_for_another() {
        let service = service();
        service.judge(Membership::of(1, 7), NOW);
        service.judge(Membership::of(1, 7), NOW);
        assert_eq!(service.judge(Membership::of(1, 8), NOW), SpamOutcome::Clean);
        assert_eq!(service.judge(Membership::of(2, 7), NOW), SpamOutcome::Clean);
    }

    #[test]
    fn a_link_nobody_can_count_is_held_back_rather_than_waved_through() {
        let limiter = Arc::new(UnavailableAttemptLimiter::new());
        let service = LinkSpamService::new(limiter.clone(), limiter);
        assert_eq!(
            service.judge(Membership::of(1, 7), NOW),
            SpamOutcome::Unavailable
        );
    }
}

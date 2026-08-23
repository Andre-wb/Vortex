use std::sync::Arc;

use crate::attempt::membership::Membership;
use crate::attempt::subject::Subject;
use crate::flood::escalation::earns_a_ban;
use crate::flood::limits::{threshold, window};
use crate::flood::outcome::FloodOutcome;
use crate::ports::attempt_limiter::AttemptLimiter;
use crate::ports::strike_ledger::StrikeLedger;
use crate::ports::window_reset::WindowReset;

pub const WINDOW_BUCKET: &str = "flood-window";
pub const STRIKE_BUCKET: &str = "flood-strikes";

pub struct FloodService {
    messages: Arc<dyn AttemptLimiter>,
    reset: Arc<dyn WindowReset>,
    strikes: Arc<dyn StrikeLedger>,
}

impl FloodService {
    pub fn new(
        messages: Arc<dyn AttemptLimiter>,
        reset: Arc<dyn WindowReset>,
        strikes: Arc<dyn StrikeLedger>,
    ) -> Self {
        FloodService {
            messages,
            reset,
            strikes,
        }
    }

    pub fn judge(&self, membership: Membership, configured: i64, now: f64) -> FloodOutcome {
        let member = membership.member();
        let within = self.messages.allow(
            &Subject::of(WINDOW_BUCKET, member.as_str()),
            threshold(configured),
            window(),
            now,
        );

        match within {
            Ok(true) | Err(_) => FloodOutcome::Passed,
            Ok(false) => {
                let strikes = self
                    .strikes
                    .strike(&Subject::of(STRIKE_BUCKET, member.as_str()))
                    .unwrap_or(0);
                FloodOutcome::Flooding {
                    strikes,
                    earns_a_ban: earns_a_ban(strikes),
                }
            }
        }
    }

    pub fn forget_window(&self, membership: Membership) {
        let member = membership.member();
        let _ = self
            .reset
            .forget(&Subject::of(WINDOW_BUCKET, member.as_str()));
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::FloodService;
    use crate::attempt::membership::Membership;
    use crate::attempt::memory::MemoryAttemptLimiter;
    use crate::attempt::unavailable::UnavailableAttemptLimiter;
    use crate::flood::limits::DEFAULT_THRESHOLD;
    use crate::flood::memory::MemoryStrikeLedger;
    use crate::flood::outcome::FloodOutcome;
    use crate::flood::unavailable::UnavailableStrikeLedger;

    const NOW: f64 = 1_000.0;
    const FIFTEEN: i64 = 15;

    fn service() -> FloodService {
        let window = Arc::new(MemoryAttemptLimiter::new());
        FloodService::new(window.clone(), window, Arc::new(MemoryStrikeLedger::new()))
    }

    fn flood(service: &FloodService, membership: Membership, times: u32) -> FloodOutcome {
        let mut last = FloodOutcome::Passed;
        for _ in 0..times {
            last = service.judge(membership, FIFTEEN, NOW);
        }
        last
    }

    #[test]
    fn fifteen_messages_in_the_window_pass_and_the_sixteenth_does_not() {
        let service = service();
        let member = Membership::of(1, 7);
        for _ in 0..15 {
            assert_eq!(service.judge(member, FIFTEEN, NOW), FloodOutcome::Passed);
        }
        assert_eq!(
            service.judge(member, FIFTEEN, NOW),
            FloodOutcome::Flooding {
                strikes: 1,
                earns_a_ban: false
            }
        );
    }

    #[test]
    fn a_room_with_a_lower_threshold_penalises_sooner() {
        let service = service();
        let member = Membership::of(1, 7);
        for _ in 0..5 {
            assert_eq!(service.judge(member, 5, NOW), FloodOutcome::Passed);
        }
        assert!(service.judge(member, 5, NOW).flooding());
    }

    #[test]
    fn a_room_that_names_no_threshold_gets_the_default() {
        let service = service();
        let member = Membership::of(1, 7);
        for _ in 0..DEFAULT_THRESHOLD {
            assert_eq!(service.judge(member, 0, NOW), FloodOutcome::Passed);
        }
        assert!(service.judge(member, 0, NOW).flooding());
    }

    #[test]
    fn the_third_penalty_earns_a_ban() {
        let service = service();
        let member = Membership::of(1, 7);
        for expected in 1..=2 {
            let outcome = flood(&service, member, 16);
            assert_eq!(outcome.strikes(), expected);
            assert!(!outcome.earns_a_ban());
            service.forget_window(member);
        }
        let outcome = flood(&service, member, 16);
        assert_eq!(outcome.strikes(), 3);
        assert!(outcome.earns_a_ban());
    }

    #[test]
    fn a_forgotten_window_gives_the_member_a_fresh_budget() {
        let service = service();
        let member = Membership::of(1, 7);
        assert!(flood(&service, member, 16).flooding());
        service.forget_window(member);
        assert_eq!(service.judge(member, FIFTEEN, NOW), FloodOutcome::Passed);
    }

    #[test]
    fn one_member_never_spends_the_budget_of_another() {
        let service = service();
        assert!(flood(&service, Membership::of(1, 7), 16).flooding());
        assert_eq!(
            service.judge(Membership::of(1, 8), FIFTEEN, NOW),
            FloodOutcome::Passed
        );
        assert_eq!(
            service.judge(Membership::of(2, 7), FIFTEEN, NOW),
            FloodOutcome::Passed
        );
    }

    #[test]
    fn the_window_slides_forward_with_the_clock() {
        let service = service();
        let member = Membership::of(1, 7);
        assert!(flood(&service, member, 16).flooding());
        assert!(service.judge(member, FIFTEEN, NOW + 9.0).flooding());
        assert_eq!(
            service.judge(member, FIFTEEN, NOW + 10.0),
            FloodOutcome::Passed
        );
    }

    #[test]
    fn a_message_nobody_can_count_travels_instead_of_being_dropped() {
        let unavailable = Arc::new(UnavailableAttemptLimiter::new());
        let service = FloodService::new(
            unavailable.clone(),
            unavailable,
            Arc::new(MemoryStrikeLedger::new()),
        );
        assert_eq!(
            service.judge(Membership::of(1, 7), FIFTEEN, NOW),
            FloodOutcome::Passed
        );
    }

    #[test]
    fn a_penalty_nobody_can_record_never_earns_a_ban() {
        let window = Arc::new(MemoryAttemptLimiter::new());
        let service = FloodService::new(
            window.clone(),
            window,
            Arc::new(UnavailableStrikeLedger::new()),
        );
        let member = Membership::of(1, 7);
        let outcome = flood(&service, member, 16);
        assert!(outcome.flooding());
        assert_eq!(outcome.strikes(), 0);
        assert!(!outcome.earns_a_ban());
    }
}

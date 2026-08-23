use std::sync::Arc;

use crate::error::Result;
use crate::handoff::acceptance::Acceptance;
use crate::handoff::lifetime::remembered_ttl;
use crate::ports::clock::Clock;
use crate::ports::replay::ReplayGuard;
use crate::token::jti::Jti;

pub struct ReplayService {
    guard: Arc<dyn ReplayGuard>,
    clock: Arc<dyn Clock>,
}

impl ReplayService {
    pub fn new(guard: Arc<dyn ReplayGuard>, clock: Arc<dyn Clock>) -> Self {
        ReplayService { guard, clock }
    }

    pub fn seen(&self, jti: &Jti) -> Result<bool> {
        self.guard.seen(jti, self.clock.unix_seconds())
    }

    pub fn accept(&self, jti: &Jti) -> Result<Acceptance> {
        let now = self.clock.unix_seconds();
        let recorded = self.guard.remember_if_new(jti, remembered_ttl(), now)?;
        Ok(if recorded {
            Acceptance::Accepted
        } else {
            Acceptance::Replayed
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::ReplayService;
    use crate::error::StateError;
    use crate::handoff::acceptance::Acceptance;
    use crate::handoff::memory::MemoryReplayGuard;
    use crate::handoff::unavailable::UnavailableReplayGuard;
    use crate::time::manual_clock::ManualClock;
    use crate::token::jti::Jti;

    #[test]
    fn a_token_is_accepted_once_and_refused_the_second_time() {
        let clock = Arc::new(ManualClock::at(1_000.0));
        let service = ReplayService::new(Arc::new(MemoryReplayGuard::new()), clock);
        let jti = Jti::parse("handoff-one").unwrap();

        assert!(!service.seen(&jti).unwrap());
        assert_eq!(service.accept(&jti).unwrap(), Acceptance::Accepted);
        assert!(service.seen(&jti).unwrap());
        assert_eq!(service.accept(&jti).unwrap(), Acceptance::Replayed);
    }

    #[test]
    fn the_memory_of_a_spent_token_outlives_the_token_itself() {
        let clock = Arc::new(ManualClock::at(1_000.0));
        let service = ReplayService::new(Arc::new(MemoryReplayGuard::new()), clock.clone());
        let jti = Jti::parse("handoff-two").unwrap();

        service.accept(&jti).unwrap();
        clock.advance(599.0);
        assert!(service.seen(&jti).unwrap());
        clock.advance(1.0);
        assert!(!service.seen(&jti).unwrap());
    }

    #[test]
    fn two_tokens_never_answer_for_each_other() {
        let clock = Arc::new(ManualClock::at(1_000.0));
        let service = ReplayService::new(Arc::new(MemoryReplayGuard::new()), clock);

        service.accept(&Jti::parse("spent").unwrap()).unwrap();
        assert!(!service.seen(&Jti::parse("fresh").unwrap()).unwrap());
    }

    #[test]
    fn without_shared_state_a_token_is_refused_rather_than_accepted_unguarded() {
        let service = ReplayService::new(
            Arc::new(UnavailableReplayGuard::new()),
            Arc::new(ManualClock::at(1_000.0)),
        );
        let jti = Jti::parse("handoff-three").unwrap();

        assert_eq!(service.seen(&jti), Err(StateError::Unavailable));
        assert_eq!(service.accept(&jti), Err(StateError::Unavailable));
    }
}

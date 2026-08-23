use crate::error::{Result, StateError};
use crate::ports::replay::ReplayGuard;
use crate::token::jti::Jti;
use crate::token::ttl::Ttl;

pub struct UnavailableReplayGuard;

impl Default for UnavailableReplayGuard {
    fn default() -> Self {
        UnavailableReplayGuard::new()
    }
}

impl UnavailableReplayGuard {
    pub fn new() -> Self {
        UnavailableReplayGuard
    }
}

impl ReplayGuard for UnavailableReplayGuard {
    fn seen(&self, _jti: &Jti, _now: f64) -> Result<bool> {
        Err(StateError::Unavailable)
    }

    fn remember_if_new(&self, _jti: &Jti, _ttl: Ttl, _now: f64) -> Result<bool> {
        Err(StateError::Unavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::UnavailableReplayGuard;
    use crate::error::StateError;
    use crate::handoff::lifetime::remembered_ttl;
    use crate::ports::replay::ReplayGuard;
    use crate::token::jti::Jti;

    #[test]
    fn a_guard_that_cannot_ask_refuses_instead_of_letting_a_replay_through() {
        let guard = UnavailableReplayGuard::new();
        let jti = Jti::parse("aaaa").unwrap();
        assert_eq!(guard.seen(&jti, 1_000.0), Err(StateError::Unavailable));
        assert_eq!(
            guard.remember_if_new(&jti, remembered_ttl(), 1_000.0),
            Err(StateError::Unavailable)
        );
    }
}

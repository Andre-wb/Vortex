use std::sync::Arc;

use crate::account::user_id::UserId;
use crate::error::Result;
use crate::ports::clock::Clock;
use crate::ports::password_markers::PasswordMarkers;
use crate::second_factor::lifetime::marker_ttl;

pub struct SecondFactorService {
    markers: Arc<dyn PasswordMarkers>,
    clock: Arc<dyn Clock>,
}

impl SecondFactorService {
    pub fn new(markers: Arc<dyn PasswordMarkers>, clock: Arc<dyn Clock>) -> Self {
        SecondFactorService { markers, clock }
    }

    pub fn arm(&self, user: UserId) -> Result<()> {
        self.markers
            .arm(user, marker_ttl(), self.clock.unix_seconds())
    }

    pub fn armed(&self, user: UserId) -> bool {
        self.markers.armed(user, self.clock.unix_seconds())
    }

    pub fn disarm(&self, user: UserId) -> Result<()> {
        self.markers.disarm(user)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::SecondFactorService;
    use crate::account::user_id::UserId;
    use crate::error::StateError;
    use crate::second_factor::memory::MemoryPasswordMarkers;
    use crate::second_factor::unavailable::UnavailablePasswordMarkers;
    use crate::time::manual_clock::ManualClock;

    #[test]
    fn the_password_step_arms_the_marker_the_second_step_asks_for() {
        let clock = Arc::new(ManualClock::at(1_000.0));
        let service =
            SecondFactorService::new(Arc::new(MemoryPasswordMarkers::new()), clock.clone());
        let user = UserId::of(7).unwrap();

        service.arm(user).unwrap();
        assert!(service.armed(user));

        clock.advance(299.0);
        assert!(service.armed(user));
        clock.advance(1.0);
        assert!(!service.armed(user));
    }

    #[test]
    fn asking_twice_does_not_burn_the_marker_but_the_second_step_does() {
        let clock = Arc::new(ManualClock::at(1_000.0));
        let service = SecondFactorService::new(Arc::new(MemoryPasswordMarkers::new()), clock);
        let user = UserId::of(7).unwrap();

        service.arm(user).unwrap();
        assert!(service.armed(user));
        assert!(service.armed(user));

        service.disarm(user).unwrap();
        assert!(!service.armed(user));
    }

    #[test]
    fn a_marker_that_cannot_be_shared_is_refused_instead_of_kept_for_one_worker() {
        let service = SecondFactorService::new(
            Arc::new(UnavailablePasswordMarkers::new()),
            Arc::new(ManualClock::at(1_000.0)),
        );
        let user = UserId::of(7).unwrap();
        assert_eq!(service.arm(user), Err(StateError::Unavailable));
        assert!(!service.armed(user));
    }
}

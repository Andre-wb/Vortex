use crate::account::user_id::UserId;
use crate::error::{Result, StateError};
use crate::ports::password_markers::PasswordMarkers;
use crate::token::ttl::Ttl;

pub struct UnavailablePasswordMarkers;

impl Default for UnavailablePasswordMarkers {
    fn default() -> Self {
        UnavailablePasswordMarkers::new()
    }
}

impl UnavailablePasswordMarkers {
    pub fn new() -> Self {
        UnavailablePasswordMarkers
    }
}

impl PasswordMarkers for UnavailablePasswordMarkers {
    fn arm(&self, _user: UserId, _ttl: Ttl, _now: f64) -> Result<()> {
        Err(StateError::Unavailable)
    }

    fn armed(&self, _user: UserId, _now: f64) -> bool {
        false
    }

    fn disarm(&self, _user: UserId) -> Result<()> {
        Err(StateError::Unavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::UnavailablePasswordMarkers;
    use crate::account::user_id::UserId;
    use crate::error::StateError;
    use crate::ports::password_markers::PasswordMarkers;
    use crate::token::ttl::Ttl;

    #[test]
    fn a_marker_that_cannot_be_shared_is_never_issued() {
        let markers = UnavailablePasswordMarkers::new();
        let user = UserId::of(7).unwrap();
        assert_eq!(
            markers.arm(user, Ttl::seconds(300).unwrap(), 1_000.0),
            Err(StateError::Unavailable)
        );
        assert!(!markers.armed(user, 1_000.0));
        assert_eq!(markers.disarm(user), Err(StateError::Unavailable));
    }
}

use crate::error::{Result, StateError};
use crate::ports::denylist::Denylist;
use crate::token::jti::Jti;
use crate::token::ttl::Ttl;

pub struct UnavailableDenylist;

impl Default for UnavailableDenylist {
    fn default() -> Self {
        UnavailableDenylist::new()
    }
}

impl UnavailableDenylist {
    pub fn new() -> Self {
        UnavailableDenylist
    }
}

impl Denylist for UnavailableDenylist {
    fn remember(&self, _jti: &Jti, _ttl: Ttl, _now: f64) -> Result<()> {
        Err(StateError::Unavailable)
    }

    fn holds(&self, _jti: &Jti, _now: f64) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::UnavailableDenylist;
    use crate::error::StateError;
    use crate::ports::denylist::Denylist;
    use crate::token::jti::Jti;
    use crate::token::ttl::Ttl;

    #[test]
    fn a_revocation_that_cannot_be_shared_is_refused_rather_than_kept_alone() {
        let list = UnavailableDenylist::new();
        let jti = Jti::parse("aaaa").unwrap();
        assert_eq!(
            list.remember(&jti, Ttl::seconds(60).unwrap(), 1_000.0),
            Err(StateError::Unavailable)
        );
    }

    #[test]
    fn a_reader_who_cannot_ask_says_nothing_was_revoked() {
        let list = UnavailableDenylist::new();
        assert!(!list.holds(&Jti::parse("aaaa").unwrap(), 1_000.0));
    }
}

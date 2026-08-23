use std::sync::Arc;

use crate::error::Result;
use crate::ports::clock::Clock;
use crate::ports::denylist::Denylist;
use crate::revocation::outcome::Revocation;
use crate::token::jti::Jti;
use crate::token::ttl::Ttl;

pub struct RevocationService {
    denylist: Arc<dyn Denylist>,
    clock: Arc<dyn Clock>,
}

impl RevocationService {
    pub fn new(denylist: Arc<dyn Denylist>, clock: Arc<dyn Clock>) -> Self {
        RevocationService { denylist, clock }
    }

    pub fn revoke(&self, jti: &Jti, expires_at: f64) -> Result<Revocation> {
        let now = self.clock.unix_seconds();
        match Ttl::until(expires_at, now) {
            Some(ttl) => {
                self.denylist.remember(jti, ttl, now)?;
                Ok(Revocation::Recorded)
            }
            None => Ok(Revocation::AlreadyExpired),
        }
    }

    pub fn is_revoked(&self, jti: &Jti) -> bool {
        self.denylist.holds(jti, self.clock.unix_seconds())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::RevocationService;
    use crate::error::StateError;
    use crate::ports::clock::Clock;
    use crate::ports::denylist::Denylist;
    use crate::revocation::memory::MemoryDenylist;
    use crate::revocation::outcome::Revocation;
    use crate::revocation::unavailable::UnavailableDenylist;
    use crate::time::manual_clock::ManualClock;
    use crate::token::jti::Jti;

    fn service(clock: Arc<ManualClock>) -> (RevocationService, Arc<MemoryDenylist>) {
        let denylist = Arc::new(MemoryDenylist::new());
        let list: Arc<dyn Denylist> = denylist.clone();
        let ticking: Arc<dyn Clock> = clock;
        (RevocationService::new(list, ticking), denylist)
    }

    #[test]
    fn a_live_token_is_revoked_until_its_own_expiry() {
        let clock = Arc::new(ManualClock::at(1_000.0));
        let (service, _) = service(clock.clone());
        let jti = Jti::parse("aaaa").unwrap();

        assert_eq!(service.revoke(&jti, 1_060.0).unwrap(), Revocation::Recorded);
        assert!(service.is_revoked(&jti));

        clock.advance(59.0);
        assert!(service.is_revoked(&jti));
        clock.advance(1.0);
        assert!(!service.is_revoked(&jti));
    }

    #[test]
    fn a_token_that_has_already_expired_is_not_written_anywhere() {
        let clock = Arc::new(ManualClock::at(1_000.0));
        let (service, denylist) = service(clock);
        let jti = Jti::parse("aaaa").unwrap();

        assert_eq!(
            service.revoke(&jti, 1_000.0).unwrap(),
            Revocation::AlreadyExpired
        );
        assert!(denylist.is_empty());
    }

    #[test]
    fn a_revocation_that_cannot_be_shared_is_reported_and_not_hidden() {
        let service = RevocationService::new(
            Arc::new(UnavailableDenylist::new()),
            Arc::new(ManualClock::at(1_000.0)),
        );
        let jti = Jti::parse("aaaa").unwrap();
        assert_eq!(service.revoke(&jti, 1_060.0), Err(StateError::Unavailable));
        assert!(!service.is_revoked(&jti));
    }

    #[test]
    fn two_tokens_never_answer_for_each_other() {
        let clock = Arc::new(ManualClock::at(1_000.0));
        let (service, _) = service(clock);
        let revoked = Jti::parse("aaaa").unwrap();
        let live = Jti::parse("bbbb").unwrap();

        service.revoke(&revoked, 1_060.0).unwrap();
        assert!(service.is_revoked(&revoked));
        assert!(!service.is_revoked(&live));
    }
}

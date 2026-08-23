use std::sync::Arc;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;

use crate::account::user_id::UserId;
use crate::challenge::secret::ChallengeSecret;
use crate::error::Result;
use crate::ports::clock::Clock;
use crate::ports::entropy::Entropy;
use crate::ports::wallet_challenges::WalletChallenges;
use crate::wallet::issued::IssuedChallenge;
use crate::wallet::lifetime::challenge_ttl;
use crate::wallet::message::LinkMessage;
use crate::wallet::verification::Verification;

pub struct WalletLinkService {
    challenges: Arc<dyn WalletChallenges>,
    clock: Arc<dyn Clock>,
    entropy: Arc<dyn Entropy>,
}

impl WalletLinkService {
    pub fn new(
        challenges: Arc<dyn WalletChallenges>,
        clock: Arc<dyn Clock>,
        entropy: Arc<dyn Entropy>,
    ) -> Self {
        WalletLinkService {
            challenges,
            clock,
            entropy,
        }
    }

    pub fn issue(&self, user: UserId) -> Result<IssuedChallenge> {
        let now = self.clock.unix_seconds();
        let ttl = challenge_ttl();
        let secret = ChallengeSecret::draw(self.entropy.as_ref());
        self.challenges.remember(user, &secret, ttl, now)?;
        Ok(IssuedChallenge::new(
            LinkMessage::of(user, &secret),
            (now + ttl.as_seconds() as f64) as i64,
            ttl.as_seconds(),
        ))
    }

    pub fn check(&self, user: UserId, supplied: &str) -> Result<Verification> {
        let now = self.clock.unix_seconds();
        let held = match self.challenges.find(user, now)? {
            Some(secret) => secret,
            None => return Ok(Verification::NoChallenge),
        };
        let decoded = match STANDARD.decode(supplied) {
            Ok(bytes) => bytes,
            Err(_) => return Ok(Verification::NotBase64),
        };
        let expected = LinkMessage::of(user, &held);
        Ok(if expected.matches(&decoded) {
            Verification::Matched(expected)
        } else {
            Verification::Mismatch
        })
    }

    pub fn burn(&self, user: UserId) -> Result<()> {
        self.challenges.burn(user)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;

    use super::WalletLinkService;
    use crate::account::user_id::UserId;
    use crate::error::StateError;
    use crate::random::fixed_entropy::FixedEntropy;
    use crate::time::manual_clock::ManualClock;
    use crate::wallet::memory::MemoryWalletChallenges;
    use crate::wallet::unavailable::UnavailableWalletChallenges;
    use crate::wallet::verification::Verification;

    fn service(clock: Arc<ManualClock>) -> WalletLinkService {
        WalletLinkService::new(
            Arc::new(MemoryWalletChallenges::new()),
            clock,
            Arc::new(FixedEntropy::counting_from(0)),
        )
    }

    fn user(value: i64) -> UserId {
        UserId::of(value).unwrap()
    }

    #[test]
    fn the_message_handed_out_is_the_message_accepted_back() {
        let service = service(Arc::new(ManualClock::at(1_000.0)));
        let issued = service.issue(user(7)).unwrap();

        assert_eq!(issued.expires_at(), 1_300);
        assert_eq!(
            service
                .check(user(7), &issued.rendered())
                .unwrap()
                .outcome(),
            "matched"
        );
    }

    #[test]
    fn an_account_that_asked_for_nothing_holds_no_challenge() {
        let service = service(Arc::new(ManualClock::at(1_000.0)));
        let issued = service.issue(user(7)).unwrap();
        assert_eq!(
            service.check(user(8), &issued.rendered()).unwrap(),
            Verification::NoChallenge
        );
    }

    #[test]
    fn the_message_of_one_account_is_not_the_message_of_another() {
        let service = service(Arc::new(ManualClock::at(1_000.0)));
        let mine = service.issue(user(7)).unwrap();
        service.issue(user(8)).unwrap();
        assert_eq!(
            service.check(user(8), &mine.rendered()).unwrap(),
            Verification::Mismatch
        );
    }

    #[test]
    fn what_is_not_base64_is_told_apart_from_a_wrong_message() {
        let service = service(Arc::new(ManualClock::at(1_000.0)));
        service.issue(user(7)).unwrap();
        assert_eq!(
            service.check(user(7), "не base64!").unwrap(),
            Verification::NotBase64
        );
    }

    #[test]
    fn a_challenge_older_than_its_lifetime_reads_as_no_challenge() {
        let clock = Arc::new(ManualClock::at(1_000.0));
        let service = service(clock.clone());
        let issued = service.issue(user(7)).unwrap();

        clock.advance(299.0);
        assert_eq!(
            service
                .check(user(7), &issued.rendered())
                .unwrap()
                .outcome(),
            "matched"
        );
        clock.advance(1.0);
        assert_eq!(
            service.check(user(7), &issued.rendered()).unwrap(),
            Verification::NoChallenge
        );
    }

    #[test]
    fn a_burnt_challenge_cannot_be_spent_twice() {
        let service = service(Arc::new(ManualClock::at(1_000.0)));
        let issued = service.issue(user(7)).unwrap();
        service.burn(user(7)).unwrap();
        assert_eq!(
            service.check(user(7), &issued.rendered()).unwrap(),
            Verification::NoChallenge
        );
    }

    #[test]
    fn asking_again_replaces_the_message_the_account_must_sign() {
        let service = service(Arc::new(ManualClock::at(1_000.0)));
        let first = service.issue(user(7)).unwrap();
        let second = service.issue(user(7)).unwrap();

        assert_ne!(first.rendered(), second.rendered());
        assert_eq!(
            service.check(user(7), &first.rendered()).unwrap(),
            Verification::Mismatch
        );
        assert_eq!(
            service
                .check(user(7), &second.rendered())
                .unwrap()
                .outcome(),
            "matched"
        );
    }

    #[test]
    fn without_shared_state_a_challenge_is_refused_instead_of_kept_for_one_worker() {
        let service = WalletLinkService::new(
            Arc::new(UnavailableWalletChallenges::new()),
            Arc::new(ManualClock::at(1_000.0)),
            Arc::new(FixedEntropy::counting_from(0)),
        );
        assert_eq!(service.issue(user(7)), Err(StateError::Unavailable));
        assert_eq!(service.burn(user(7)), Err(StateError::Unavailable));
        assert_eq!(
            service
                .check(user(7), &STANDARD.encode(b"anything"))
                .unwrap(),
            Verification::NoChallenge
        );
    }
}

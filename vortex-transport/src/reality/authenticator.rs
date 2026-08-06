use crate::ports::clock::Clock;
use crate::ports::seen_envelopes::SeenEnvelopes;
use crate::ports::short_id_registry::ShortIdRegistry;
use crate::reality::auth::envelope::ENVELOPE_VERSION;
use crate::reality::auth::opener;
use crate::reality::auth::sealed_auth::X25519_KEY_LEN;
use crate::reality::config::RealityConfig;
use crate::reality::handshake::client_hello;
use crate::reality::verdict::{AuthVerdict, RejectReason};
use std::sync::Arc;
use x25519_dalek::{PublicKey, StaticSecret};

pub struct RealityAuthenticator {
    secret: StaticSecret,
    short_ids: Arc<dyn ShortIdRegistry>,
    seen: Arc<dyn SeenEnvelopes>,
    clock: Arc<dyn Clock>,
    config: RealityConfig,
}

impl RealityAuthenticator {
    pub fn new(
        secret: StaticSecret,
        short_ids: Arc<dyn ShortIdRegistry>,
        seen: Arc<dyn SeenEnvelopes>,
        clock: Arc<dyn Clock>,
        config: RealityConfig,
    ) -> Self {
        RealityAuthenticator {
            secret,
            short_ids,
            seen,
            clock,
            config,
        }
    }

    pub fn public_key(&self) -> [u8; X25519_KEY_LEN] {
        PublicKey::from(&self.secret).to_bytes()
    }

    pub fn short_ids(&self) -> &Arc<dyn ShortIdRegistry> {
        &self.short_ids
    }

    pub fn config(&self) -> RealityConfig {
        self.config
    }

    pub fn authenticate(&self, client_hello: &[u8]) -> AuthVerdict {
        let Some(hello) = client_hello::parse(client_hello) else {
            return AuthVerdict::Rejected(RejectReason::NotAClientHello);
        };
        if hello.session_id.is_empty() {
            return AuthVerdict::Rejected(RejectReason::NoSessionId);
        }
        let Some(key_share) = hello.key_share else {
            return AuthVerdict::Rejected(RejectReason::NoKeyShare);
        };
        self.verify(&key_share, &hello.session_id)
    }

    pub fn verify(&self, ephemeral_public: &[u8], session_id: &[u8]) -> AuthVerdict {
        let Some(envelope) = opener::open(&self.secret, ephemeral_public, session_id) else {
            return AuthVerdict::Rejected(RejectReason::Undecryptable);
        };
        if envelope.version != ENVELOPE_VERSION {
            return AuthVerdict::Rejected(RejectReason::UnsupportedVersion);
        }

        let now = self.clock.unix_seconds();
        if now.saturating_sub(envelope.timestamp).saturating_abs() > self.config.auth_window_secs {
            return AuthVerdict::Rejected(RejectReason::OutsideTimeWindow);
        }
        if !self.short_ids.contains(&envelope.short_id) {
            return AuthVerdict::Rejected(RejectReason::UnknownShortId);
        }

        self.seen.prune(now);
        let expires_at = envelope
            .timestamp
            .saturating_add(self.config.auth_window_secs);
        if !self.seen.remember(session_id, expires_at) {
            return AuthVerdict::Rejected(RejectReason::Replayed);
        }

        AuthVerdict::Authenticated(envelope.short_id)
    }
}

#[cfg(test)]
mod tests {
    use super::RealityAuthenticator;
    use crate::ports::short_id_registry::ShortIdRegistry;
    use crate::random::fixed_random::FixedRandom;
    use crate::reality::auth::envelope::Envelope;
    use crate::reality::auth::sealed_auth::SealedAuth;
    use crate::reality::auth::sealer::seal;
    use crate::reality::config::RealityConfig;
    use crate::reality::replay::memory_seen::MemorySeenEnvelopes;
    use crate::reality::short_id::registry::MemoryShortIdRegistry;
    use crate::reality::short_id::value::ShortId;
    use crate::reality::verdict::{AuthVerdict, RejectReason};
    use crate::time::manual_clock::ManualClock;
    use std::sync::Arc;
    use x25519_dalek::StaticSecret;

    const NOW: i64 = 1_760_000_000;

    struct Fixture {
        authenticator: RealityAuthenticator,
        clock: Arc<ManualClock>,
        registry: Arc<MemoryShortIdRegistry>,
    }

    fn fixture() -> Fixture {
        let registry = Arc::new(MemoryShortIdRegistry::with_entries([short_id()]));
        let clock = Arc::new(ManualClock::at(NOW));
        let authenticator = RealityAuthenticator::new(
            StaticSecret::from([0x22u8; 32]),
            registry.clone(),
            Arc::new(MemorySeenEnvelopes::new()),
            clock.clone(),
            RealityConfig::default(),
        );
        Fixture {
            authenticator,
            clock,
            registry,
        }
    }

    fn short_id() -> ShortId {
        ShortId::from_hex("deadbeef").unwrap()
    }

    fn sealed_at(fixture: &Fixture, timestamp: i64, short_id: ShortId, filler: u8) -> SealedAuth {
        let random = FixedRandom::new(vec![]).with_filler(filler);
        seal(
            &fixture.authenticator.public_key(),
            &Envelope::current(timestamp, short_id),
            &random,
        )
        .unwrap()
    }

    #[test]
    fn accepts_a_fresh_envelope_from_a_known_client() {
        let fixture = fixture();
        let sealed = sealed_at(&fixture, NOW, short_id(), 0x11);
        assert_eq!(
            fixture
                .authenticator
                .verify(&sealed.ephemeral_public, &sealed.session_id),
            AuthVerdict::Authenticated(short_id())
        );
    }

    #[test]
    fn the_same_envelope_is_refused_the_second_time() {
        let fixture = fixture();
        let sealed = sealed_at(&fixture, NOW, short_id(), 0x11);
        fixture
            .authenticator
            .verify(&sealed.ephemeral_public, &sealed.session_id);
        assert_eq!(
            fixture
                .authenticator
                .verify(&sealed.ephemeral_public, &sealed.session_id)
                .reason(),
            Some(RejectReason::Replayed)
        );
    }

    #[test]
    fn a_replay_after_the_window_has_passed_is_refused_as_stale() {
        let fixture = fixture();
        let sealed = sealed_at(&fixture, NOW, short_id(), 0x11);
        fixture
            .authenticator
            .verify(&sealed.ephemeral_public, &sealed.session_id);
        fixture.clock.advance(121);
        assert_eq!(
            fixture
                .authenticator
                .verify(&sealed.ephemeral_public, &sealed.session_id)
                .reason(),
            Some(RejectReason::OutsideTimeWindow)
        );
    }

    #[test]
    fn an_envelope_from_the_edge_of_the_window_is_still_accepted() {
        let fixture = fixture();
        let sealed = sealed_at(&fixture, NOW - 120, short_id(), 0x11);
        assert!(fixture
            .authenticator
            .verify(&sealed.ephemeral_public, &sealed.session_id)
            .is_authenticated());
    }

    #[test]
    fn an_envelope_just_outside_the_window_is_refused() {
        let fixture = fixture();
        let sealed = sealed_at(&fixture, NOW - 121, short_id(), 0x11);
        assert_eq!(
            fixture
                .authenticator
                .verify(&sealed.ephemeral_public, &sealed.session_id)
                .reason(),
            Some(RejectReason::OutsideTimeWindow)
        );
    }

    #[test]
    fn an_envelope_from_the_future_is_refused_beyond_the_window() {
        let fixture = fixture();
        let sealed = sealed_at(&fixture, NOW + 121, short_id(), 0x11);
        assert_eq!(
            fixture
                .authenticator
                .verify(&sealed.ephemeral_public, &sealed.session_id)
                .reason(),
            Some(RejectReason::OutsideTimeWindow)
        );
    }

    #[test]
    fn an_unknown_short_id_is_refused() {
        let fixture = fixture();
        let stranger = ShortId::from_hex("cafebabe").unwrap();
        let sealed = sealed_at(&fixture, NOW, stranger, 0x11);
        assert_eq!(
            fixture
                .authenticator
                .verify(&sealed.ephemeral_public, &sealed.session_id)
                .reason(),
            Some(RejectReason::UnknownShortId)
        );
    }

    #[test]
    fn revoking_a_short_id_takes_effect_immediately() {
        let fixture = fixture();
        fixture.registry.remove(&short_id());
        let sealed = sealed_at(&fixture, NOW, short_id(), 0x11);
        assert_eq!(
            fixture
                .authenticator
                .verify(&sealed.ephemeral_public, &sealed.session_id)
                .reason(),
            Some(RejectReason::UnknownShortId)
        );
    }

    #[test]
    fn garbage_is_refused_as_undecryptable() {
        let fixture = fixture();
        assert_eq!(
            fixture
                .authenticator
                .verify(&[0x01u8; 32], &[0x02u8; 29])
                .reason(),
            Some(RejectReason::Undecryptable)
        );
    }

    #[test]
    fn a_rejected_envelope_does_not_occupy_the_replay_cache() {
        let fixture = fixture();
        let stranger = ShortId::from_hex("cafebabe").unwrap();
        let sealed = sealed_at(&fixture, NOW, stranger.clone(), 0x11);
        fixture
            .authenticator
            .verify(&sealed.ephemeral_public, &sealed.session_id);

        fixture.registry.insert(stranger.clone());
        assert_eq!(
            fixture
                .authenticator
                .verify(&sealed.ephemeral_public, &sealed.session_id),
            AuthVerdict::Authenticated(stranger)
        );
    }
}

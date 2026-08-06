use crate::ports::clock::Clock;
use crate::ports::random_source::RandomSource;
use crate::ports::seen_envelopes::SeenEnvelopes;
use crate::ports::short_id_registry::ShortIdRegistry;
use crate::random::os_random::OsRandom;
use crate::reality::auth::sealed_auth::X25519_KEY_LEN;
use crate::reality::authenticator::RealityAuthenticator;
use crate::reality::config::RealityConfig;
use crate::reality::replay::memory_seen::MemorySeenEnvelopes;
use crate::reality::short_id::registry::MemoryShortIdRegistry;
use crate::time::system_clock::SystemClock;
use std::sync::Arc;
use x25519_dalek::StaticSecret;

pub struct AuthenticatorBuilder {
    secret: Option<StaticSecret>,
    short_ids: Option<Arc<dyn ShortIdRegistry>>,
    seen: Option<Arc<dyn SeenEnvelopes>>,
    clock: Arc<dyn Clock>,
    random: Arc<dyn RandomSource>,
    config: RealityConfig,
}

impl Default for AuthenticatorBuilder {
    fn default() -> Self {
        AuthenticatorBuilder {
            secret: None,
            short_ids: None,
            seen: None,
            clock: Arc::new(SystemClock::new()),
            random: Arc::new(OsRandom::new()),
            config: RealityConfig::default(),
        }
    }
}

impl AuthenticatorBuilder {
    pub fn new() -> Self {
        AuthenticatorBuilder::default()
    }

    pub fn with_secret(mut self, secret: StaticSecret) -> Self {
        self.secret = Some(secret);
        self
    }

    pub fn with_short_ids(mut self, short_ids: Arc<dyn ShortIdRegistry>) -> Self {
        self.short_ids = Some(short_ids);
        self
    }

    pub fn with_seen_envelopes(mut self, seen: Arc<dyn SeenEnvelopes>) -> Self {
        self.seen = Some(seen);
        self
    }

    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    pub fn with_random(mut self, random: Arc<dyn RandomSource>) -> Self {
        self.random = random;
        self
    }

    pub fn with_config(mut self, config: RealityConfig) -> Self {
        self.config = config;
        self
    }

    pub fn random(&self) -> &Arc<dyn RandomSource> {
        &self.random
    }

    pub fn build(self) -> RealityAuthenticator {
        let secret = self.secret.unwrap_or_else(|| {
            let mut bytes = [0u8; X25519_KEY_LEN];
            self.random.fill_bytes(&mut bytes);
            StaticSecret::from(bytes)
        });

        RealityAuthenticator::new(
            secret,
            self.short_ids
                .unwrap_or_else(|| Arc::new(MemoryShortIdRegistry::new())),
            self.seen
                .unwrap_or_else(|| Arc::new(MemorySeenEnvelopes::new())),
            self.clock,
            self.config,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::AuthenticatorBuilder;
    use crate::random::fixed_random::FixedRandom;
    use std::sync::Arc;
    use x25519_dalek::{PublicKey, StaticSecret};

    #[test]
    fn generates_a_secret_from_the_random_source_when_none_is_given() {
        let authenticator = AuthenticatorBuilder::new()
            .with_random(Arc::new(FixedRandom::new(vec![]).with_filler(0x11)))
            .build();
        assert_eq!(
            authenticator.public_key(),
            PublicKey::from(&StaticSecret::from([0x11u8; 32])).to_bytes()
        );
    }

    #[test]
    fn keeps_the_secret_it_was_given() {
        let secret = StaticSecret::from([0x22u8; 32]);
        let expected = PublicKey::from(&secret).to_bytes();
        let authenticator = AuthenticatorBuilder::new().with_secret(secret).build();
        assert_eq!(authenticator.public_key(), expected);
    }

    #[test]
    fn starts_with_an_empty_short_id_registry() {
        let authenticator = AuthenticatorBuilder::new().build();
        assert!(authenticator.short_ids().is_empty());
    }
}

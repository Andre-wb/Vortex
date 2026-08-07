use std::sync::Arc;

use crate::config::rate::RateConfig;
use crate::config::rotation::RotationConfig;
use crate::config::storage::StorageConfig;
use crate::ports::clock::Clock;
use crate::ports::mailbox_store::MailboxStore;
use crate::ports::random_source::RandomSource;
use crate::ports::rate_limiter::RateLimiter;
use crate::ports::room_secrets::RoomSecrets;
use crate::random::os_random::OsRandom;
use crate::ratelimit::sliding_window::SlidingWindowLimiter;
use crate::secrets::memory_secrets::MemoryRoomSecrets;
use crate::service::mailbox_service::BmpService;
use crate::store::memory_store::MemoryMailboxStore;
use crate::time::system_clock::SystemClock;

pub struct BmpServiceBuilder {
    store: Option<Arc<dyn MailboxStore>>,
    secrets: Option<Arc<dyn RoomSecrets>>,
    limiter: Option<Arc<dyn RateLimiter>>,
    random: Arc<dyn RandomSource>,
    clock: Arc<dyn Clock>,
    storage: StorageConfig,
    rotation: RotationConfig,
    rate: RateConfig,
}

impl Default for BmpServiceBuilder {
    fn default() -> Self {
        BmpServiceBuilder {
            store: None,
            secrets: None,
            limiter: None,
            random: Arc::new(OsRandom::new()),
            clock: Arc::new(SystemClock::new()),
            storage: StorageConfig::default(),
            rotation: RotationConfig::default(),
            rate: RateConfig::default(),
        }
    }
}

impl BmpServiceBuilder {
    pub fn new() -> Self {
        BmpServiceBuilder::default()
    }

    pub fn with_store(mut self, store: Arc<dyn MailboxStore>) -> Self {
        self.store = Some(store);
        self
    }

    pub fn with_room_secrets(mut self, secrets: Arc<dyn RoomSecrets>) -> Self {
        self.secrets = Some(secrets);
        self
    }

    pub fn with_rate_limiter(mut self, limiter: Arc<dyn RateLimiter>) -> Self {
        self.limiter = Some(limiter);
        self
    }

    pub fn with_random(mut self, random: Arc<dyn RandomSource>) -> Self {
        self.random = random;
        self
    }

    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    pub fn with_storage(mut self, storage: StorageConfig) -> Self {
        self.storage = storage;
        self
    }

    pub fn with_rotation(mut self, rotation: RotationConfig) -> Self {
        self.rotation = rotation;
        self
    }

    pub fn with_rate(mut self, rate: RateConfig) -> Self {
        self.rate = rate;
        self
    }

    pub fn build(self) -> BmpService {
        let store = self
            .store
            .unwrap_or_else(|| Arc::new(MemoryMailboxStore::new(self.clock.clone(), self.storage)));
        let secrets = self
            .secrets
            .unwrap_or_else(|| Arc::new(MemoryRoomSecrets::new()));
        let limiter = self
            .limiter
            .unwrap_or_else(|| Arc::new(SlidingWindowLimiter::new(self.clock.clone(), self.rate)));

        BmpService::new(
            store,
            secrets,
            limiter,
            self.random,
            self.clock,
            self.storage,
            self.rotation,
            self.rate,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::BmpServiceBuilder;
    use crate::config::storage::StorageConfig;
    use crate::time::manual_clock::ManualClock;
    use std::sync::Arc;

    #[test]
    fn a_service_built_with_defaults_stores_messages_in_memory() {
        let service = BmpServiceBuilder::new().build();
        assert!(service
            .deposit("0123456789abcdef", "abababababababababababab", "1.2.3.4")
            .is_none());
        assert_eq!(service.stats().total_deposited, 1);
    }

    #[test]
    fn the_clock_reaches_both_the_store_and_the_rate_limiter() {
        let clock = Arc::new(ManualClock::at(1_000.0));
        let service = BmpServiceBuilder::new()
            .with_clock(clock.clone())
            .with_storage(StorageConfig::default().ttl_secs(10.0))
            .build();
        service.deposit("0123456789abcdef", "abababababababababababab", "1.2.3.4");
        clock.advance(10.0);
        assert_eq!(service.collect_garbage(), 1);
    }
}

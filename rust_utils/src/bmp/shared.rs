use std::sync::Arc;

use once_cell::sync::Lazy;
use parking_lot::RwLock;
use vortex_bmp::config::rate::RateConfig;
use vortex_bmp::config::storage::StorageConfig;
use vortex_bmp::ports::clock::Clock;
use vortex_bmp::service::builder::BmpServiceBuilder;
use vortex_bmp::service::mailbox_service::BmpService;
use vortex_bmp::time::system_clock::SystemClock;
use vortex_redis::backbone::RedisBackbone;
use vortex_redis::bmp::mailbox_store::RedisMailboxStore;
use vortex_redis::bmp::rate_limiter::RedisRateLimiter;
use vortex_redis::bmp::room_secrets::RedisRoomSecrets;
use vortex_redis::config::RedisConfig;
use vortex_redis::error::BackboneError;

static SERVICE: Lazy<RwLock<Arc<BmpService>>> =
    Lazy::new(|| RwLock::new(Arc::new(BmpServiceBuilder::new().build())));

static BACKBONE: Lazy<RwLock<Option<Arc<RedisBackbone>>>> = Lazy::new(|| RwLock::new(None));

pub fn service() -> Arc<BmpService> {
    SERVICE.read().clone()
}

pub fn backbone() -> Option<Arc<RedisBackbone>> {
    BACKBONE.read().clone()
}

pub fn is_shared() -> bool {
    BACKBONE.read().is_some()
}

pub fn connect(config: RedisConfig) -> Result<(), BackboneError> {
    let backbone = RedisBackbone::connect(config)?;
    let clock: Arc<dyn Clock> = Arc::new(SystemClock::new());
    let storage = StorageConfig::default();
    let rate = RateConfig::default();

    let service = BmpServiceBuilder::new()
        .with_clock(clock.clone())
        .with_storage(storage)
        .with_rate(rate)
        .with_store(Arc::new(RedisMailboxStore::new(
            backbone.clone(),
            clock.clone(),
            storage,
        )))
        .with_room_secrets(Arc::new(RedisRoomSecrets::new(backbone.clone())))
        .with_rate_limiter(Arc::new(RedisRateLimiter::new(
            backbone.clone(),
            clock,
            rate,
        )))
        .build();

    *SERVICE.write() = Arc::new(service);
    *BACKBONE.write() = Some(backbone);
    Ok(())
}

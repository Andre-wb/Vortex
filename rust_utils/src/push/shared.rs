use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use once_cell::sync::Lazy;
use parking_lot::RwLock;
use vortex_bmp::ports::push_registry::PushRegistry;
use vortex_bmp::push::memory::MemoryPushRegistry;
use vortex_bmp::push::service::PushProxyService;
use vortex_bmp::push::unavailable::UnavailablePushRegistry;
use vortex_redis::backbone::RedisBackbone;
use vortex_redis::bmp::push_registry::RedisPushRegistry;
use vortex_redis::config::RedisConfig;
use vortex_redis::error::BackboneError;

pub const MEMORY: &str = "memory";
pub const REDIS: &str = "redis";
pub const UNAVAILABLE: &str = "unavailable";

static MODE: Lazy<RwLock<&'static str>> = Lazy::new(|| RwLock::new(MEMORY));

static PROXY: Lazy<RwLock<Arc<PushProxyService>>> = Lazy::new(|| {
    RwLock::new(Arc::new(PushProxyService::new(Arc::new(
        MemoryPushRegistry::new(),
    ))))
});

fn install(registry: Arc<dyn PushRegistry>, mode: &'static str) {
    *PROXY.write() = Arc::new(PushProxyService::new(registry));
    *MODE.write() = mode;
}

pub fn proxy() -> Arc<PushProxyService> {
    PROXY.read().clone()
}

pub fn mode() -> &'static str {
    *MODE.read()
}

pub fn is_shared() -> bool {
    mode() == REDIS
}

pub fn now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|since| since.as_secs_f64())
        .unwrap_or_default()
}

pub fn connect(config: RedisConfig) -> Result<(), BackboneError> {
    let backbone: Arc<RedisBackbone> = match RedisBackbone::connect(config) {
        Ok(backbone) => backbone,
        Err(BackboneError::Unconfigured) => return Err(BackboneError::Unconfigured),
        Err(error) => {
            seal_off();
            return Err(error);
        }
    };

    install(Arc::new(RedisPushRegistry::new(backbone)), REDIS);
    Ok(())
}

pub fn seal_off() {
    install(Arc::new(UnavailablePushRegistry::new()), UNAVAILABLE);
}

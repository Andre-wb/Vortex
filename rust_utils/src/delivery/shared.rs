use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use once_cell::sync::Lazy;
use parking_lot::RwLock;
use vortex_delivery::dedup::service::DeduplicationService;
use vortex_delivery::mailbox::notification::service::NotificationMailboxService;
use vortex_delivery::mailbox::room::service::RoomMailboxService;
use vortex_redis::backbone::RedisBackbone;
use vortex_redis::config::RedisConfig;
use vortex_redis::error::BackboneError;

use crate::delivery::stores::Stores;

pub const MEMORY: &str = "memory";
pub const REDIS: &str = "redis";
pub const UNAVAILABLE: &str = "unavailable";

pub struct Delivery {
    pub dedup: DeduplicationService,
    pub rooms: RoomMailboxService,
    pub notifications: NotificationMailboxService,
}

impl Delivery {
    fn kept_in(stores: Stores) -> Self {
        Delivery {
            dedup: DeduplicationService::new(stores.seen),
            rooms: RoomMailboxService::new(stores.rooms),
            notifications: NotificationMailboxService::new(stores.notifications),
        }
    }
}

static MODE: Lazy<RwLock<&'static str>> = Lazy::new(|| RwLock::new(MEMORY));

static DELIVERY: Lazy<RwLock<Arc<Delivery>>> =
    Lazy::new(|| RwLock::new(Arc::new(Delivery::kept_in(Stores::in_memory()))));

fn install(stores: Stores, mode: &'static str) {
    *DELIVERY.write() = Arc::new(Delivery::kept_in(stores));
    *MODE.write() = mode;
}

pub fn delivery() -> Arc<Delivery> {
    DELIVERY.read().clone()
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

    install(Stores::in_redis(backbone), REDIS);
    Ok(())
}

pub fn seal_off() {
    install(Stores::sealed(), UNAVAILABLE);
}

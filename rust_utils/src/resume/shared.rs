use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use once_cell::sync::Lazy;
use parking_lot::RwLock;
use vortex_redis::backbone::RedisBackbone;
use vortex_redis::config::RedisConfig;
use vortex_redis::error::BackboneError;
use vortex_resume::cursor::service::SessionCursorService;
use vortex_resume::upload::service::UploadSessionService;

use crate::resume::stores::Stores;

pub const MEMORY: &str = "memory";
pub const REDIS: &str = "redis";
pub const UNAVAILABLE: &str = "unavailable";

pub struct Resume {
    pub uploads: UploadSessionService,
    pub cursors: SessionCursorService,
}

impl Resume {
    fn kept_in(stores: Stores) -> Self {
        Resume {
            uploads: UploadSessionService::new(stores.uploads),
            cursors: SessionCursorService::new(stores.cursors),
        }
    }
}

static MODE: Lazy<RwLock<&'static str>> = Lazy::new(|| RwLock::new(MEMORY));

static RESUME: Lazy<RwLock<Arc<Resume>>> =
    Lazy::new(|| RwLock::new(Arc::new(Resume::kept_in(Stores::in_memory()))));

fn install(stores: Stores, mode: &'static str) {
    *RESUME.write() = Arc::new(Resume::kept_in(stores));
    *MODE.write() = mode;
}

pub fn resume() -> Arc<Resume> {
    RESUME.read().clone()
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

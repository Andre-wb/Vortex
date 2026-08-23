use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use once_cell::sync::Lazy;
use parking_lot::RwLock;
use vortex_net::federation::memory::MemoryVirtualRoomIds;
use vortex_net::federation::service::VirtualRoomIdService;
use vortex_net::federation::unavailable::UnavailableVirtualRoomIds;
use vortex_net::ports::peer_registry::PeerRegistry;
use vortex_net::ports::virtual_room_ids::VirtualRoomIds;
use vortex_net::registry::memory::MemoryPeerRegistry;
use vortex_net::registry::service::PeerRegistryService;
use vortex_net::registry::unavailable::UnavailablePeerRegistry;
use vortex_redis::backbone::RedisBackbone;
use vortex_redis::config::RedisConfig;
use vortex_redis::error::BackboneError;
use vortex_redis::net::peer_registry::RedisPeerRegistry;
use vortex_redis::net::virtual_room_ids::RedisVirtualRoomIds;

pub const MEMORY: &str = "memory";
pub const REDIS: &str = "redis";
pub const UNAVAILABLE: &str = "unavailable";

pub const DEFAULT_TIMEOUT_SECONDS: f64 = 15.0;

static MODE: Lazy<RwLock<&'static str>> = Lazy::new(|| RwLock::new(MEMORY));

static TIMEOUT: Lazy<RwLock<f64>> = Lazy::new(|| RwLock::new(DEFAULT_TIMEOUT_SECONDS));

static OWN_ADDRESS: Lazy<RwLock<String>> = Lazy::new(|| RwLock::new(String::new()));

static REGISTRY: Lazy<RwLock<Arc<PeerRegistryService>>> = Lazy::new(|| {
    RwLock::new(Arc::new(PeerRegistryService::new(
        Arc::new(MemoryPeerRegistry::new()),
        DEFAULT_TIMEOUT_SECONDS,
    )))
});

static VIRTUAL_ROOMS: Lazy<RwLock<Arc<VirtualRoomIdService>>> = Lazy::new(|| {
    RwLock::new(Arc::new(VirtualRoomIdService::new(Arc::new(
        MemoryVirtualRoomIds::new(),
    ))))
});

fn install(peers: Arc<dyn PeerRegistry>, mode: &'static str) {
    *REGISTRY.write() = Arc::new(PeerRegistryService::new(peers, timeout()));
    *MODE.write() = mode;
}

fn install_ids(ids: Arc<dyn VirtualRoomIds>) {
    *VIRTUAL_ROOMS.write() = Arc::new(VirtualRoomIdService::new(ids));
}

pub fn virtual_rooms() -> Arc<VirtualRoomIdService> {
    VIRTUAL_ROOMS.read().clone()
}

pub fn registry() -> Arc<PeerRegistryService> {
    REGISTRY.read().clone()
}

pub fn mode() -> &'static str {
    *MODE.read()
}

pub fn is_shared() -> bool {
    mode() == REDIS
}

pub fn timeout() -> f64 {
    *TIMEOUT.read()
}

pub fn set_timeout(seconds: f64) {
    if seconds > 0.0 {
        *TIMEOUT.write() = seconds;
        let mode = mode();
        let peers = REGISTRY.read().store();
        install(peers, mode);
    }
}

pub fn own_address() -> String {
    OWN_ADDRESS.read().clone()
}

pub fn set_own_address(address: String) {
    *OWN_ADDRESS.write() = address;
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

    install(Arc::new(RedisPeerRegistry::new(backbone.clone())), REDIS);
    install_ids(Arc::new(RedisVirtualRoomIds::new(backbone)));
    Ok(())
}

pub fn seal_off() {
    install(Arc::new(UnavailablePeerRegistry::new()), UNAVAILABLE);
    install_ids(Arc::new(UnavailableVirtualRoomIds::new()));
}

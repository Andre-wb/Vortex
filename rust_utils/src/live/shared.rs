use std::sync::Arc;

use once_cell::sync::Lazy;
use parking_lot::RwLock;
use vortex_auth::ports::clock::Clock;
use vortex_auth::ports::entropy::Entropy;
use vortex_auth::random::system_entropy::SystemEntropy;
use vortex_auth::time::system_clock::SystemClock;
use vortex_live::call::service::GroupCallService;
use vortex_live::recording::service::RecordingService;
use vortex_live::stage::service::StageService;
use vortex_live::stream::schedule::service::StreamScheduleService;
use vortex_live::stream::service::StreamService;
use vortex_live::voice::service::VoiceChannelService;
use vortex_redis::backbone::RedisBackbone;
use vortex_redis::config::RedisConfig;
use vortex_redis::error::BackboneError;

use crate::live::stores::Stores;

pub const MEMORY: &str = "memory";
pub const REDIS: &str = "redis";
pub const UNAVAILABLE: &str = "unavailable";

pub struct Sessions {
    pub voice: VoiceChannelService,
    pub stage: StageService,
    pub recording: RecordingService,
    pub calls: GroupCallService,
    pub streams: StreamService,
    pub schedule: StreamScheduleService,
}

impl Sessions {
    fn kept_in(stores: Stores) -> Self {
        let clock: Arc<dyn Clock> = Arc::new(SystemClock::new());
        let entropy: Arc<dyn Entropy> = Arc::new(SystemEntropy::new());
        Sessions {
            voice: VoiceChannelService::new(stores.presence, clock.clone()),
            stage: StageService::new(stores.stage, clock.clone()),
            recording: RecordingService::new(stores.recording, clock.clone()),
            calls: GroupCallService::new(
                stores.call_records,
                stores.call_index,
                stores.rings,
                clock.clone(),
                entropy,
            ),
            streams: StreamService::new(
                stores.stream_records,
                stores.roster,
                stores.hands,
                stores.tally,
                stores.donations,
                clock.clone(),
            ),
            schedule: StreamScheduleService::new(stores.schedule, clock),
        }
    }
}

static MODE: Lazy<RwLock<&'static str>> = Lazy::new(|| RwLock::new(MEMORY));

static SESSIONS: Lazy<RwLock<Arc<Sessions>>> =
    Lazy::new(|| RwLock::new(Arc::new(Sessions::kept_in(Stores::in_memory()))));

fn install(stores: Stores, mode: &'static str) {
    *SESSIONS.write() = Arc::new(Sessions::kept_in(stores));
    *MODE.write() = mode;
}

pub fn sessions() -> Arc<Sessions> {
    SESSIONS.read().clone()
}

pub fn mode() -> &'static str {
    *MODE.read()
}

pub fn is_shared() -> bool {
    mode() == REDIS
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

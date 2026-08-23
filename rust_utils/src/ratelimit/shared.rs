use std::sync::Arc;

use once_cell::sync::Lazy;
use parking_lot::RwLock;
use vortex_auth::ports::clock::Clock;
use vortex_auth::time::system_clock::SystemClock;
use vortex_ratelimit::antispam::links::LinkSpamService;
use vortex_ratelimit::antispam::repeats::RepeatSpamService;
use vortex_ratelimit::assistant::service::AssistantRateService;
use vortex_ratelimit::flood::service::FloodService;
use vortex_ratelimit::gossip::service::GossipRateService;
use vortex_ratelimit::guest::service::GuestLoginRateService;
use vortex_ratelimit::node::service::NodeRateService;
use vortex_ratelimit::notification::service::NotificationRateService;
use vortex_ratelimit::preview::service::PreviewRateService;
use vortex_ratelimit::pseudonym::service::PseudonymRateService;
use vortex_ratelimit::push::service::PushRateService;
use vortex_ratelimit::replication::service::ReplicationRateService;
use vortex_ratelimit::secrets::service::TransportSecretsRateService;
use vortex_ratelimit::shard::service::ShardStoreRateService;
use vortex_ratelimit::signal::service::SignalRateService;
use vortex_ratelimit::translation::service::TranslationRateService;
use vortex_ratelimit::vault::service::VaultRateService;
use vortex_redis::backbone::RedisBackbone;
use vortex_redis::config::RedisConfig;
use vortex_redis::error::BackboneError;

use crate::ratelimit::stores::Stores;

pub const MEMORY: &str = "memory";
pub const REDIS: &str = "redis";
pub const UNAVAILABLE: &str = "unavailable";

pub struct Limits {
    pub assistant: AssistantRateService,
    pub flood: FloodService,
    pub gossip: GossipRateService,
    pub guest: GuestLoginRateService,
    pub links: LinkSpamService,
    pub node: NodeRateService,
    pub notification: NotificationRateService,
    pub preview: PreviewRateService,
    pub pseudonym: PseudonymRateService,
    pub push: PushRateService,
    pub replication: ReplicationRateService,
    pub repeats: RepeatSpamService,
    pub secrets: TransportSecretsRateService,
    pub shard: ShardStoreRateService,
    pub signal: SignalRateService,
    pub translation: TranslationRateService,
    pub vault: VaultRateService,
}

impl Limits {
    fn counted_by(stores: Stores) -> Self {
        let attempts = stores.attempts;
        Limits {
            assistant: AssistantRateService::new(attempts.clone()),
            flood: FloodService::new(stores.flood_window, stores.flood_reset, stores.strikes),
            gossip: GossipRateService::new(attempts.clone()),
            guest: GuestLoginRateService::new(attempts.clone()),
            links: LinkSpamService::new(attempts.clone(), stores.attempts_reset),
            node: NodeRateService::new(attempts.clone()),
            notification: NotificationRateService::new(attempts.clone()),
            preview: PreviewRateService::new(attempts.clone()),
            pseudonym: PseudonymRateService::new(attempts.clone()),
            push: PushRateService::new(attempts.clone()),
            replication: ReplicationRateService::new(attempts.clone()),
            repeats: RepeatSpamService::new(stores.repeats, stores.repeats_reset),
            secrets: TransportSecretsRateService::new(attempts.clone()),
            shard: ShardStoreRateService::new(attempts.clone()),
            signal: SignalRateService::new(attempts.clone()),
            translation: TranslationRateService::new(attempts.clone()),
            vault: VaultRateService::new(attempts),
        }
    }
}

static MODE: Lazy<RwLock<&'static str>> = Lazy::new(|| RwLock::new(MEMORY));

static LIMITS: Lazy<RwLock<Arc<Limits>>> =
    Lazy::new(|| RwLock::new(Arc::new(Limits::counted_by(Stores::in_memory()))));

static CLOCK: Lazy<SystemClock> = Lazy::new(SystemClock::new);

fn install(stores: Stores, mode: &'static str) {
    *LIMITS.write() = Arc::new(Limits::counted_by(stores));
    *MODE.write() = mode;
}

pub fn limits() -> Arc<Limits> {
    LIMITS.read().clone()
}

pub fn now() -> f64 {
    CLOCK.unix_seconds()
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

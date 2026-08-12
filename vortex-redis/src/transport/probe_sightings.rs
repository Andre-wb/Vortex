use std::sync::Arc;

use fred::prelude::*;
use vortex_transport::active_probe::config::{
    DEFAULT_MAX_TRACKED_REQUESTS, DEFAULT_REQUEST_MEMORY,
};
use vortex_transport::active_probe::store::memory_sightings::MemorySightings;
use vortex_transport::ports::probe_sightings::ProbeSightings;

use crate::backbone::RedisBackbone;
use crate::keys::KeySpace;
use crate::script::LuaScript;

const DOMAIN: &str = "active-probe";
const SIGHTINGS: &str = "sightings";

static REMEMBER: LuaScript = LuaScript::new(
    r#"
local previous = redis.call('ZSCORE', KEYS[1], ARGV[1])
redis.call('ZADD', KEYS[1], ARGV[2], ARGV[1])
if redis.call('ZCARD', KEYS[1]) > tonumber(ARGV[3]) then
  redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', ARGV[4])
end
if previous then
  return previous
end
return ''
"#,
);

pub struct RedisSightings {
    backbone: Arc<RedisBackbone>,
    fallback: Arc<MemorySightings>,
    capacity: usize,
    memory: f64,
    space: KeySpace,
}

impl RedisSightings {
    pub fn new(backbone: Arc<RedisBackbone>) -> Self {
        RedisSightings::with_limits(
            backbone,
            DEFAULT_MAX_TRACKED_REQUESTS,
            DEFAULT_REQUEST_MEMORY,
        )
    }

    pub fn with_limits(backbone: Arc<RedisBackbone>, capacity: usize, memory: f64) -> Self {
        let space = backbone.key_space(DOMAIN);
        RedisSightings {
            backbone,
            fallback: Arc::new(MemorySightings::new(capacity, memory)),
            capacity,
            memory,
            space,
        }
    }

    fn sightings_key(&self) -> String {
        self.space.key(SIGHTINGS)
    }
}

impl ProbeSightings for RedisSightings {
    fn remember(&self, fingerprint: &str, now: f64) -> Option<f64> {
        let key = self.sightings_key();
        let member = fingerprint.to_owned();
        let capacity = self.capacity.max(1) as i64;
        let cutoff = now - self.memory;

        let answered = self.backbone.execute(
            "запись отпечатка запроса",
            move |pool| {
                let keys = vec![key.clone()];
                let args: Vec<Value> = vec![
                    member.clone().into(),
                    now.into(),
                    capacity.into(),
                    cutoff.into(),
                ];
                async move { REMEMBER.run::<String>(&pool, keys, args).await }
            },
        );

        match answered {
            Ok(previous) => previous.parse::<f64>().ok(),
            Err(_) => self.fallback.remember(fingerprint, now),
        }
    }

    fn forget_stale(&self, cutoff: f64) {
        self.fallback.forget_stale(cutoff);
        let key = self.sightings_key();
        let _ = self.backbone.execute(
            "уборка отпечатков запросов",
            move |pool| {
                let key = key.clone();
                async move {
                    let _: i64 = pool
                        .zremrangebyscore(key, f64::NEG_INFINITY, cutoff)
                        .await?;
                    Ok::<(), Error>(())
                }
            },
        );
    }

    fn len(&self) -> usize {
        let key = self.sightings_key();
        let counted =
            self.backbone
                .execute("размер кэша отпечатков", move |pool| {
                    let key = key.clone();
                    async move { pool.zcard::<u64, _>(key).await }
                });
        counted.unwrap_or_default() as usize + self.fallback.len()
    }
}

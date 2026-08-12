use std::sync::Arc;

use fred::prelude::*;
use vortex_transport::active_probe::config::{DEFAULT_MAX_TRACKED_PROBES, DEFAULT_PROBE_MEMORY};
use vortex_transport::active_probe::store::memory_roll::MemoryRoll;
use vortex_transport::ports::probe_roll::ProbeRoll;

use crate::backbone::RedisBackbone;
use crate::keys::KeySpace;
use crate::script::LuaScript;

const DOMAIN: &str = "active-probe";
const ROLL: &str = "roll";

static RECORD: LuaScript = LuaScript::new(
    r#"
local known = redis.call('ZSCORE', KEYS[1], ARGV[1])
redis.call('ZADD', KEYS[1], ARGV[2], ARGV[1])
local capacity = tonumber(ARGV[3])
if redis.call('ZCARD', KEYS[1]) > capacity then
  redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', ARGV[4])
  local over = redis.call('ZCARD', KEYS[1]) - capacity
  if over > 0 then
    redis.call('ZREMRANGEBYRANK', KEYS[1], 0, over - 1)
  end
end
if known then
  return 0
end
return 1
"#,
);

pub struct RedisRoll {
    backbone: Arc<RedisBackbone>,
    fallback: Arc<MemoryRoll>,
    capacity: usize,
    memory: f64,
    space: KeySpace,
}

impl RedisRoll {
    pub fn new(backbone: Arc<RedisBackbone>) -> Self {
        RedisRoll::with_limits(backbone, DEFAULT_MAX_TRACKED_PROBES, DEFAULT_PROBE_MEMORY)
    }

    pub fn with_limits(backbone: Arc<RedisBackbone>, capacity: usize, memory: f64) -> Self {
        let space = backbone.key_space(DOMAIN);
        RedisRoll {
            backbone,
            fallback: Arc::new(MemoryRoll::new(capacity, memory)),
            capacity,
            memory,
            space,
        }
    }

    fn roll_key(&self) -> String {
        self.space.key(ROLL)
    }
}

impl ProbeRoll for RedisRoll {
    fn record(&self, peer: &str, now: f64) -> bool {
        let key = self.roll_key();
        let member = peer.to_owned();
        let capacity = self.capacity.max(1) as i64;
        let cutoff = now - self.memory;

        let answered = self.backbone.execute("запись адреса зонда", move |pool| {
            let keys = vec![key.clone()];
            let args: Vec<Value> = vec![
                member.clone().into(),
                now.into(),
                capacity.into(),
                cutoff.into(),
            ];
            async move { RECORD.run::<i64>(&pool, keys, args).await }
        });

        match answered {
            Ok(first_time) => first_time == 1,
            Err(_) => self.fallback.record(peer, now),
        }
    }

    fn holds(&self, peer: &str) -> bool {
        if self.fallback.holds(peer) {
            return true;
        }
        let key = self.roll_key();
        let member = peer.to_owned();
        let scored = self.backbone.execute("поиск адреса зонда", move |pool| {
            let key = key.clone();
            let member = member.clone();
            async move { pool.zscore::<Option<f64>, _, _>(key, member).await }
        });
        matches!(scored, Ok(Some(_)))
    }

    fn forget_stale(&self, cutoff: f64) {
        self.fallback.forget_stale(cutoff);
        let key = self.roll_key();
        let _ = self.backbone.execute("уборка адресов зондов", move |pool| {
            let key = key.clone();
            async move {
                let _: i64 = pool
                    .zremrangebyscore(key, f64::NEG_INFINITY, cutoff)
                    .await?;
                Ok::<(), Error>(())
            }
        });
    }

    fn len(&self) -> usize {
        let key = self.roll_key();
        let counted = self.backbone.execute("размер списка зондов", move |pool| {
            let key = key.clone();
            async move { pool.zcard::<u64, _>(key).await }
        });
        counted.unwrap_or_default() as usize + self.fallback.len()
    }
}

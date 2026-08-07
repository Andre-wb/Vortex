use std::sync::Arc;

use fred::prelude::*;
use vortex_transport::ports::seen_envelopes::SeenEnvelopes;
use vortex_transport::reality::replay::memory_seen::MemorySeenEnvelopes;

use crate::backbone::RedisBackbone;
use crate::keys::KeySpace;
use crate::script::LuaScript;

const DOMAIN: &str = "reality";
const SEEN_NAME: &str = "seen";

static REMEMBER: LuaScript = LuaScript::new(
    r#"
local capacity = tonumber(ARGV[2])
if redis.call('ZSCORE', KEYS[1], ARGV[1]) then
  return 0
end
if redis.call('ZCARD', KEYS[1]) >= capacity then
  return 0
end
redis.call('ZADD', KEYS[1], tonumber(ARGV[3]), ARGV[1])
return 1
"#,
);

pub struct RedisSeenEnvelopes {
    backbone: Arc<RedisBackbone>,
    fallback: Arc<MemorySeenEnvelopes>,
    capacity: usize,
    space: KeySpace,
}

impl RedisSeenEnvelopes {
    pub fn new(backbone: Arc<RedisBackbone>) -> Self {
        Self::with_capacity(
            backbone,
            vortex_transport::reality::replay::memory_seen::DEFAULT_CAPACITY,
        )
    }

    pub fn with_capacity(backbone: Arc<RedisBackbone>, capacity: usize) -> Self {
        let space = backbone.key_space(DOMAIN);
        RedisSeenEnvelopes {
            backbone,
            fallback: Arc::new(MemorySeenEnvelopes::with_capacity(capacity)),
            capacity,
            space,
        }
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    fn seen_key(&self) -> String {
        self.space.key(SEEN_NAME)
    }
}

impl SeenEnvelopes for RedisSeenEnvelopes {
    fn prune(&self, now: i64) {
        self.fallback.prune(now);
        let key = self.seen_key();
        let _ = self.backbone.execute("уборка кэша повторов", move |pool| {
            let key = key.clone();
            async move {
                let _: i64 = pool
                    .zremrangebyscore(key, f64::NEG_INFINITY, (now - 1) as f64)
                    .await?;
                Ok::<(), Error>(())
            }
        });
    }

    fn remember(&self, envelope: &[u8], valid_until: i64) -> bool {
        let key = self.seen_key();
        let member = hex_of(envelope);
        let capacity = self.capacity as i64;

        let verdict = self.backbone.execute("запись конверта", move |pool| {
            let keys = vec![key.clone()];
            let args: Vec<Value> = vec![member.clone().into(), capacity.into(), valid_until.into()];
            async move { REMEMBER.run::<i64>(&pool, keys, args).await }
        });

        match verdict {
            Ok(accepted) => accepted == 1,
            Err(_) => self.fallback.remember(envelope, valid_until),
        }
    }

    fn len(&self) -> usize {
        let key = self.seen_key();
        let counted = self.backbone.execute("размер кэша повторов", move |pool| {
            let key = key.clone();
            async move { pool.zcard::<u64, _>(key).await }
        });
        counted.unwrap_or_default() as usize + self.fallback.len()
    }
}

fn hex_of(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::hex_of;

    #[test]
    fn an_envelope_becomes_a_printable_member() {
        assert_eq!(hex_of(&[0x00, 0xab, 0xff]), "00abff");
    }
}

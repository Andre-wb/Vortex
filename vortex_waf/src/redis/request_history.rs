use std::sync::Arc;

use fred::prelude::*;
use vortex_redis::backbone::RedisBackbone;
use vortex_redis::keys::KeySpace;
use vortex_redis::script::LuaScript;

use crate::domain::client_ip::ClientIp;
use crate::domain::timestamp::Timestamp;
use crate::ports::request_history::RequestHistory;
use crate::ratelimit::memory_history::InMemoryRequestHistory;

const DOMAIN: &str = "waf";
const WINDOW_NAME: &str = "rate";
const INDEX_NAME: &str = "rate-index";

static REGISTER: LuaScript = LuaScript::new(
    r#"
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local requests = tonumber(ARGV[3])
local address = ARGV[4]

redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', '(' .. (now - window))
local hits = redis.call('ZCARD', KEYS[1])
if hits >= requests then
  local oldest = redis.call('ZRANGE', KEYS[1], 0, 0, 'WITHSCORES')
  return {hits, tonumber(oldest[2])}
end

local sequence = redis.call('INCR', KEYS[3])
redis.call('ZADD', KEYS[1], now, string.format('%019d', sequence))
redis.call('PEXPIRE', KEYS[1], math.ceil(window) * 2)
redis.call('SADD', KEYS[2], address)
return {}
"#,
);

pub struct RedisRequestHistory {
    backbone: Arc<RedisBackbone>,
    fallback: Arc<InMemoryRequestHistory>,
    space: KeySpace,
}

impl RedisRequestHistory {
    pub fn new(backbone: Arc<RedisBackbone>) -> Self {
        let space = backbone.key_space(DOMAIN);
        RedisRequestHistory {
            backbone,
            fallback: Arc::new(InMemoryRequestHistory::new()),
            space,
        }
    }

    pub fn fallback(&self) -> &Arc<InMemoryRequestHistory> {
        &self.fallback
    }

    fn window_key(&self, ip: &ClientIp) -> String {
        self.space.member_key(WINDOW_NAME, &ip.to_string())
    }

    fn index_key(&self) -> String {
        self.space.key(INDEX_NAME)
    }

    fn addresses(&self) -> Vec<ClientIp> {
        let index = self.index_key();
        let listed = self.backbone.execute("список адресов", move |pool| {
            let index = index.clone();
            async move { pool.smembers::<Vec<String>, _>(index).await }
        });
        listed
            .unwrap_or_default()
            .into_iter()
            .map(ClientIp::new)
            .collect()
    }
}

impl RequestHistory for RedisRequestHistory {
    fn register(
        &self,
        ip: &ClientIp,
        now: Timestamp,
        requests: usize,
        window_secs: u64,
    ) -> Option<(usize, f64)> {
        let keys = vec![
            self.window_key(ip),
            self.index_key(),
            self.space.key("rate-sequence"),
        ];
        let window_millis = (window_secs as i64).saturating_mul(1000);
        let args: Vec<Value> = vec![
            now.unix_millis().into(),
            window_millis.into(),
            (requests as i64).into(),
            ip.to_string().into(),
        ];

        let verdict = self.backbone.execute("учёт обращения", move |pool| {
            let keys = keys.clone();
            let args = args.clone();
            async move { REGISTER.run::<Vec<i64>>(&pool, keys, args).await }
        });

        match verdict {
            Ok(reply) if reply.is_empty() => None,
            Ok(reply) => {
                let hits = *reply.first().unwrap_or(&0) as usize;
                let oldest = Timestamp::from_unix_millis(*reply.get(1).unwrap_or(&0));
                Some((hits, window_secs as f64 - now.secs_since(oldest)))
            }
            Err(_) => self.fallback.register(ip, now, requests, window_secs),
        }
    }

    fn hits_in_window(&self, ip: &ClientIp, now: Timestamp, window_secs: u64) -> usize {
        let key = self.window_key(ip);
        let window_start = now.minus_secs(window_secs).unix_millis();
        let counted = self.backbone.execute("обращений в окне", move |pool| {
            let key = key.clone();
            async move {
                pool.zcount::<u64, _>(key, (window_start + 1) as f64, f64::INFINITY)
                    .await
            }
        });
        counted.unwrap_or_default() as usize + self.fallback.hits_in_window(ip, now, window_secs)
    }

    fn forget_stale(&self, now: Timestamp, window_secs: u64) -> usize {
        let mut removed = self.fallback.forget_stale(now, window_secs);
        let cutoff = now.minus_secs(window_secs).unix_millis();

        for ip in self.addresses() {
            let key = self.window_key(&ip);
            let index = self.index_key();
            let address = ip.to_string();
            let dropped = self.backbone.execute("уборка истории", move |pool| {
                let key = key.clone();
                let index = index.clone();
                let address = address.clone();
                async move {
                    let _: i64 = pool
                        .zremrangebyscore(key.as_str(), f64::NEG_INFINITY, cutoff as f64)
                        .await?;
                    let left: u64 = pool.zcard(key.as_str()).await?;
                    if left == 0 {
                        let _: i64 = pool.del(key).await?;
                        let _: i64 = pool.srem(index, address).await?;
                        return Ok::<bool, Error>(true);
                    }
                    Ok::<bool, Error>(false)
                }
            });
            if dropped.unwrap_or(false) {
                removed += 1;
            }
        }
        removed
    }

    fn tracked_clients(&self) -> usize {
        let index = self.index_key();
        let counted = self.backbone.execute("адресов под учётом", move |pool| {
            let index = index.clone();
            async move { pool.scard::<u64, _>(index).await }
        });
        counted.unwrap_or_default() as usize + self.fallback.tracked_clients()
    }
}

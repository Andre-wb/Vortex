use crate::script::LuaScript;

pub const DOMAIN: &str = "live";
pub const ABSENT: i64 = 0;
pub const CHANGED: i64 = 1;
pub const SWAPPED: i64 = 2;
pub const NOTHING: &str = "";

pub fn seconds_left(until: f64, now: f64) -> i64 {
    let left = (until - now).ceil() as i64;
    left.max(1)
}

pub static HOLD: LuaScript = LuaScript::new(
    r#"
local existing = redis.call('HGET', KEYS[1], ARGV[1])
if not existing then
  redis.call('HSET', KEYS[1], ARGV[1], ARGV[2])
end
redis.call('EXPIRE', KEYS[1], ARGV[3])
return existing or ''
"#,
);

pub static HSWAP: LuaScript = LuaScript::new(
    r#"
local raw = redis.call('HGET', KEYS[1], ARGV[1])
if not raw then return 0 end
if raw ~= ARGV[2] then return 1 end
redis.call('HSET', KEYS[1], ARGV[1], ARGV[3])
redis.call('EXPIRE', KEYS[1], ARGV[4])
return 2
"#,
);

pub static SWAP_KEEPING_LIFE: LuaScript = LuaScript::new(
    r#"
local raw = redis.call('GET', KEYS[1])
if not raw then return 0 end
if raw ~= ARGV[1] then return 1 end
redis.call('SET', KEYS[1], ARGV[2], 'EX', ARGV[3])
return 2
"#,
);

pub static CLAIM: LuaScript = LuaScript::new(
    r#"
local taken = redis.call('SET', KEYS[1], ARGV[1], 'NX', 'EX', ARGV[2])
if taken then return '' end
return redis.call('GET', KEYS[1]) or ''
"#,
);

pub static RELEASE: LuaScript = LuaScript::new(
    r#"
if redis.call('GET', KEYS[1]) == ARGV[1] then
  redis.call('DEL', KEYS[1])
  return 1
end
return 0
"#,
);

pub static RAISE: LuaScript = LuaScript::new(
    r#"
local current = tonumber(redis.call('HGET', KEYS[1], ARGV[1]) or '0')
local seen = tonumber(ARGV[2])
if seen > current then
  redis.call('HSET', KEYS[1], ARGV[1], seen)
  current = seen
end
redis.call('EXPIRE', KEYS[1], ARGV[3])
return current
"#,
);

pub static CLAIM_DUE: LuaScript = LuaScript::new(
    r#"
local due = redis.call('ZRANGEBYSCORE', KEYS[1], '-inf', ARGV[1], 'LIMIT', 0, 1)
if #due == 0 then return '' end
local room = due[1]
redis.call('ZREM', KEYS[1], room)
local raw = redis.call('HGET', KEYS[2], room)
redis.call('HDEL', KEYS[2], room)
return raw or ''
"#,
);

pub static PLAN: LuaScript = LuaScript::new(
    r#"
redis.call('ZADD', KEYS[1], ARGV[1], ARGV[2])
redis.call('HSET', KEYS[2], ARGV[2], ARGV[3])
redis.call('EXPIRE', KEYS[1], ARGV[4])
redis.call('EXPIRE', KEYS[2], ARGV[4])
return 1
"#,
);

pub static UNPLAN: LuaScript = LuaScript::new(
    r#"
local removed = redis.call('ZREM', KEYS[1], ARGV[1])
redis.call('HDEL', KEYS[2], ARGV[1])
return removed
"#,
);

#[cfg(test)]
mod tests {
    use super::seconds_left;

    #[test]
    fn a_lifetime_is_counted_up_to_the_whole_second() {
        assert_eq!(seconds_left(1_060.0, 1_000.0), 60);
        assert_eq!(seconds_left(1_000.4, 1_000.0), 1);
    }

    #[test]
    fn a_record_that_already_expired_still_gets_the_shortest_life_redis_allows() {
        assert_eq!(seconds_left(1_000.0, 1_000.0), 1);
        assert_eq!(seconds_left(900.0, 1_000.0), 1);
    }
}

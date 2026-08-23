use crate::script::LuaScript;

pub const REFUSED: i64 = 0;
pub const ALLOWED: i64 = 1;

pub static SCRIPT: LuaScript = LuaScript::new(
    r#"
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])

redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', now - window)
if redis.call('ZCARD', KEYS[1]) >= limit then
  return 0
end
local sequence = redis.call('INCR', KEYS[2])
redis.call('ZADD', KEYS[1], now, sequence)
redis.call('EXPIRE', KEYS[1], math.ceil(window) + 1)
return 1
"#,
);

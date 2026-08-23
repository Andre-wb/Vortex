use crate::script::LuaScript;

pub const ABSENT: i64 = 0;
pub const CHANGED: i64 = 1;
pub const SWAPPED: i64 = 2;

pub static SWAP: LuaScript = LuaScript::new(
    r#"
local raw = redis.call('GET', KEYS[1])
if not raw then return 0 end
if raw ~= ARGV[1] then return 1 end
if ARGV[2] == '' then
  redis.call('DEL', KEYS[1])
  return 2
end
local ttl = redis.call('TTL', KEYS[1])
if ttl > 0 then
  redis.call('SET', KEYS[1], ARGV[2], 'EX', ttl)
else
  redis.call('SET', KEYS[1], ARGV[2], 'KEEPTTL')
end
return 2
"#,
);

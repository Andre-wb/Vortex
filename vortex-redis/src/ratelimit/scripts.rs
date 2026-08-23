use crate::script::LuaScript;

pub static REPEATS: LuaScript = LuaScript::new(
    r#"
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local digest = ARGV[3]

redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', now - window)
local sequence = redis.call('INCR', KEYS[2])
redis.call('ZADD', KEYS[1], now, sequence .. ':' .. digest)
redis.call('EXPIRE', KEYS[1], math.ceil(window) + 1)

local same = 0
local entries = redis.call('ZRANGE', KEYS[1], 0, -1)
for _, entry in ipairs(entries) do
  local separator = string.find(entry, ':', 1, true)
  if separator and string.sub(entry, separator + 1) == digest then
    same = same + 1
  end
end
return same
"#,
);

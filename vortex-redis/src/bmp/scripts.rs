use crate::script::LuaScript;

pub static DEPOSIT: LuaScript = LuaScript::new(
    r#"
local ciphertext = ARGV[2]
local incoming = string.len(ciphertext)
if incoming > tonumber(ARGV[7]) then
  redis.call('HINCRBY', KEYS[6], 'refused', 1)
  return {0, 'too_large'}
end

local id = ARGV[1]
local now = tonumber(ARGV[3])
local max_messages = tonumber(ARGV[4])
local max_mailboxes = tonumber(ARGV[5])
local max_total = tonumber(ARGV[6])
local box_ttl = tonumber(ARGV[8])

local exists = redis.call('EXISTS', KEYS[1]) == 1
if not exists and redis.call('SCARD', KEYS[2]) >= max_mailboxes then
  redis.call('HINCRBY', KEYS[6], 'refused', 1)
  return {0, 'at_capacity'}
end

local card = redis.call('ZCARD', KEYS[1])
local evicted = 0
if card >= max_messages then
  local oldest = redis.call('ZRANGE', KEYS[1], 0, 0)
  if oldest[1] then
    local separator = string.find(oldest[1], ':', 1, true)
    evicted = string.len(oldest[1]) - separator
  end
end

local total = tonumber(redis.call('GET', KEYS[4]) or '0')
local projected = total + incoming - evicted
if projected > max_total then
  redis.call('HINCRBY', KEYS[6], 'refused', 1)
  return {0, 'at_capacity'}
end

if card >= max_messages then
  redis.call('ZREMRANGEBYRANK', KEYS[1], 0, 0)
else
  redis.call('HINCRBY', KEYS[6], 'messages', 1)
end

local sequence = redis.call('INCR', KEYS[5])
redis.call('ZADD', KEYS[1], now, string.format('%019d', sequence) .. ':' .. ciphertext)
redis.call('SADD', KEYS[2], id)
redis.call('HINCRBY', KEYS[3], id, incoming - evicted)
redis.call('SET', KEYS[4], projected)
redis.call('EXPIRE', KEYS[1], box_ttl)
redis.call('HINCRBY', KEYS[6], 'deposited', 1)
return {1, 'ok'}
"#,
);

pub static COLLECT: LuaScript = LuaScript::new(
    r#"
local cutoff = tonumber(ARGV[1])
local removed = 0
local freed = 0

for index = 2, #ARGV do
  local id = ARGV[index]
  local box_key = KEYS[5] .. ':' .. id

  if redis.call('EXISTS', box_key) == 0 then
    local orphan = tonumber(redis.call('HGET', KEYS[3], id) or '0')
    freed = freed + orphan
    redis.call('HDEL', KEYS[3], id)
    redis.call('SREM', KEYS[2], id)
  else
    local expired = redis.call('ZRANGEBYSCORE', box_key, '-inf', cutoff)
    if #expired > 0 then
      local bytes = 0
      for _, member in ipairs(expired) do
        local separator = string.find(member, ':', 1, true)
        bytes = bytes + string.len(member) - separator
      end
      redis.call('ZREMRANGEBYSCORE', box_key, '-inf', cutoff)
      removed = removed + #expired
      freed = freed + bytes
      redis.call('HINCRBY', KEYS[3], id, -bytes)
    end

    if redis.call('ZCARD', box_key) == 0 then
      redis.call('DEL', box_key)
      redis.call('HDEL', KEYS[3], id)
      redis.call('SREM', KEYS[2], id)
    end
  end
end

if freed > 0 then
  local total = tonumber(redis.call('GET', KEYS[4]) or '0') - freed
  if total < 0 then total = 0 end
  redis.call('SET', KEYS[4], total)
end
if removed > 0 then
  redis.call('HINCRBY', KEYS[6], 'expired', removed)
  redis.call('HINCRBY', KEYS[6], 'messages', -removed)
end
return removed
"#,
);

pub static SLIDING_WINDOW: LuaScript = LuaScript::new(
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

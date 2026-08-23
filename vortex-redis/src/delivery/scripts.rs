use crate::script::LuaScript;

pub const DOMAIN: &str = "delivery";

pub static REMEMBER: LuaScript = LuaScript::new(
    r#"
local now = tonumber(ARGV[1])
local lifetime = tonumber(ARGV[2])
local capacity = tonumber(ARGV[3])
local message = ARGV[4]

redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', now - lifetime)
if redis.call('ZSCORE', KEYS[1], message) then
  return 0
end
redis.call('ZADD', KEYS[1], now, message)
local excess = redis.call('ZCARD', KEYS[1]) - capacity
if excess > 0 then
  redis.call('ZREMRANGEBYRANK', KEYS[1], 0, excess - 1)
end
redis.call('EXPIRE', KEYS[1], math.ceil(lifetime) + 1)
return 1
"#,
);

pub static DEPOSIT: LuaScript = LuaScript::new(
    r#"
local now = tonumber(ARGV[1])
local lifetime = tonumber(ARGV[2])
local depth = tonumber(ARGV[3])
local payload = ARGV[4]
local life = math.ceil(lifetime) + 1

local sequence = redis.call('INCR', KEYS[1])
local entry = sequence .. ':' .. now .. ':' .. payload

for index = 3, #KEYS do
  redis.call('RPUSH', KEYS[index], entry)
  redis.call('LTRIM', KEYS[index], -depth, -1)
  redis.call('EXPIRE', KEYS[index], life)
  redis.call('SADD', KEYS[2], ARGV[index + 2])
end
redis.call('EXPIRE', KEYS[2], life)
return #KEYS - 2
"#,
);

pub static COLLECT: LuaScript = LuaScript::new(
    r#"
local entries = redis.call('LRANGE', KEYS[1], 0, -1)
redis.call('DEL', KEYS[1])
redis.call('SREM', KEYS[2], ARGV[1])
return entries
"#,
);

pub static TRIM_STALE: LuaScript = LuaScript::new(
    r#"
local now = tonumber(ARGV[1])
local lifetime = tonumber(ARGV[2])
local removed = 0

while true do
  local head = redis.call('LINDEX', KEYS[1], 0)
  if not head then
    break
  end
  local first = string.find(head, ':', 1, true)
  if not first then
    break
  end
  local second = string.find(head, ':', first + 1, true)
  if not second then
    break
  end
  local stamped = tonumber(string.sub(head, first + 1, second - 1))
  if stamped and (now - stamped) > lifetime then
    redis.call('LPOP', KEYS[1])
    removed = removed + 1
  else
    break
  end
end

if redis.call('EXISTS', KEYS[1]) == 0 then
  redis.call('SREM', KEYS[2], ARGV[3])
end
return removed
"#,
);

pub fn seconds_of(lifetime: f64) -> i64 {
    lifetime.ceil() as i64 + 1
}

pub fn payload_of(entry: &str) -> Option<&str> {
    let after_sequence = entry.find(':')? + 1;
    let after_stamp = entry[after_sequence..].find(':')? + after_sequence + 1;
    Some(&entry[after_stamp..])
}

pub fn stamp_of(entry: &str) -> Option<f64> {
    let after_sequence = entry.find(':')? + 1;
    let width = entry[after_sequence..].find(':')?;
    entry[after_sequence..after_sequence + width].parse().ok()
}

#[cfg(test)]
mod tests {
    use super::{payload_of, seconds_of, stamp_of};

    #[test]
    fn a_lifetime_becomes_a_whole_number_of_seconds_with_a_margin() {
        assert_eq!(seconds_of(300.0), 301);
        assert_eq!(seconds_of(299.4), 301);
    }

    #[test]
    fn an_entry_gives_back_its_stamp_and_its_payload() {
        let entry = "17:1700.5:{\"type\":\"message\"}";
        assert_eq!(stamp_of(entry), Some(1700.5));
        assert_eq!(payload_of(entry), Some("{\"type\":\"message\"}"));
    }

    #[test]
    fn a_payload_carrying_colons_survives_intact() {
        let entry = "3:1000:{\"url\":\"https://example.com:8443\"}";
        assert_eq!(
            payload_of(entry),
            Some("{\"url\":\"https://example.com:8443\"}")
        );
    }

    #[test]
    fn a_malformed_entry_yields_nothing() {
        assert_eq!(payload_of("no-separators"), None);
        assert_eq!(stamp_of("17:"), None);
    }
}

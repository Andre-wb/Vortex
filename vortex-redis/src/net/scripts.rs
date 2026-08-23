use crate::script::LuaScript;

pub const DOMAIN: &str = "net";

pub static OBSERVE: LuaScript = LuaScript::new(
    r#"
local address = ARGV[1]
local name = ARGV[2]
local port = ARGV[3]
local pubkey = ARGV[4]
local seen = tonumber(ARGV[5])

local known = redis.call('HGET', KEYS[1], address)
local fresh = 1
if known then
  fresh = 0
  if pubkey == '' then
    local first = string.find(known, ':', 1, true)
    local second = string.find(known, ':', first + 1, true)
    local third = string.find(known, ':', second + 1, true)
    pubkey = string.sub(known, second + 1, third - 1)
  end
end

redis.call('HSET', KEYS[1], address, port .. ':' .. seen .. ':' .. pubkey .. ':' .. name)
redis.call('ZADD', KEYS[2], seen, address)
return fresh
"#,
);

pub static ALIVE: LuaScript = LuaScript::new(
    r#"
local living = redis.call('ZRANGEBYSCORE', KEYS[2], '(' .. ARGV[1], '+inf')
local told = {}
for index = 1, #living do
  local record = redis.call('HGET', KEYS[1], living[index])
  if record then
    told[#told + 1] = living[index]
    told[#told + 1] = record
  end
end
return told
"#,
);

pub static FORGET_DEAD: LuaScript = LuaScript::new(
    r#"
local dead = redis.call('ZRANGEBYSCORE', KEYS[2], '-inf', ARGV[1])
for index = 1, #dead do
  redis.call('HDEL', KEYS[1], dead[index])
  redis.call('HDEL', KEYS[3], dead[index])
end
if #dead > 0 then
  redis.call('ZREMRANGEBYSCORE', KEYS[2], '-inf', ARGV[1])
end
return #dead
"#,
);

pub fn written(port: u16, seen: f64, pubkey: Option<&str>, name: &str) -> String {
    format!("{}:{}:{}:{}", port, seen, pubkey.unwrap_or_default(), name)
}

pub fn read(record: &str) -> Option<(u16, f64, Option<String>, String)> {
    let first = record.find(':')?;
    let second = record[first + 1..].find(':')? + first + 1;
    let third = record[second + 1..].find(':')? + second + 1;

    let port = record[..first].parse().ok()?;
    let seen = record[first + 1..second].parse().ok()?;
    let pubkey = &record[second + 1..third];
    let name = &record[third + 1..];

    Some((
        port,
        seen,
        (!pubkey.is_empty()).then(|| pubkey.to_owned()),
        name.to_owned(),
    ))
}

pub static RESERVE_BELOW: LuaScript = LuaScript::new(
    r#"
local taken = tonumber(ARGV[1])
local handed = tonumber(redis.call('GET', KEYS[1]) or 0)
if taken < handed then
  redis.call('SET', KEYS[1], taken)
  return taken
end
return handed
"#,
);

#[cfg(test)]
mod tests {
    use super::{read, written};

    #[test]
    fn a_record_survives_a_round_trip() {
        let row = written(8000, 1700.5, Some(&"ab".repeat(32)), "laptop");
        let (port, seen, pubkey, name) = read(&row).unwrap();
        assert_eq!(port, 8000);
        assert_eq!(seen, 1700.5);
        assert_eq!(pubkey, Some("ab".repeat(32)));
        assert_eq!(name, "laptop");
    }

    #[test]
    fn a_record_without_a_key_survives_a_round_trip() {
        let (_, _, pubkey, name) = read(&written(9000, 1.0, None, "quiet")).unwrap();
        assert!(pubkey.is_none());
        assert_eq!(name, "quiet");
    }

    #[test]
    fn a_malformed_record_yields_nothing() {
        assert!(read("no-separators").is_none());
        assert!(read("8000:1.0").is_none());
    }
}

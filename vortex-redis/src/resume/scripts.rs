use crate::script::LuaScript;

pub const DOMAIN: &str = "resume";

pub const SESSION_FIELDS: usize = 7;

pub static OPEN: LuaScript = LuaScript::new(
    r#"
local life = tonumber(ARGV[8])
redis.call('DEL', KEYS[1], KEYS[2])
redis.call('HSET', KEYS[1],
  'room', ARGV[1],
  'owner', ARGV[2],
  'name', ARGV[3],
  'bytes', ARGV[4],
  'chunks', ARGV[5],
  'digest', ARGV[6],
  'opened', ARGV[7])
redis.call('EXPIRE', KEYS[1], life)
for index = 11, #ARGV do
  redis.call('SADD', KEYS[2], ARGV[index])
end
if redis.call('EXISTS', KEYS[2]) == 1 then
  redis.call('EXPIRE', KEYS[2], life)
end
redis.call('ZADD', KEYS[3], tonumber(ARGV[9]), ARGV[10])
return 1
"#,
);

pub static FIND: LuaScript = LuaScript::new(
    r#"
local row = redis.call('HMGET', KEYS[1],
  'room', 'owner', 'name', 'bytes', 'chunks', 'digest', 'opened')
if not row[7] then
  return {}
end
local held = redis.call('SMEMBERS', KEYS[2])
for index = 1, #held do
  row[#row + 1] = held[index]
end
return row
"#,
);

pub static TAKE: LuaScript = LuaScript::new(
    r#"
local row = redis.call('HMGET', KEYS[1],
  'room', 'owner', 'name', 'bytes', 'chunks', 'digest', 'opened')
if not row[7] then
  return {}
end
redis.call('SADD', KEYS[2], ARGV[1])
redis.call('EXPIRE', KEYS[2], tonumber(ARGV[2]))
local held = redis.call('SMEMBERS', KEYS[2])
for index = 1, #held do
  row[#row + 1] = held[index]
end
return row
"#,
);

pub static CLOSE: LuaScript = LuaScript::new(
    r#"
local existed = redis.call('EXISTS', KEYS[1])
redis.call('DEL', KEYS[1], KEYS[2])
redis.call('ZREM', KEYS[3], ARGV[1])
return existed
"#,
);

pub static SAVE_CURSOR: LuaScript = LuaScript::new(
    r#"
local life = tonumber(ARGV[4])
redis.call('HSET', KEYS[1], 'stamp', ARGV[1], 'rooms', ARGV[2], 'saved', ARGV[3])
redis.call('EXPIRE', KEYS[1], life)
redis.call('SADD', KEYS[2], ARGV[5])
return 1
"#,
);

pub static FIND_CURSOR: LuaScript = LuaScript::new(
    r#"
local row = redis.call('HMGET', KEYS[1], 'stamp', 'rooms', 'saved')
if not row[3] then
  redis.call('SREM', KEYS[2], ARGV[1])
  return {}
end
return row
"#,
);

pub static FORGET_CURSOR: LuaScript = LuaScript::new(
    r#"
local existed = redis.call('EXISTS', KEYS[1])
redis.call('DEL', KEYS[1])
redis.call('SREM', KEYS[2], ARGV[1])
return existed
"#,
);

pub fn seconds_of(lifetime: f64) -> i64 {
    lifetime.ceil() as i64 + 1
}

pub fn rooms_written(rooms: &[i64]) -> String {
    rooms
        .iter()
        .map(|room| room.to_string())
        .collect::<Vec<String>>()
        .join(",")
}

pub fn rooms_read(written: &str) -> Vec<i64> {
    written
        .split(',')
        .filter(|piece| !piece.is_empty())
        .filter_map(|piece| piece.parse().ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{rooms_read, rooms_written, seconds_of};

    #[test]
    fn a_lifetime_becomes_a_whole_number_of_seconds_with_a_margin() {
        assert_eq!(seconds_of(86400.0), 86401);
        assert_eq!(seconds_of(299.4), 301);
    }

    #[test]
    fn a_room_list_survives_a_round_trip() {
        assert_eq!(rooms_read(&rooms_written(&[1, 3, 9])), vec![1, 3, 9]);
    }

    #[test]
    fn an_empty_room_list_survives_a_round_trip() {
        assert_eq!(rooms_written(&[]), "");
        assert!(rooms_read("").is_empty());
    }
}

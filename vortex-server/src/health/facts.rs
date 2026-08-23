use serde_json::Value;

pub const LIVENESS_FIELDS: [&str; 11] = [
    "instance_id",
    "crypto_backend",
    "key_exchange",
    "post_quantum",
    "database",
    "redis",
    "scaling",
    "active_peers",
    "ws_connections",
    "own_ip",
    "uptime_seconds",
];

pub const LIVENESS_GLOBAL_FIELDS: [&str; 2] = ["global_peers", "obfuscation"];

pub const READINESS_FIELDS: [&str; 2] = ["database", "background_tasks"];

#[derive(Debug, Clone, PartialEq)]
pub struct LivenessFacts {
    pub instance_id: Value,
    pub crypto_backend: Value,
    pub key_exchange: Value,
    pub post_quantum: Value,
    pub database: Value,
    pub redis: Value,
    pub scaling: Value,
    pub active_peers: Value,
    pub ws_connections: Value,
    pub own_ip: Value,
    pub uptime_seconds: Value,
    pub global_peers: Option<Value>,
    pub obfuscation: Option<Value>,
}

impl LivenessFacts {
    pub fn read(reported: &Value) -> Self {
        LivenessFacts {
            instance_id: field(reported, "instance_id"),
            crypto_backend: field(reported, "crypto_backend"),
            key_exchange: field(reported, "key_exchange"),
            post_quantum: field(reported, "post_quantum"),
            database: field(reported, "database"),
            redis: field(reported, "redis"),
            scaling: field(reported, "scaling"),
            active_peers: field(reported, "active_peers"),
            ws_connections: field(reported, "ws_connections"),
            own_ip: field(reported, "own_ip"),
            uptime_seconds: field(reported, "uptime_seconds"),
            global_peers: reported.get("global_peers").cloned(),
            obfuscation: reported.get("obfuscation").cloned(),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ReadinessFacts {
    pub status: u16,
    pub database: Value,
    pub background_tasks: Value,
}

impl ReadinessFacts {
    pub fn read(status: u16, reported: &Value) -> Self {
        ReadinessFacts {
            status,
            database: field(reported, "database"),
            background_tasks: field(reported, "background_tasks"),
        }
    }
}

fn field(reported: &Value, name: &str) -> Value {
    match reported.get(name) {
        Some(value) => value.clone(),
        None => {
            tracing::warn!("Python не вернул поле {name} — в ответе будет null");
            Value::Null
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{LivenessFacts, ReadinessFacts};

    #[test]
    fn every_field_is_carried_verbatim_from_the_python_answer() {
        let reported = json!({
            "instance_id": "worker-1",
            "crypto_backend": "rust",
            "key_exchange": "X25519+Kyber768+HKDF-SHA256",
            "post_quantum": "liboqs",
            "database": "sqlite",
            "redis": "connected",
            "scaling": "horizontal",
            "active_peers": 3,
            "ws_connections": 7,
            "own_ip": "10.0.0.2",
            "uptime_seconds": 12.5
        });
        let facts = LivenessFacts::read(&reported);
        assert_eq!(facts.active_peers, json!(3));
        assert_eq!(facts.uptime_seconds, json!(12.5));
        assert_eq!(facts.global_peers, None);
    }

    #[test]
    fn the_wide_area_fields_appear_only_when_python_reports_them() {
        let facts = LivenessFacts::read(&json!({"global_peers": 5, "obfuscation": true}));
        assert_eq!(facts.global_peers, Some(json!(5)));
        assert_eq!(facts.obfuscation, Some(json!(true)));
    }

    #[test]
    fn a_missing_field_becomes_null_rather_than_a_refusal() {
        let facts = ReadinessFacts::read(503, &json!({"database": "ok"}));
        assert_eq!(facts.status, 503);
        assert!(facts.background_tasks.is_null());
    }
}

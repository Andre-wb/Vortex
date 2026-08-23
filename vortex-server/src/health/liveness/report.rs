use serde::Serialize;
use serde_json::Value;

use crate::health::facts::LivenessFacts;
use crate::settings::node::{
    NodeFacts, AUTHENTICATION, ENCRYPTION, FEDERATION, PASSWORD_HASH, VERSION,
};

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct LivenessReport {
    pub status: &'static str,
    pub version: &'static str,
    pub instance_id: Value,
    pub crypto_backend: Value,
    pub key_exchange: Value,
    pub post_quantum: Value,
    pub encryption: &'static str,
    pub password_hash: &'static str,
    pub authentication: &'static str,
    pub federation: &'static str,
    pub database: Value,
    pub redis: Value,
    pub scaling: Value,
    pub network_mode: String,
    pub active_peers: Value,
    pub ws_connections: Value,
    pub own_ip: Value,
    pub uptime_seconds: Value,
    pub ephemeral: bool,
    pub metadata_padding: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub global_peers: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub obfuscation: Option<Value>,
}

impl LivenessReport {
    pub fn compose(node: &NodeFacts, facts: LivenessFacts) -> Self {
        let global = node.global();
        LivenessReport {
            status: "ok",
            version: VERSION,
            instance_id: facts.instance_id,
            crypto_backend: facts.crypto_backend,
            key_exchange: facts.key_exchange,
            post_quantum: facts.post_quantum,
            encryption: ENCRYPTION,
            password_hash: PASSWORD_HASH,
            authentication: AUTHENTICATION,
            federation: FEDERATION,
            database: facts.database,
            redis: facts.redis,
            scaling: facts.scaling,
            network_mode: node.network_mode().to_string(),
            active_peers: facts.active_peers,
            ws_connections: facts.ws_connections,
            own_ip: facts.own_ip,
            uptime_seconds: facts.uptime_seconds,
            ephemeral: node.ephemeral(),
            metadata_padding: node.metadata_padding(),
            global_peers: if global { facts.global_peers } else { None },
            obfuscation: if global { facts.obfuscation } else { None },
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::LivenessReport;
    use crate::health::facts::LivenessFacts;
    use crate::settings::node::NodeFacts;

    fn facts() -> LivenessFacts {
        LivenessFacts::read(&json!({
            "instance_id": "single",
            "crypto_backend": "rust",
            "key_exchange": "X25519+HKDF-SHA256",
            "post_quantum": "none",
            "database": "sqlite",
            "redis": "disabled",
            "scaling": "single-node",
            "active_peers": 0,
            "ws_connections": 0,
            "own_ip": "127.0.0.1",
            "uptime_seconds": 1.0,
            "global_peers": 4,
            "obfuscation": true
        }))
    }

    #[test]
    fn the_key_order_matches_the_python_answer() {
        let report = LivenessReport::compose(&NodeFacts::default(), facts());
        let rendered = serde_json::to_string(&report).unwrap();
        let order: Vec<&str> = rendered
            .split("\":")
            .filter_map(|chunk| chunk.rsplit('"').next())
            .collect();
        assert_eq!(order[0], "status");
        assert_eq!(order[1], "version");
        assert_eq!(order[2], "instance_id");
        assert_eq!(order[6], "encryption");
        assert_eq!(order[10], "database");
    }

    #[test]
    fn a_local_node_never_reports_the_wide_area_fields() {
        let report = LivenessReport::compose(&NodeFacts::default(), facts());
        let rendered = serde_json::to_string(&report).unwrap();
        assert!(!rendered.contains("global_peers"));
        assert!(!rendered.contains("obfuscation"));
    }

    #[test]
    fn a_global_node_reports_them_verbatim() {
        let node = NodeFacts::new("global", false, true);
        let report = LivenessReport::compose(&node, facts());
        assert_eq!(report.global_peers, Some(json!(4)));
        assert_eq!(report.obfuscation, Some(json!(true)));
    }
}

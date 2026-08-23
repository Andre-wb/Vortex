use serde::Serialize;

use crate::settings::node::{
    NodeFacts, AUTHENTICATION, ENCRYPTION, FEDERATION, PASSWORD_HASH, VERSION,
};

pub const STATUS: &str = "degraded";
pub const UPSTREAM: &str = "unreachable";

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DegradedReport {
    pub status: &'static str,
    pub version: &'static str,
    pub upstream: &'static str,
    pub encryption: &'static str,
    pub password_hash: &'static str,
    pub authentication: &'static str,
    pub federation: &'static str,
    pub network_mode: String,
    pub ephemeral: bool,
    pub metadata_padding: bool,
}

impl DegradedReport {
    pub fn compose(node: &NodeFacts) -> Self {
        DegradedReport {
            status: STATUS,
            version: VERSION,
            upstream: UPSTREAM,
            encryption: ENCRYPTION,
            password_hash: PASSWORD_HASH,
            authentication: AUTHENTICATION,
            federation: FEDERATION,
            network_mode: node.network_mode().to_string(),
            ephemeral: node.ephemeral(),
            metadata_padding: node.metadata_padding(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{DegradedReport, STATUS, UPSTREAM};
    use crate::settings::node::NodeFacts;

    #[test]
    fn the_degraded_answer_names_the_half_that_did_not_answer() {
        let report = DegradedReport::compose(&NodeFacts::default());
        assert_eq!(report.status, STATUS);
        assert_eq!(report.upstream, UPSTREAM);
    }

    #[test]
    fn no_field_of_the_degraded_answer_comes_from_python() {
        let rendered = serde_json::to_string(&DegradedReport::compose(&NodeFacts::default()))
            .expect("отчёт сериализуется");
        for absent in [
            "instance_id",
            "database",
            "ws_connections",
            "uptime_seconds",
        ] {
            assert!(!rendered.contains(absent), "{absent}");
        }
    }
}

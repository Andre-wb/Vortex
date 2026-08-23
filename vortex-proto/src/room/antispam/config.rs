use crate::room::antispam::action::AntispamAction;
use crate::room::antispam::threshold::Threshold;
use serde_json::Value;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AntispamConfig {
    pub threshold: Option<Threshold>,
    pub action: Option<AntispamAction>,
    pub block_repeats: Option<bool>,
    pub block_links: Option<bool>,
}

impl AntispamConfig {
    pub fn read(payload: &str) -> Option<Self> {
        let Ok(Value::Object(fields)) = serde_json::from_str::<Value>(payload) else {
            return None;
        };
        Some(AntispamConfig {
            threshold: fields
                .get("threshold")
                .and_then(Value::as_i64)
                .and_then(Threshold::read),
            action: fields
                .get("action")
                .and_then(Value::as_str)
                .and_then(AntispamAction::read),
            block_repeats: fields.get("block_repeats").map(truthy),
            block_links: fields.get("block_links").map(truthy),
        })
    }

    pub fn written(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        if let Some(threshold) = self.threshold {
            parts.push(format!("\"threshold\":{}", threshold.value()));
        }
        if let Some(action) = self.action {
            parts.push(format!("\"action\":\"{}\"", action.as_str()));
        }
        if let Some(block_repeats) = self.block_repeats {
            parts.push(format!("\"block_repeats\":{block_repeats}"));
        }
        if let Some(block_links) = self.block_links {
            parts.push(format!("\"block_links\":{block_links}"));
        }
        format!("{{{}}}", parts.join(","))
    }
}

fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(flag) => *flag,
        Value::Number(number) => number.as_f64().map(|value| value != 0.0).unwrap_or(true),
        Value::String(text) => !text.is_empty(),
        Value::Array(entries) => !entries.is_empty(),
        Value::Object(fields) => !fields.is_empty(),
    }
}

#[cfg(test)]
mod tests {
    use super::AntispamConfig;

    #[test]
    fn a_full_configuration_keeps_every_known_key_in_order() {
        let config = AntispamConfig::read(
            r#"{"block_links":false,"action":"mute","threshold":10,"block_repeats":true}"#,
        )
        .unwrap();
        assert_eq!(
            config.written(),
            r#"{"threshold":10,"action":"mute","block_repeats":true,"block_links":false}"#
        );
    }

    #[test]
    fn an_unknown_key_never_reaches_the_stored_configuration() {
        let config = AntispamConfig::read(r#"{"threshold":5,"nuke_everything":true}"#).unwrap();
        assert_eq!(config.written(), r#"{"threshold":5}"#);
    }

    #[test]
    fn a_value_that_was_never_offered_is_dropped_and_the_rest_survive() {
        let config =
            AntispamConfig::read(r#"{"threshold":7,"action":"delete","block_links":1}"#).unwrap();
        assert_eq!(config.written(), r#"{"block_links":true}"#);
    }

    #[test]
    fn a_flag_is_read_the_way_a_condition_reads_it() {
        let config = AntispamConfig::read(r#"{"block_repeats":"","block_links":"yes"}"#).unwrap();
        assert_eq!(
            config.written(),
            r#"{"block_repeats":false,"block_links":true}"#
        );
    }

    #[test]
    fn anything_that_is_not_an_object_is_not_a_configuration() {
        assert_eq!(AntispamConfig::read("[]"), None);
        assert_eq!(AntispamConfig::read("5"), None);
        assert_eq!(AntispamConfig::read("not json"), None);
        assert_eq!(AntispamConfig::read(""), None);
    }

    #[test]
    fn an_empty_object_is_a_configuration_that_says_nothing() {
        assert_eq!(AntispamConfig::read("{}").unwrap().written(), "{}");
    }
}

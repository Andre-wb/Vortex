use serde::Deserialize;

#[derive(Clone, Debug, Default, Deserialize)]
pub struct RoomPatchRequest {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub avatar_emoji: Option<String>,
    #[serde(default)]
    pub is_private: Option<bool>,
    #[serde(default)]
    pub auto_delete_seconds: Option<i64>,
    #[serde(default)]
    pub slow_mode_seconds: Option<i64>,
    #[serde(default)]
    pub antispam_enabled: Option<bool>,
    #[serde(default)]
    pub antispam_config: Option<String>,
    #[serde(default)]
    pub discussion_enabled: Option<bool>,
    #[serde(default)]
    pub reactions_type: Option<String>,
    #[serde(default)]
    pub allowed_reactions: Option<String>,
    #[serde(default)]
    pub admin_signatures: Option<bool>,
    #[serde(default)]
    pub copy_protection: Option<bool>,
    #[serde(default)]
    pub silent_default: Option<bool>,
    #[serde(default)]
    pub join_approval: Option<bool>,
    #[serde(default)]
    pub hashtags_enabled: Option<bool>,
}

impl RoomPatchRequest {
    pub fn from_json(payload: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(payload)
    }
}

#[cfg(test)]
mod tests {
    use super::RoomPatchRequest;

    #[test]
    fn an_empty_body_changes_nothing() {
        let request = RoomPatchRequest::from_json("{}").unwrap();
        assert_eq!(request.name, None);
        assert_eq!(request.slow_mode_seconds, None);
        assert_eq!(request.hashtags_enabled, None);
    }

    #[test]
    fn only_the_named_fields_are_read() {
        let request =
            RoomPatchRequest::from_json(r#"{"name":"General","unknown":1,"is_private":true}"#)
                .unwrap();
        assert_eq!(request.name.as_deref(), Some("General"));
        assert_eq!(request.is_private, Some(true));
    }

    #[test]
    fn a_null_is_the_same_as_an_absent_field() {
        let request = RoomPatchRequest::from_json(r#"{"name":null}"#).unwrap();
        assert_eq!(request.name, None);
    }
}

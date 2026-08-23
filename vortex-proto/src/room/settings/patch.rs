use crate::room::antispam::config::AntispamConfig;
use crate::room::avatar::RoomAvatar;
use crate::room::description::RoomDescription;
use crate::room::name::RoomName;
use crate::room::reactions::allowed::AllowedReactions;
use crate::room::reactions::kind::ReactionsType;
use crate::room::refusal::RoomRefusal;
use crate::room::seconds::{AutoDelete, SlowMode};
use crate::room::settings::request::RoomPatchRequest;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RoomPatch {
    pub name: Option<RoomName>,
    pub description: Option<RoomDescription>,
    pub avatar_emoji: Option<RoomAvatar>,
    pub is_private: Option<bool>,
    pub auto_delete: Option<AutoDelete>,
    pub slow_mode: Option<SlowMode>,
    pub antispam_enabled: Option<bool>,
    pub antispam_config: Option<AntispamConfig>,
    pub antispam_config_refused: bool,
    pub discussion_enabled: Option<bool>,
    pub reactions_type: Option<ReactionsType>,
    pub allowed_reactions: Option<AllowedReactions>,
    pub admin_signatures: Option<bool>,
    pub copy_protection: Option<bool>,
    pub silent_default: Option<bool>,
    pub join_approval: Option<bool>,
    pub hashtags_enabled: Option<bool>,
}

impl RoomPatch {
    pub fn read(request: &RoomPatchRequest) -> Result<Self, RoomRefusal> {
        let antispam_config = request.antispam_config.as_deref().map(AntispamConfig::read);
        Ok(RoomPatch {
            name: request.name.as_deref().map(RoomName::read).transpose()?,
            description: request
                .description
                .as_deref()
                .map(RoomDescription::read)
                .transpose()?,
            avatar_emoji: request
                .avatar_emoji
                .as_deref()
                .map(RoomAvatar::read)
                .transpose()?,
            is_private: request.is_private,
            auto_delete: request.auto_delete_seconds.map(AutoDelete::read),
            slow_mode: request.slow_mode_seconds.map(SlowMode::read),
            antispam_enabled: request.antispam_enabled,
            antispam_config: antispam_config.flatten(),
            antispam_config_refused: matches!(antispam_config, Some(None)),
            discussion_enabled: request.discussion_enabled,
            reactions_type: request
                .reactions_type
                .as_deref()
                .map(ReactionsType::read)
                .transpose()?,
            allowed_reactions: request
                .allowed_reactions
                .as_deref()
                .map(AllowedReactions::read)
                .transpose()?,
            admin_signatures: request.admin_signatures,
            copy_protection: request.copy_protection,
            silent_default: request.silent_default,
            join_approval: request.join_approval,
            hashtags_enabled: request.hashtags_enabled,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::RoomPatch;
    use crate::room::refusal::RoomRefusal;
    use crate::room::settings::request::RoomPatchRequest;

    fn patch(payload: &str) -> Result<RoomPatch, RoomRefusal> {
        RoomPatch::read(&RoomPatchRequest::from_json(payload).unwrap())
    }

    #[test]
    fn an_empty_patch_changes_nothing() {
        let parsed = patch("{}").unwrap();
        assert_eq!(parsed, RoomPatch::default());
    }

    #[test]
    fn a_name_arrives_without_its_surrounding_whitespace() {
        let parsed = patch(r#"{"name":"  General "}"#).unwrap();
        assert_eq!(parsed.name.unwrap().as_str(), "General");
    }

    #[test]
    fn a_name_of_the_wrong_size_refuses_the_whole_patch() {
        assert_eq!(patch(r#"{"name":"   "}"#), Err(RoomRefusal::Name));
        assert_eq!(
            patch(&format!(r#"{{"name":"{}"}}"#, "a".repeat(101))),
            Err(RoomRefusal::Name)
        );
    }

    #[test]
    fn switching_auto_delete_off_is_told_apart_from_leaving_it_alone() {
        assert_eq!(patch("{}").unwrap().auto_delete, None);
        assert_eq!(
            patch(r#"{"auto_delete_seconds":0}"#)
                .unwrap()
                .auto_delete
                .unwrap()
                .seconds(),
            None
        );
        assert_eq!(
            patch(r#"{"auto_delete_seconds":30}"#)
                .unwrap()
                .auto_delete
                .unwrap()
                .seconds(),
            Some(30)
        );
    }

    #[test]
    fn a_negative_slow_mode_arrives_as_no_slow_mode() {
        assert_eq!(
            patch(r#"{"slow_mode_seconds":-5}"#)
                .unwrap()
                .slow_mode
                .unwrap()
                .seconds(),
            0
        );
    }

    #[test]
    fn an_antispam_configuration_is_sanitised_on_the_way_in() {
        let parsed = patch(r#"{"antispam_config":"{\"threshold\":10,\"evil\":1}"}"#).unwrap();
        assert_eq!(
            parsed.antispam_config.unwrap().written(),
            r#"{"threshold":10}"#
        );
        assert!(!parsed.antispam_config_refused);
    }

    #[test]
    fn an_unreadable_antispam_configuration_leaves_the_previous_one_alone() {
        let parsed = patch(r#"{"antispam_config":"not json"}"#).unwrap();
        assert_eq!(parsed.antispam_config, None);
        assert!(parsed.antispam_config_refused);
    }

    #[test]
    fn a_reactions_setting_that_was_never_offered_refuses_the_patch() {
        assert_eq!(
            patch(r#"{"reactions_type":"some"}"#),
            Err(RoomRefusal::ReactionsType)
        );
    }

    #[test]
    fn every_flag_is_carried_through_untouched() {
        let parsed = patch(
            r#"{"is_private":true,"antispam_enabled":false,"discussion_enabled":true,
                "admin_signatures":true,"copy_protection":false,"silent_default":true,
                "join_approval":false,"hashtags_enabled":false}"#,
        )
        .unwrap();
        assert_eq!(parsed.is_private, Some(true));
        assert_eq!(parsed.antispam_enabled, Some(false));
        assert_eq!(parsed.discussion_enabled, Some(true));
        assert_eq!(parsed.admin_signatures, Some(true));
        assert_eq!(parsed.copy_protection, Some(false));
        assert_eq!(parsed.silent_default, Some(true));
        assert_eq!(parsed.join_approval, Some(false));
        assert_eq!(parsed.hashtags_enabled, Some(false));
    }
}

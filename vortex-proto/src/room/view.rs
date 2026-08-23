use crate::message::time::stored_stamp::stored_stamp;
use crate::room::avatar::RoomAvatar;
use crate::room::reactions::allowed::AllowedReactions;
use crate::room::reactions::kind::ReactionsType;
use crate::room::replication::ReplicationMode;
use crate::room::seconds::SlowMode;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoomView {
    pub id: i64,
    pub name: String,
    pub description: String,
    pub is_private: bool,
    pub is_channel: bool,
    pub is_voice: bool,
    pub invite_code: Option<String>,
    pub member_count: i64,
    pub online_count: i64,
    pub avatar_emoji: String,
    pub avatar_url: Option<String>,
    pub auto_delete_seconds: Option<i64>,
    pub slow_mode_seconds: i64,
    pub antispam_enabled: bool,
    pub antispam_config: String,
    pub creator_id: Option<i64>,
    pub created_at: String,
    pub theme_json: Option<String>,
    pub discussion_enabled: bool,
    pub reactions_type: String,
    pub allowed_reactions: String,
    pub admin_signatures: bool,
    pub copy_protection: bool,
    pub silent_default: bool,
    pub join_approval: bool,
    pub hashtags_enabled: bool,
    pub replication_mode: String,
    pub is_dm: bool,
}

pub struct RoomRow<'a> {
    pub id: i64,
    pub name: &'a str,
    pub description: Option<&'a str>,
    pub is_private: Option<bool>,
    pub is_channel: Option<bool>,
    pub is_voice: Option<bool>,
    pub invite_code: Option<&'a str>,
    pub member_count: i64,
    pub online_count: i64,
    pub avatar_emoji: Option<&'a str>,
    pub avatar_url: Option<&'a str>,
    pub auto_delete_seconds: Option<i64>,
    pub slow_mode_seconds: Option<i64>,
    pub antispam_enabled: Option<bool>,
    pub antispam_config: Option<&'a str>,
    pub creator_id: Option<i64>,
    pub created_at: (i64, u32),
    pub theme_json: Option<&'a str>,
    pub discussion_enabled: Option<bool>,
    pub reactions_type: Option<&'a str>,
    pub allowed_reactions: Option<&'a str>,
    pub admin_signatures: Option<bool>,
    pub copy_protection: Option<bool>,
    pub silent_default: Option<bool>,
    pub join_approval: Option<bool>,
    pub hashtags_enabled: Option<bool>,
    pub replication_mode: Option<&'a str>,
    pub is_dm: Option<bool>,
}

impl RoomView {
    pub fn render(row: RoomRow<'_>) -> Self {
        RoomView {
            id: row.id,
            name: row.name.to_string(),
            description: row.description.unwrap_or("").to_string(),
            is_private: row.is_private.unwrap_or(false),
            is_channel: row.is_channel.unwrap_or(false),
            is_voice: row.is_voice.unwrap_or(false),
            invite_code: row.invite_code.map(str::to_string),
            member_count: row.member_count,
            online_count: row.online_count,
            avatar_emoji: RoomAvatar::shown(row.avatar_emoji),
            avatar_url: row.avatar_url.map(str::to_string),
            auto_delete_seconds: row.auto_delete_seconds,
            slow_mode_seconds: SlowMode::shown(row.slow_mode_seconds),
            antispam_enabled: row.antispam_enabled.unwrap_or(true),
            antispam_config: shown_config(row.antispam_config),
            creator_id: row.creator_id,
            created_at: stored_stamp(row.created_at.0, row.created_at.1),
            theme_json: row.theme_json.map(str::to_string),
            discussion_enabled: row.discussion_enabled.unwrap_or(false),
            reactions_type: ReactionsType::shown(row.reactions_type),
            allowed_reactions: AllowedReactions::shown(row.allowed_reactions),
            admin_signatures: row.admin_signatures.unwrap_or(false),
            copy_protection: row.copy_protection.unwrap_or(false),
            silent_default: row.silent_default.unwrap_or(false),
            join_approval: row.join_approval.unwrap_or(false),
            hashtags_enabled: row.hashtags_enabled.unwrap_or(true),
            replication_mode: ReplicationMode::shown(row.replication_mode),
            is_dm: row.is_dm.unwrap_or(false),
        }
    }

    pub fn shows_voice_participants(&self) -> bool {
        self.is_voice
    }
}

fn shown_config(stored: Option<&str>) -> String {
    stored
        .filter(|value| !value.is_empty())
        .unwrap_or("{}")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::{RoomRow, RoomView};
    use crate::room::limits::DEFAULT_AVATAR;

    fn row<'a>() -> RoomRow<'a> {
        RoomRow {
            id: 7,
            name: "General",
            description: None,
            is_private: None,
            is_channel: None,
            is_voice: None,
            invite_code: Some("abcd1234"),
            member_count: 3,
            online_count: 1,
            avatar_emoji: None,
            avatar_url: None,
            auto_delete_seconds: None,
            slow_mode_seconds: None,
            antispam_enabled: None,
            antispam_config: None,
            creator_id: Some(2),
            created_at: (1_785_834_930, 0),
            theme_json: None,
            discussion_enabled: None,
            reactions_type: None,
            allowed_reactions: None,
            admin_signatures: None,
            copy_protection: None,
            silent_default: None,
            join_approval: None,
            hashtags_enabled: None,
            replication_mode: None,
            is_dm: None,
        }
    }

    #[test]
    fn a_room_that_set_nothing_is_shown_with_every_default() {
        let view = RoomView::render(row());
        assert_eq!(view.description, "");
        assert!(!view.is_private);
        assert_eq!(view.avatar_emoji, DEFAULT_AVATAR);
        assert_eq!(view.slow_mode_seconds, 0);
        assert!(view.antispam_enabled);
        assert_eq!(view.antispam_config, "{}");
        assert_eq!(view.reactions_type, "all");
        assert_eq!(view.allowed_reactions, "");
        assert!(view.hashtags_enabled);
        assert_eq!(view.replication_mode, "none");
        assert!(!view.is_dm);
    }

    #[test]
    fn the_flags_that_default_to_yes_are_told_apart_from_the_rest() {
        let view = RoomView::render(RoomRow {
            antispam_enabled: Some(false),
            hashtags_enabled: Some(false),
            ..row()
        });
        assert!(!view.antispam_enabled);
        assert!(!view.hashtags_enabled);
    }

    #[test]
    fn a_room_is_stamped_the_way_stored_rows_are_stamped() {
        let view = RoomView::render(RoomRow {
            created_at: (1_785_834_930, 789_012),
            ..row()
        });
        assert_eq!(view.created_at, "2026-08-04T09:15:30.789012");
    }

    #[test]
    fn only_a_voice_room_shows_who_is_in_the_call() {
        assert!(!RoomView::render(row()).shows_voice_participants());
        assert!(RoomView::render(RoomRow {
            is_voice: Some(true),
            ..row()
        })
        .shows_voice_participants());
    }
}

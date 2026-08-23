use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use vortex_auth::account::user_id::UserId;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Participant {
    pub user_id: i64,
    pub username: String,
    pub display_name: String,
    pub avatar_emoji: String,
    pub avatar_url: Option<String>,
    pub joined_at: String,
    pub is_muted: bool,
    pub is_video: bool,
}

impl Participant {
    pub fn user(&self) -> Option<UserId> {
        UserId::of(self.user_id)
    }

    pub fn view(&self) -> Value {
        json!({
            "user_id": self.user_id,
            "username": self.username,
            "display_name": self.display_name,
            "avatar_emoji": self.avatar_emoji,
            "avatar_url": self.avatar_url,
            "joined_at": self.joined_at,
            "is_muted": self.is_muted,
            "is_video": self.is_video,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::Participant;
    use serde_json::json;

    pub fn sample() -> Participant {
        Participant {
            user_id: 7,
            username: "ann".to_owned(),
            display_name: "Ann".to_owned(),
            avatar_emoji: "\u{1f464}".to_owned(),
            avatar_url: None,
            joined_at: "2026-08-04T09:15:30+00:00".to_owned(),
            is_muted: false,
            is_video: false,
        }
    }

    #[test]
    fn a_participant_is_seen_by_the_room_exactly_as_it_is_kept() {
        assert_eq!(
            sample().view(),
            json!({
                "user_id": 7,
                "username": "ann",
                "display_name": "Ann",
                "avatar_emoji": "\u{1f464}",
                "avatar_url": null,
                "joined_at": "2026-08-04T09:15:30+00:00",
                "is_muted": false,
                "is_video": false,
            })
        );
    }

    #[test]
    fn a_participant_names_the_account_it_belongs_to() {
        assert_eq!(sample().user().unwrap().value(), 7);
    }
}

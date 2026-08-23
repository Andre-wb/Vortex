use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::call::membership::MemberState;
use crate::identity::person::Person;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallParticipant {
    #[serde(flatten)]
    pub person: Person,
    pub state: MemberState,
    pub joined_at: Option<String>,
    pub is_muted: bool,
    pub is_video: bool,
    pub is_screen_sharing: bool,
}

impl CallParticipant {
    pub fn invited(person: Person) -> Self {
        CallParticipant {
            person,
            state: MemberState::Invited,
            joined_at: None,
            is_muted: false,
            is_video: false,
            is_screen_sharing: false,
        }
    }

    pub fn connecting(person: Person, joined_at: String) -> Self {
        CallParticipant {
            person,
            state: MemberState::Connecting,
            joined_at: Some(joined_at),
            is_muted: false,
            is_video: false,
            is_screen_sharing: false,
        }
    }

    pub fn joining(&self, joined_at: String) -> Self {
        CallParticipant {
            person: self.person.clone(),
            state: MemberState::Connecting,
            joined_at: Some(joined_at),
            is_muted: self.is_muted,
            is_video: self.is_video,
            is_screen_sharing: self.is_screen_sharing,
        }
    }

    pub fn in_state(&self, state: MemberState) -> Self {
        CallParticipant {
            person: self.person.clone(),
            state,
            joined_at: self.joined_at.clone(),
            is_muted: self.is_muted,
            is_video: self.is_video,
            is_screen_sharing: self.is_screen_sharing,
        }
    }

    pub fn view(&self) -> Value {
        json!({
            "user_id": self.person.user_id,
            "username": self.person.username,
            "display_name": self.person.display_name,
            "avatar_emoji": self.person.avatar_emoji,
            "avatar_url": self.person.avatar_url,
            "state": self.state.as_str(),
            "joined_at": self.joined_at,
            "is_muted": self.is_muted,
            "is_video": self.is_video,
            "is_screen_sharing": self.is_screen_sharing,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::CallParticipant;
    use crate::call::membership::MemberState;
    use crate::identity::person::Person;
    use serde_json::json;

    fn ann() -> Person {
        Person::of(7, "ann", Some("Ann"), None, None)
    }

    #[test]
    fn an_invited_participant_has_not_joined_yet() {
        let participant = CallParticipant::invited(ann());
        assert_eq!(participant.state, MemberState::Invited);
        assert_eq!(participant.joined_at, None);
    }

    #[test]
    fn joining_records_the_moment_and_keeps_the_flags() {
        let participant =
            CallParticipant::invited(ann()).joining("2026-08-04T09:15:30+00:00".to_owned());
        assert_eq!(participant.state, MemberState::Connecting);
        assert_eq!(
            participant.joined_at.as_deref(),
            Some("2026-08-04T09:15:30+00:00")
        );
    }

    #[test]
    fn a_participant_is_shown_to_the_room_with_the_state_it_is_in() {
        let participant =
            CallParticipant::connecting(ann(), "2026-08-04T09:15:30+00:00".to_owned());
        assert_eq!(
            participant.view(),
            json!({
                "user_id": 7,
                "username": "ann",
                "display_name": "Ann",
                "avatar_emoji": "\u{1f464}",
                "avatar_url": null,
                "state": "connecting",
                "joined_at": "2026-08-04T09:15:30+00:00",
                "is_muted": false,
                "is_video": false,
                "is_screen_sharing": false,
            })
        );
    }

    #[test]
    fn a_participant_survives_the_trip_through_the_store() {
        let participant = CallParticipant::invited(ann());
        let wire = serde_json::to_string(&participant).unwrap();
        assert_eq!(
            serde_json::from_str::<CallParticipant>(&wire).unwrap(),
            participant
        );
    }
}

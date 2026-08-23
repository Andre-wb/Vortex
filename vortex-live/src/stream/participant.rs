use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::identity::person::Person;
use crate::stream::permissions::Permissions;
use crate::stream::role::StreamRole;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamParticipant {
    #[serde(flatten)]
    pub person: Person,
    pub role: StreamRole,
    pub allowed: Permissions,
    pub is_muted: bool,
    pub is_video_on: bool,
    pub is_screen_sharing: bool,
    pub hand_raised: bool,
    pub joined_at: String,
}

impl StreamParticipant {
    pub fn joining(person: Person, role: StreamRole, joined_at: String) -> Self {
        StreamParticipant {
            person,
            role,
            allowed: Permissions::of(role),
            is_muted: role == StreamRole::Viewer,
            is_video_on: false,
            is_screen_sharing: false,
            hand_raised: false,
            joined_at,
        }
    }

    pub fn in_role(&self, role: StreamRole) -> Self {
        let mut changed = self.clone();
        changed.role = role;
        changed.allowed = Permissions::of(role);
        if role == StreamRole::Viewer {
            changed.is_muted = true;
            changed.is_video_on = false;
        }
        changed
    }

    pub fn granted(&self, allowed: Permissions) -> Self {
        let mut changed = self.clone();
        changed.allowed = allowed;
        if !allowed.can_speak {
            changed.is_muted = true;
        }
        if !allowed.can_video {
            changed.is_video_on = false;
        }
        changed
    }

    pub fn with_hand(&self, raised: bool) -> Self {
        let mut changed = self.clone();
        changed.hand_raised = raised;
        changed
    }

    pub fn promoted_to_speaker(&self) -> Self {
        let mut changed = self.in_role(StreamRole::Speaker);
        changed.hand_raised = false;
        changed.is_muted = self.is_muted;
        changed
    }

    pub fn muted(&self, is_muted: Option<bool>, is_video_on: Option<bool>) -> Self {
        let mut changed = self.clone();
        if let Some(value) = is_muted {
            if self.allowed.can_speak || value {
                changed.is_muted = value;
            }
        }
        if let Some(value) = is_video_on {
            if self.allowed.can_video {
                changed.is_video_on = value;
            }
        }
        changed
    }

    pub fn sharing(&self, is_sharing: bool) -> Self {
        let mut changed = self.clone();
        changed.is_screen_sharing = is_sharing;
        changed
    }

    pub fn to_wire(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }

    pub fn parse(wire: &str) -> Option<Self> {
        serde_json::from_str(wire).ok()
    }

    pub fn view(&self) -> Value {
        json!({
            "user_id": self.person.user_id,
            "username": self.person.username,
            "display_name": self.person.display_name,
            "avatar_emoji": self.person.avatar_emoji,
            "avatar_url": self.person.avatar_url,
            "role": self.role.as_str(),
            "can_speak": self.allowed.can_speak,
            "can_video": self.allowed.can_video,
            "can_screen_share": self.allowed.can_screen_share,
            "is_muted": self.is_muted,
            "is_video_on": self.is_video_on,
            "is_screen_sharing": self.is_screen_sharing,
            "hand_raised": self.hand_raised,
            "joined_at": self.joined_at,
        })
    }
}

#[cfg(test)]
pub mod tests {
    use super::StreamParticipant;
    use crate::identity::person::Person;
    use crate::stream::permissions::Permissions;
    use crate::stream::role::StreamRole;

    pub fn viewer() -> StreamParticipant {
        StreamParticipant::joining(
            Person::of(8, "bob", None, None, None),
            StreamRole::Viewer,
            "2026-08-04T09:15:30+00:00".to_owned(),
        )
    }

    pub fn host() -> StreamParticipant {
        StreamParticipant::joining(
            Person::of(7, "ann", Some("Ann"), None, None),
            StreamRole::Host,
            "2026-08-04T09:15:30+00:00".to_owned(),
        )
    }

    #[test]
    fn a_viewer_joins_muted_and_a_host_does_not() {
        assert!(viewer().is_muted);
        assert!(!host().is_muted);
    }

    #[test]
    fn a_promoted_viewer_may_speak_and_lowers_the_hand() {
        let promoted = viewer().with_hand(true).promoted_to_speaker();
        assert_eq!(promoted.role, StreamRole::Speaker);
        assert!(promoted.allowed.can_speak);
        assert!(!promoted.hand_raised);
    }

    #[test]
    fn a_demoted_participant_is_muted_and_its_video_goes_off() {
        let demoted = host()
            .muted(Some(false), Some(true))
            .in_role(StreamRole::Viewer);
        assert!(demoted.is_muted);
        assert!(!demoted.is_video_on);
        assert!(!demoted.allowed.can_speak);
    }

    #[test]
    fn a_viewer_may_mute_itself_but_never_unmute_itself() {
        assert!(viewer().muted(Some(true), None).is_muted);
        assert!(viewer().muted(Some(false), None).is_muted);
    }

    #[test]
    fn a_speaker_turns_its_own_microphone_back_on() {
        let speaker = viewer().promoted_to_speaker();
        assert!(!speaker.muted(Some(false), None).is_muted);
    }

    #[test]
    fn video_stays_off_for_whoever_may_not_show_it() {
        assert!(!viewer().muted(None, Some(true)).is_video_on);
        assert!(host().muted(None, Some(true)).is_video_on);
    }

    #[test]
    fn taking_away_the_right_to_speak_mutes_the_participant() {
        let silenced = host().granted(Permissions {
            can_speak: false,
            can_video: false,
            can_screen_share: false,
        });
        assert!(silenced.is_muted);
        assert!(!silenced.is_video_on);
    }

    #[test]
    fn a_participant_survives_the_trip_through_the_store() {
        assert_eq!(StreamParticipant::parse(&host().to_wire()).unwrap(), host());
        assert!(StreamParticipant::parse("").is_none());
        assert!(StreamParticipant::parse("{\"role\": \"host\"}").is_none());
    }

    #[test]
    fn the_stream_shows_a_participant_with_everything_the_client_draws() {
        let view = host().view();
        assert_eq!(view["user_id"], 7);
        assert_eq!(view["role"], "host");
        assert_eq!(view["can_screen_share"], true);
        assert_eq!(view["hand_raised"], false);
        assert_eq!(view["joined_at"], "2026-08-04T09:15:30+00:00");
    }
}

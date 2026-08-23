use serde::{Deserialize, Serialize};

use crate::voice::participant::Participant;
use crate::voice::patch::MutePatch;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Presence {
    pub participant: Participant,
    pub until: f64,
}

impl Presence {
    pub fn new(participant: Participant, until: f64) -> Self {
        Presence { participant, until }
    }

    pub fn alive_at(&self, now: f64) -> bool {
        self.until > now
    }

    pub fn renewed(&self, until: f64) -> Self {
        Presence {
            participant: self.participant.clone(),
            until,
        }
    }

    pub fn amended(&self, patch: MutePatch, until: f64) -> Self {
        let mut participant = self.participant.clone();
        participant.is_muted = patch.muted_after(participant.is_muted);
        participant.is_video = patch.video_after(participant.is_video);
        Presence { participant, until }
    }

    pub fn to_wire(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }

    pub fn parse(wire: &str) -> Option<Self> {
        serde_json::from_str(wire).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::Presence;
    use crate::voice::participant::Participant;
    use crate::voice::patch::MutePatch;

    fn participant() -> Participant {
        Participant {
            user_id: 7,
            username: "ann".to_owned(),
            display_name: "Ann".to_owned(),
            avatar_emoji: "\u{1f464}".to_owned(),
            avatar_url: Some("https://example.invalid/a.png".to_owned()),
            joined_at: "2026-08-04T09:15:30+00:00".to_owned(),
            is_muted: false,
            is_video: false,
        }
    }

    #[test]
    fn a_presence_survives_the_trip_through_the_store() {
        let presence = Presence::new(participant(), 1_120.0);
        assert_eq!(Presence::parse(&presence.to_wire()).unwrap(), presence);
    }

    #[test]
    fn a_presence_is_alive_only_until_its_moment() {
        let presence = Presence::new(participant(), 1_120.0);
        assert!(presence.alive_at(1_119.9));
        assert!(!presence.alive_at(1_120.0));
    }

    #[test]
    fn renewing_moves_the_moment_and_keeps_the_participant() {
        let presence = Presence::new(participant(), 1_120.0).renewed(1_240.0);
        assert_eq!(presence.until, 1_240.0);
        assert_eq!(presence.participant, participant());
    }

    #[test]
    fn amending_flips_the_flags_and_renews_the_moment() {
        let amended = Presence::new(participant(), 1_120.0)
            .amended(MutePatch::new(None, Some(true)), 1_240.0);
        assert!(amended.participant.is_muted);
        assert!(amended.participant.is_video);
        assert_eq!(amended.until, 1_240.0);
    }

    #[test]
    fn what_the_store_could_not_have_written_is_not_a_presence() {
        assert!(Presence::parse("").is_none());
        assert!(Presence::parse("{}").is_none());
        assert!(Presence::parse("{\"until\": 1.0}").is_none());
    }
}

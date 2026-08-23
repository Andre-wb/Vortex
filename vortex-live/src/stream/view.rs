use std::collections::BTreeMap;

use serde_json::{json, Value};

use crate::stream::participant::StreamParticipant;
use crate::stream::record::Stream;

#[derive(Debug, Clone, PartialEq)]
pub struct Snapshot {
    pub stream: Stream,
    pub participants: Vec<StreamParticipant>,
    pub hands: Vec<i64>,
    pub reactions: BTreeMap<String, u64>,
    pub peak: u64,
}

impl Snapshot {
    pub fn viewer_count(&self) -> usize {
        self.participants.len()
    }

    pub fn view(&self) -> Value {
        json!({
            "room_id": self.stream.room_id,
            "host_id": self.stream.host_id,
            "title": self.stream.title,
            "description": self.stream.description,
            "allow_reactions": self.stream.allow_reactions,
            "allow_donations": self.stream.allow_donations,
            "donation_card": self.stream.donation_card,
            "donation_message": self.stream.donation_message,
            "auto_accept_speakers": self.stream.auto_accept_speakers,
            "started_at": self.stream.started_at,
            "viewer_count": self.viewer_count(),
            "viewer_peak": self.peak,
            "participants": self
                .participants
                .iter()
                .map(StreamParticipant::view)
                .collect::<Vec<Value>>(),
            "hand_queue": self.hands,
            "reaction_counts": self.reactions,
        })
    }

    pub fn room_view(&self, action: &str) -> Value {
        json!({
            "title": self.stream.title,
            "host_id": self.stream.host_id,
            "viewer_count": self.viewer_count(),
            "started_at": self.stream.started_at,
            "action": action,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::Snapshot;
    use crate::stream::participant::tests::{host, viewer};
    use crate::stream::record::tests::stream;

    fn snapshot() -> Snapshot {
        Snapshot {
            stream: stream(),
            participants: vec![host(), viewer()],
            hands: vec![8],
            reactions: BTreeMap::from([("\u{2764}\u{fe0f}".to_owned(), 3)]),
            peak: 5,
        }
    }

    #[test]
    fn the_client_sees_the_stream_with_everyone_watching_it() {
        let view = snapshot().view();
        assert_eq!(view["room_id"], 1);
        assert_eq!(view["title"], "Показ");
        assert_eq!(view["viewer_count"], 2);
        assert_eq!(view["viewer_peak"], 5);
        assert_eq!(view["participants"][0]["user_id"], 7);
        assert_eq!(view["hand_queue"][0], 8);
        assert_eq!(view["reaction_counts"]["\u{2764}\u{fe0f}"], 3);
    }

    #[test]
    fn the_room_is_told_only_what_the_sidebar_draws() {
        let view = snapshot().room_view("started");
        assert_eq!(view["title"], "Показ");
        assert_eq!(view["host_id"], 7);
        assert_eq!(view["viewer_count"], 2);
        assert_eq!(view["action"], "started");
    }

    #[test]
    fn a_stream_nobody_is_watching_counts_nobody() {
        let mut empty = snapshot();
        empty.participants.clear();
        assert_eq!(empty.viewer_count(), 0);
        assert_eq!(empty.view()["viewer_count"], 0);
    }
}

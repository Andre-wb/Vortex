use serde::{Deserialize, Serialize};

pub const DEFAULT_TITLE: &str = "Live";

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Opening {
    pub title: String,
    pub description: String,
    pub allow_reactions: bool,
    pub allow_donations: bool,
    pub donation_card: String,
    pub donation_message: String,
    pub auto_accept_speakers: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Stream {
    pub room_id: i64,
    pub host_id: i64,
    pub title: String,
    pub description: String,
    pub allow_reactions: bool,
    pub allow_donations: bool,
    pub donation_card: String,
    pub donation_message: String,
    pub auto_accept_speakers: bool,
    pub started_at: String,
    pub until: f64,
}

impl Stream {
    pub fn opened(
        room_id: i64,
        host_id: i64,
        opening: Opening,
        started_at: String,
        until: f64,
    ) -> Self {
        Stream {
            room_id,
            host_id,
            title: titled(&opening.title),
            description: opening.description,
            allow_reactions: opening.allow_reactions,
            allow_donations: opening.allow_donations,
            donation_card: opening.donation_card,
            donation_message: opening.donation_message,
            auto_accept_speakers: opening.auto_accept_speakers,
            started_at,
            until,
        }
    }

    pub fn alive_at(&self, now: f64) -> bool {
        self.until > now
    }

    pub fn renewed(&self, until: f64) -> Self {
        let mut changed = self.clone();
        changed.until = until;
        changed
    }

    pub fn to_wire(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }

    pub fn parse(wire: &str) -> Option<Self> {
        serde_json::from_str(wire).ok()
    }
}

fn titled(given: &str) -> String {
    if given.is_empty() {
        return DEFAULT_TITLE.to_owned();
    }
    given.to_owned()
}

#[cfg(test)]
pub mod tests {
    use super::{Opening, Stream};

    pub fn opening() -> Opening {
        Opening {
            title: "Показ".to_owned(),
            description: "О продукте".to_owned(),
            allow_reactions: true,
            allow_donations: false,
            donation_card: String::new(),
            donation_message: String::new(),
            auto_accept_speakers: false,
        }
    }

    pub fn stream() -> Stream {
        Stream::opened(
            1,
            7,
            opening(),
            "2026-08-04T09:15:30+00:00".to_owned(),
            1_120.0,
        )
    }

    #[test]
    fn a_stream_without_a_title_is_called_live() {
        let mut blank = opening();
        blank.title = String::new();
        let stream = Stream::opened(1, 7, blank, "2026-08-04T09:15:30+00:00".to_owned(), 1_120.0);
        assert_eq!(stream.title, "Live");
    }

    #[test]
    fn a_stream_keeps_the_title_it_was_opened_with() {
        assert_eq!(stream().title, "Показ");
    }

    #[test]
    fn a_stream_survives_the_trip_through_the_store() {
        assert_eq!(Stream::parse(&stream().to_wire()).unwrap(), stream());
    }

    #[test]
    fn a_stream_nobody_renews_stops_being_live() {
        assert!(stream().alive_at(1_119.9));
        assert!(!stream().alive_at(1_120.0));
        assert!(stream().renewed(1_240.0).alive_at(1_120.0));
    }

    #[test]
    fn what_the_store_could_not_have_written_is_not_a_stream() {
        assert!(Stream::parse("").is_none());
        assert!(Stream::parse("{\"room_id\": 1}").is_none());
    }
}

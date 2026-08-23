use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Stage {
    pub speakers: Vec<i64>,
    pub until: f64,
}

impl Stage {
    pub fn opened_by(speaker: i64, until: f64) -> Self {
        Stage {
            speakers: vec![speaker],
            until,
        }
    }

    pub fn alive_at(&self, now: f64) -> bool {
        self.until > now
    }

    pub fn speaks(&self, user_id: i64) -> bool {
        self.speakers.contains(&user_id)
    }

    pub fn with(&self, speaker: i64, until: f64) -> Self {
        let mut speakers = self.speakers.clone();
        if !speakers.contains(&speaker) {
            speakers.push(speaker);
            speakers.sort_unstable();
        }
        Stage { speakers, until }
    }

    pub fn without(&self, speaker: i64, until: f64) -> Self {
        Stage {
            speakers: self
                .speakers
                .iter()
                .copied()
                .filter(|kept| *kept != speaker)
                .collect(),
            until,
        }
    }

    pub fn renewed(&self, until: f64) -> Self {
        Stage {
            speakers: self.speakers.clone(),
            until,
        }
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
    use super::Stage;

    #[test]
    fn the_one_who_opens_the_stage_speaks_first() {
        let stage = Stage::opened_by(7, 1_120.0);
        assert_eq!(stage.speakers, vec![7]);
        assert!(stage.speaks(7));
        assert!(!stage.speaks(8));
    }

    #[test]
    fn a_stage_survives_the_trip_through_the_store() {
        let stage = Stage::opened_by(7, 1_120.0);
        assert_eq!(Stage::parse(&stage.to_wire()).unwrap(), stage);
    }

    #[test]
    fn adding_the_same_speaker_twice_adds_them_once() {
        let stage = Stage::opened_by(7, 1_120.0)
            .with(8, 1_120.0)
            .with(8, 1_120.0);
        assert_eq!(stage.speakers, vec![7, 8]);
    }

    #[test]
    fn removing_the_last_speaker_leaves_the_stage_open_and_empty() {
        let stage = Stage::opened_by(7, 1_120.0).without(7, 1_120.0);
        assert!(stage.speakers.is_empty());
        assert!(stage.alive_at(1_000.0));
    }

    #[test]
    fn removing_someone_who_never_spoke_changes_nothing() {
        let stage = Stage::opened_by(7, 1_120.0).without(8, 1_120.0);
        assert_eq!(stage.speakers, vec![7]);
    }

    #[test]
    fn a_stage_nobody_renews_stops_being_open() {
        let stage = Stage::opened_by(7, 1_120.0);
        assert!(stage.alive_at(1_119.9));
        assert!(!stage.alive_at(1_120.0));
        assert!(stage.renewed(1_240.0).alive_at(1_120.0));
    }

    #[test]
    fn what_the_store_could_not_have_written_is_not_a_stage() {
        assert!(Stage::parse("").is_none());
        assert!(Stage::parse("{\"speakers\": []}").is_none());
    }
}

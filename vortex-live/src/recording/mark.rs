use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Mark {
    pub started_by: i64,
    pub started_at: String,
    pub participants: Vec<i64>,
    pub until: f64,
}

impl Mark {
    pub fn new(started_by: i64, started_at: String, participants: Vec<i64>, until: f64) -> Self {
        Mark {
            started_by,
            started_at,
            participants,
            until,
        }
    }

    pub fn alive_at(&self, now: f64) -> bool {
        self.until > now
    }

    pub fn renewed(&self, until: f64) -> Self {
        Mark {
            started_by: self.started_by,
            started_at: self.started_at.clone(),
            participants: self.participants.clone(),
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

pub fn status_view(mark: Option<&Mark>) -> Value {
    match mark {
        Some(mark) => json!({
            "recording": true,
            "started_at": mark.started_at,
            "started_by": mark.started_by,
        }),
        None => json!({
            "recording": false,
            "started_at": null,
            "started_by": null,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::{status_view, Mark};
    use serde_json::json;

    fn mark() -> Mark {
        Mark::new(
            7,
            "2026-08-04T09:15:30+00:00".to_owned(),
            vec![7, 8],
            1_120.0,
        )
    }

    #[test]
    fn a_mark_survives_the_trip_through_the_store() {
        assert_eq!(Mark::parse(&mark().to_wire()).unwrap(), mark());
    }

    #[test]
    fn a_mark_nobody_renews_stops_being_a_recording() {
        assert!(mark().alive_at(1_119.9));
        assert!(!mark().alive_at(1_120.0));
        assert!(mark().renewed(1_240.0).alive_at(1_120.0));
    }

    #[test]
    fn the_room_is_told_who_started_the_recording_and_when() {
        assert_eq!(
            status_view(Some(&mark())),
            json!({
                "recording": true,
                "started_at": "2026-08-04T09:15:30+00:00",
                "started_by": 7,
            })
        );
    }

    #[test]
    fn a_room_that_is_not_recorded_says_so_without_naming_anyone() {
        assert_eq!(
            status_view(None),
            json!({"recording": false, "started_at": null, "started_by": null})
        );
    }

    #[test]
    fn what_the_store_could_not_have_written_is_not_a_mark() {
        assert!(Mark::parse("").is_none());
        assert!(Mark::parse("{\"started_by\": 7}").is_none());
    }
}

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use vortex_proto::message::time::client_stamp::{ClientStamp, MICROS_PER_SECOND};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScheduleEntry {
    pub room_id: i64,
    pub title: String,
    pub scheduled_at: String,
    pub at: i64,
    pub host_id: i64,
    pub host_name: String,
}

impl ScheduleEntry {
    pub fn of(
        room_id: i64,
        title: &str,
        scheduled_at: &str,
        host_id: i64,
        host_name: &str,
    ) -> Option<Self> {
        let at = ClientStamp::read(scheduled_at)?.div_euclid(MICROS_PER_SECOND);
        Some(ScheduleEntry {
            room_id,
            title: title.to_owned(),
            scheduled_at: scheduled_at.to_owned(),
            at,
            host_id,
            host_name: host_name.to_owned(),
        })
    }

    pub fn due_at(&self, now: f64) -> bool {
        now >= self.at as f64
    }

    pub fn view(&self) -> Value {
        json!({
            "title": self.title,
            "scheduled_at": self.scheduled_at,
            "host_id": self.host_id,
            "host_name": self.host_name,
        })
    }

    pub fn to_wire(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }

    pub fn parse(wire: &str) -> Option<Self> {
        serde_json::from_str(wire).ok()
    }
}

#[cfg(test)]
pub mod tests {
    use super::ScheduleEntry;

    pub fn entry() -> ScheduleEntry {
        ScheduleEntry::of(1, "Показ", "2026-08-04T09:15:30Z", 7, "Ann").unwrap()
    }

    #[test]
    fn the_moment_the_host_typed_becomes_the_moment_the_stream_fires() {
        assert_eq!(entry().at, 1_785_834_930);
        assert_eq!(entry().scheduled_at, "2026-08-04T09:15:30Z");
    }

    #[test]
    fn a_schedule_without_a_zone_is_read_as_utc() {
        assert_eq!(
            ScheduleEntry::of(1, "Показ", "2026-08-04T09:15:30", 7, "Ann")
                .unwrap()
                .at,
            1_785_834_930
        );
    }

    #[test]
    fn a_moment_nobody_can_read_is_not_a_schedule() {
        assert!(ScheduleEntry::of(1, "Показ", "", 7, "Ann").is_none());
        assert!(ScheduleEntry::of(1, "Показ", "завтра", 7, "Ann").is_none());
        assert!(ScheduleEntry::of(1, "Показ", "2025-02-29T00:00:00Z", 7, "Ann").is_none());
    }

    #[test]
    fn a_schedule_is_due_only_once_its_moment_has_come() {
        assert!(!entry().due_at(1_785_834_929.0));
        assert!(entry().due_at(1_785_834_930.0));
    }

    #[test]
    fn the_host_is_told_exactly_what_they_scheduled() {
        assert_eq!(
            entry().view(),
            serde_json::json!({
                "title": "Показ",
                "scheduled_at": "2026-08-04T09:15:30Z",
                "host_id": 7,
                "host_name": "Ann",
            })
        );
    }

    #[test]
    fn a_schedule_survives_the_trip_through_the_store() {
        assert_eq!(ScheduleEntry::parse(&entry().to_wire()).unwrap(), entry());
        assert!(ScheduleEntry::parse("").is_none());
    }
}

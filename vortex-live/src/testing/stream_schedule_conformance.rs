use std::sync::Arc;

use crate::ports::stream_schedule::StreamSchedule;
use crate::stream::schedule::entry::ScheduleEntry;
use crate::testing::until;
use vortex_core::room::room_id::RoomId;

pub type StreamScheduleFactory = dyn Fn() -> Arc<dyn StreamSchedule>;

const NOON: f64 = 1_785_834_930.0;

fn room(value: i64) -> RoomId {
    RoomId::of(value).expect("номер комнаты положителен")
}

fn entry(room_id: i64, title: &str, at: &str) -> ScheduleEntry {
    ScheduleEntry::of(room_id, title, at, 7, "Ann").expect("момент расписания читается")
}

pub fn check_all(make: &StreamScheduleFactory) {
    a_channel_without_a_plan_has_no_schedule(make);
    a_planned_stream_is_found(make);
    a_schedule_whose_moment_has_not_come_is_claimed_by_nobody(make);
    a_due_schedule_is_claimed_exactly_once(make);
    the_earliest_due_schedule_is_claimed_first(make);
    a_forgotten_schedule_is_forgotten_only_once(make);
}

pub fn a_channel_without_a_plan_has_no_schedule(make: &StreamScheduleFactory) {
    let schedule = make();
    assert_eq!(schedule.find(room(1), NOON).unwrap(), None);
    assert!(!schedule.forget(room(1), NOON).unwrap());
    assert_eq!(schedule.claim_due(NOON).unwrap(), None);
}

pub fn a_planned_stream_is_found(make: &StreamScheduleFactory) {
    let schedule = make();
    let planned = entry(1, "Показ", "2026-08-04T09:15:30Z");
    schedule
        .put(room(1), &planned, until(NOON), NOON - 3_600.0)
        .unwrap();

    assert_eq!(
        schedule.find(room(1), NOON - 3_600.0).unwrap(),
        Some(planned)
    );
}

pub fn a_schedule_whose_moment_has_not_come_is_claimed_by_nobody(make: &StreamScheduleFactory) {
    let schedule = make();
    schedule
        .put(
            room(1),
            &entry(1, "Показ", "2026-08-04T09:15:30Z"),
            until(NOON),
            NOON - 1.0,
        )
        .unwrap();
    assert_eq!(schedule.claim_due(NOON - 1.0).unwrap(), None);
}

pub fn a_due_schedule_is_claimed_exactly_once(make: &StreamScheduleFactory) {
    let schedule = make();
    schedule
        .put(
            room(1),
            &entry(1, "Показ", "2026-08-04T09:15:30Z"),
            until(NOON),
            NOON,
        )
        .unwrap();

    assert_eq!(schedule.claim_due(NOON).unwrap().unwrap().room_id, 1);
    assert_eq!(schedule.claim_due(NOON).unwrap(), None);
    assert_eq!(schedule.find(room(1), NOON).unwrap(), None);
}

pub fn the_earliest_due_schedule_is_claimed_first(make: &StreamScheduleFactory) {
    let schedule = make();
    schedule
        .put(
            room(1),
            &entry(1, "Позже", "2026-08-04T09:15:30Z"),
            until(NOON),
            NOON,
        )
        .unwrap();
    schedule
        .put(
            room(2),
            &entry(2, "Раньше", "2026-08-04T08:00:00Z"),
            until(NOON),
            NOON,
        )
        .unwrap();

    assert_eq!(schedule.claim_due(NOON).unwrap().unwrap().title, "Раньше");
    assert_eq!(schedule.claim_due(NOON).unwrap().unwrap().title, "Позже");
}

pub fn a_forgotten_schedule_is_forgotten_only_once(make: &StreamScheduleFactory) {
    let schedule = make();
    schedule
        .put(
            room(1),
            &entry(1, "Показ", "2026-08-04T09:15:30Z"),
            until(NOON),
            NOON - 3_600.0,
        )
        .unwrap();

    assert!(schedule.forget(room(1), NOON - 3_600.0).unwrap());
    assert!(!schedule.forget(room(1), NOON - 3_600.0).unwrap());
}

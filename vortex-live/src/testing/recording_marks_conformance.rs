use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;

use crate::ports::recording_marks::RecordingMarks;
use crate::recording::mark::Mark;
use crate::testing::{blink, until, BASE, BLINK, BLINK_MILLIS};
use vortex_core::room::room_id::RoomId;

pub type RecordingMarksFactory = dyn Fn() -> Arc<dyn RecordingMarks>;

fn room() -> RoomId {
    RoomId::of(1).expect("номер комнаты положителен")
}

fn mark(until: f64) -> Mark {
    Mark::new(7, "2026-08-04T09:15:30+00:00".to_owned(), vec![7, 8], until)
}

pub fn check_all(make: &RecordingMarksFactory) {
    a_room_nobody_records_has_no_mark(make);
    a_started_recording_is_found(make);
    a_recording_is_started_only_once(make);
    a_recording_is_stopped_only_once(make);
    a_recording_nobody_renews_stops_by_itself(make);
}

pub fn a_room_nobody_records_has_no_mark(make: &RecordingMarksFactory) {
    let store = make();
    assert_eq!(store.find(room(), BASE).unwrap(), None);
    assert_eq!(store.stop(room(), BASE).unwrap(), None);
    assert!(!store.renew(room(), until(BASE), BASE).unwrap());
}

pub fn a_started_recording_is_found(make: &RecordingMarksFactory) {
    let store = make();
    let started = store.start(room(), &mark(until(BASE)), BASE).unwrap();
    assert!(!started.already_started());

    let found = store.find(room(), BASE).unwrap().unwrap();
    assert_eq!(found.started_by, 7);
    assert_eq!(found.participants, vec![7, 8]);
}

pub fn a_recording_is_started_only_once(make: &RecordingMarksFactory) {
    let store = make();
    store.start(room(), &mark(until(BASE)), BASE).unwrap();

    let again = store
        .start(
            room(),
            &Mark::new(
                8,
                "2026-08-04T09:20:00+00:00".to_owned(),
                vec![],
                until(BASE),
            ),
            BASE,
        )
        .unwrap();
    assert!(again.already_started());
    assert_eq!(again.mark().started_by, 7);
}

pub fn a_recording_is_stopped_only_once(make: &RecordingMarksFactory) {
    let store = make();
    store.start(room(), &mark(until(BASE)), BASE).unwrap();

    assert_eq!(store.stop(room(), BASE).unwrap().unwrap().started_by, 7);
    assert_eq!(store.stop(room(), BASE).unwrap(), None);
}

pub fn a_recording_nobody_renews_stops_by_itself(make: &RecordingMarksFactory) {
    let store = make();
    store.start(room(), &mark(blink(BASE)), BASE).unwrap();
    sleep(Duration::from_millis(BLINK_MILLIS));
    assert_eq!(store.find(room(), BASE + BLINK).unwrap(), None);
}

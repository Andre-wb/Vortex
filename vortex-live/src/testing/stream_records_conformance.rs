use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;

use crate::ports::stream_records::StreamRecords;
use crate::store::swapped::Swapped;
use crate::stream::record::{Opening, Stream};
use crate::testing::{blink, until, BASE, BLINK, BLINK_MILLIS};
use vortex_core::room::room_id::RoomId;

pub type StreamRecordsFactory = dyn Fn() -> Arc<dyn StreamRecords>;

fn room() -> RoomId {
    RoomId::of(1).expect("номер комнаты положителен")
}

fn stream(until: f64) -> Stream {
    Stream::opened(
        1,
        7,
        Opening {
            title: "Показ".to_owned(),
            description: String::new(),
            allow_reactions: true,
            allow_donations: false,
            donation_card: String::new(),
            donation_message: String::new(),
            auto_accept_speakers: false,
        },
        "2026-08-04T09:15:30+00:00".to_owned(),
        until,
    )
}

pub fn check_all(make: &StreamRecordsFactory) {
    a_channel_without_a_stream_is_not_live(make);
    an_opened_stream_is_found(make);
    a_channel_that_is_live_opens_no_second_stream(make);
    a_stream_is_swapped_only_when_it_did_not_change(make);
    a_stream_is_forgotten_only_once(make);
    a_stream_nobody_renews_disappears(make);
}

pub fn a_channel_without_a_stream_is_not_live(make: &StreamRecordsFactory) {
    let store = make();
    assert_eq!(store.find(room(), BASE).unwrap(), None);
    assert_eq!(store.forget(room(), BASE).unwrap(), None);
    assert_eq!(
        store
            .swap(room(), &stream(until(BASE)), &stream(until(BASE)), BASE)
            .unwrap(),
        Swapped::Missing
    );
}

pub fn an_opened_stream_is_found(make: &StreamRecordsFactory) {
    let store = make();
    assert!(store.open(room(), &stream(until(BASE)), BASE).unwrap());

    let found = store.find(room(), BASE).unwrap().unwrap();
    assert_eq!(found.host_id, 7);
    assert_eq!(found.title, "Показ");
}

pub fn a_channel_that_is_live_opens_no_second_stream(make: &StreamRecordsFactory) {
    let store = make();
    store.open(room(), &stream(until(BASE)), BASE).unwrap();
    assert!(!store.open(room(), &stream(until(BASE)), BASE).unwrap());
}

pub fn a_stream_is_swapped_only_when_it_did_not_change(make: &StreamRecordsFactory) {
    let store = make();
    let opened = stream(until(BASE));
    store.open(room(), &opened, BASE).unwrap();

    let mut renamed = opened.clone();
    renamed.title = "Другой".to_owned();
    assert_eq!(
        store.swap(room(), &opened, &renamed, BASE).unwrap(),
        Swapped::Done
    );
    assert_eq!(
        store.swap(room(), &opened, &renamed, BASE).unwrap(),
        Swapped::Changed
    );
    assert_eq!(store.find(room(), BASE).unwrap().unwrap().title, "Другой");
}

pub fn a_stream_is_forgotten_only_once(make: &StreamRecordsFactory) {
    let store = make();
    store.open(room(), &stream(until(BASE)), BASE).unwrap();

    assert!(store.forget(room(), BASE).unwrap().is_some());
    assert_eq!(store.forget(room(), BASE).unwrap(), None);
}

pub fn a_stream_nobody_renews_disappears(make: &StreamRecordsFactory) {
    let store = make();
    store.open(room(), &stream(blink(BASE)), BASE).unwrap();
    sleep(Duration::from_millis(BLINK_MILLIS));
    assert_eq!(store.find(room(), BASE + BLINK).unwrap(), None);
}

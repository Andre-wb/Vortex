use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;

use vortex_auth::account::user_id::UserId;

use crate::identity::person::Person;
use crate::ports::stream_roster::StreamRoster;
use crate::store::swapped::Swapped;
use crate::stream::participant::StreamParticipant;
use crate::stream::role::StreamRole;
use crate::testing::{blink, until, BASE, BLINK, BLINK_MILLIS};
use vortex_core::room::room_id::RoomId;

pub type StreamRosterFactory = dyn Fn() -> Arc<dyn StreamRoster>;

fn room() -> RoomId {
    RoomId::of(1).expect("номер комнаты положителен")
}

fn user(value: i64) -> UserId {
    UserId::of(value).expect("номер учётной записи положителен")
}

fn seat(user_id: i64, role: StreamRole) -> StreamParticipant {
    StreamParticipant::joining(
        Person::of(user_id, "member", None, None, None),
        role,
        "2026-08-04T09:15:30+00:00".to_owned(),
    )
}

pub fn check_all(make: &StreamRosterFactory) {
    a_stream_nobody_watches_seats_nobody(make);
    a_seated_participant_is_listed(make);
    seating_twice_gives_back_who_is_already_there(make);
    a_participant_is_swapped_only_when_it_did_not_change(make);
    unseating_gives_back_who_left_and_only_once(make);
    clearing_empties_the_whole_roster(make);
    a_roster_nobody_renews_disappears(make);
}

pub fn a_stream_nobody_watches_seats_nobody(make: &StreamRosterFactory) {
    let store = make();
    assert!(store.list(room(), BASE).unwrap().is_empty());
    assert_eq!(store.find(room(), user(7), BASE).unwrap(), None);
    assert_eq!(store.unseat(room(), user(7), BASE).unwrap(), None);
    assert!(!store.renew(room(), until(BASE), BASE).unwrap());
}

pub fn a_seated_participant_is_listed(make: &StreamRosterFactory) {
    let store = make();
    assert_eq!(
        store
            .seat(room(), &seat(7, StreamRole::Host), until(BASE), BASE)
            .unwrap(),
        None
    );

    assert_eq!(store.list(room(), BASE).unwrap().len(), 1);
    assert_eq!(
        store.find(room(), user(7), BASE).unwrap().unwrap().role,
        StreamRole::Host
    );
}

pub fn seating_twice_gives_back_who_is_already_there(make: &StreamRosterFactory) {
    let store = make();
    store
        .seat(room(), &seat(7, StreamRole::Host), until(BASE), BASE)
        .unwrap();

    let already = store
        .seat(room(), &seat(7, StreamRole::Viewer), until(BASE), BASE)
        .unwrap()
        .unwrap();
    assert_eq!(already.role, StreamRole::Host);
    assert_eq!(store.list(room(), BASE).unwrap().len(), 1);
}

pub fn a_participant_is_swapped_only_when_it_did_not_change(make: &StreamRosterFactory) {
    let store = make();
    let before = seat(8, StreamRole::Viewer);
    store.seat(room(), &before, until(BASE), BASE).unwrap();
    let after = before.with_hand(true);

    assert_eq!(
        store
            .swap_member(room(), user(8), &before, &after, until(BASE), BASE)
            .unwrap(),
        Swapped::Done
    );
    assert_eq!(
        store
            .swap_member(room(), user(8), &before, &after, until(BASE), BASE)
            .unwrap(),
        Swapped::Changed
    );
    assert_eq!(
        store
            .swap_member(room(), user(9), &before, &after, until(BASE), BASE)
            .unwrap(),
        Swapped::Missing
    );
    assert!(
        store
            .find(room(), user(8), BASE)
            .unwrap()
            .unwrap()
            .hand_raised
    );
}

pub fn unseating_gives_back_who_left_and_only_once(make: &StreamRosterFactory) {
    let store = make();
    store
        .seat(room(), &seat(8, StreamRole::Viewer), until(BASE), BASE)
        .unwrap();

    assert_eq!(
        store
            .unseat(room(), user(8), BASE)
            .unwrap()
            .unwrap()
            .person
            .user_id,
        8
    );
    assert_eq!(store.unseat(room(), user(8), BASE).unwrap(), None);
}

pub fn clearing_empties_the_whole_roster(make: &StreamRosterFactory) {
    let store = make();
    store
        .seat(room(), &seat(7, StreamRole::Host), until(BASE), BASE)
        .unwrap();
    store
        .seat(room(), &seat(8, StreamRole::Viewer), until(BASE), BASE)
        .unwrap();

    store.clear(room(), BASE).unwrap();
    assert!(store.list(room(), BASE).unwrap().is_empty());
}

pub fn a_roster_nobody_renews_disappears(make: &StreamRosterFactory) {
    let store = make();
    store
        .seat(room(), &seat(7, StreamRole::Host), blink(BASE), BASE)
        .unwrap();
    sleep(Duration::from_millis(BLINK_MILLIS));
    assert!(store.list(room(), BASE + BLINK).unwrap().is_empty());
}

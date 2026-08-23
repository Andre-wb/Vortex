use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;

use vortex_auth::account::user_id::UserId;

use crate::ports::stream_hands::StreamHands;
use crate::testing::{blink, until, BASE, BLINK, BLINK_MILLIS};
use vortex_core::room::room_id::RoomId;

pub type StreamHandsFactory = dyn Fn() -> Arc<dyn StreamHands>;

fn room() -> RoomId {
    RoomId::of(1).expect("номер комнаты положителен")
}

fn user(value: i64) -> UserId {
    UserId::of(value).expect("номер учётной записи положителен")
}

pub fn check_all(make: &StreamHandsFactory) {
    a_stream_without_raised_hands_has_an_empty_queue(make);
    hands_stand_in_the_order_they_went_up(make);
    a_hand_raised_twice_keeps_its_place(make);
    a_lowered_hand_leaves_the_queue(make);
    clearing_empties_the_whole_queue(make);
    a_queue_nobody_renews_disappears(make);
}

pub fn a_stream_without_raised_hands_has_an_empty_queue(make: &StreamHandsFactory) {
    let hands = make();
    assert!(hands.queue(room(), BASE).unwrap().is_empty());
    hands.lower(room(), user(7), BASE).unwrap();
    assert!(!hands.renew(room(), until(BASE), BASE).unwrap());
}

pub fn hands_stand_in_the_order_they_went_up(make: &StreamHandsFactory) {
    let hands = make();
    hands
        .raise(room(), user(8), BASE, until(BASE), BASE)
        .unwrap();
    hands
        .raise(room(), user(7), BASE + 1.0, until(BASE), BASE)
        .unwrap();

    assert_eq!(hands.queue(room(), BASE).unwrap(), vec![8, 7]);
}

pub fn a_hand_raised_twice_keeps_its_place(make: &StreamHandsFactory) {
    let hands = make();
    hands
        .raise(room(), user(8), BASE, until(BASE), BASE)
        .unwrap();
    hands
        .raise(room(), user(7), BASE + 1.0, until(BASE), BASE)
        .unwrap();
    hands
        .raise(room(), user(8), BASE + 2.0, until(BASE), BASE)
        .unwrap();

    assert_eq!(hands.queue(room(), BASE).unwrap(), vec![8, 7]);
}

pub fn a_lowered_hand_leaves_the_queue(make: &StreamHandsFactory) {
    let hands = make();
    hands
        .raise(room(), user(8), BASE, until(BASE), BASE)
        .unwrap();
    hands.lower(room(), user(8), BASE).unwrap();
    assert!(hands.queue(room(), BASE).unwrap().is_empty());
}

pub fn clearing_empties_the_whole_queue(make: &StreamHandsFactory) {
    let hands = make();
    hands
        .raise(room(), user(8), BASE, until(BASE), BASE)
        .unwrap();
    hands
        .raise(room(), user(7), BASE + 1.0, until(BASE), BASE)
        .unwrap();

    hands.clear(room(), BASE).unwrap();
    assert!(hands.queue(room(), BASE).unwrap().is_empty());
}

pub fn a_queue_nobody_renews_disappears(make: &StreamHandsFactory) {
    let hands = make();
    hands
        .raise(room(), user(8), BASE, blink(BASE), BASE)
        .unwrap();
    sleep(Duration::from_millis(BLINK_MILLIS));
    assert!(hands.queue(room(), BASE + BLINK).unwrap().is_empty());
}

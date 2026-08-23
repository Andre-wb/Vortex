use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;

use crate::call::call_id::CallId;
use crate::ports::call_index::CallIndex;
use crate::testing::{blink, until, BASE, BLINK, BLINK_MILLIS};
use vortex_core::room::room_id::RoomId;

pub type CallIndexFactory = dyn Fn() -> Arc<dyn CallIndex>;

fn room() -> RoomId {
    RoomId::of(1).expect("номер комнаты положителен")
}

fn call(value: &str) -> CallId {
    CallId::parse(value).expect("идентификатор звонка валиден")
}

pub fn check_all(make: &CallIndexFactory) {
    a_room_without_a_call_claims_nothing(make);
    the_first_claim_wins_and_the_second_reads_it(make);
    a_claim_is_released_only_by_the_call_that_holds_it(make);
    a_claim_nobody_renews_frees_the_room(make);
}

pub fn a_room_without_a_call_claims_nothing(make: &CallIndexFactory) {
    let index = make();
    assert_eq!(index.find(room(), BASE).unwrap(), None);
    assert!(!index.release(room(), &call("abcd"), BASE).unwrap());
    assert!(!index.renew(room(), until(BASE), BASE).unwrap());
}

pub fn the_first_claim_wins_and_the_second_reads_it(make: &CallIndexFactory) {
    let index = make();
    assert_eq!(
        index
            .claim(room(), &call("first"), until(BASE), BASE)
            .unwrap(),
        None
    );
    assert_eq!(
        index
            .claim(room(), &call("second"), until(BASE), BASE)
            .unwrap(),
        Some(call("first"))
    );
    assert_eq!(index.find(room(), BASE).unwrap(), Some(call("first")));
}

pub fn a_claim_is_released_only_by_the_call_that_holds_it(make: &CallIndexFactory) {
    let index = make();
    index
        .claim(room(), &call("first"), until(BASE), BASE)
        .unwrap();

    assert!(!index.release(room(), &call("second"), BASE).unwrap());
    assert!(index.release(room(), &call("first"), BASE).unwrap());
    assert_eq!(index.find(room(), BASE).unwrap(), None);
}

pub fn a_claim_nobody_renews_frees_the_room(make: &CallIndexFactory) {
    let index = make();
    index
        .claim(room(), &call("first"), blink(BASE), BASE)
        .unwrap();
    sleep(Duration::from_millis(BLINK_MILLIS));

    assert_eq!(index.find(room(), BASE + BLINK).unwrap(), None);
    assert_eq!(
        index
            .claim(room(), &call("second"), until(BASE + BLINK), BASE + BLINK)
            .unwrap(),
        None
    );
}

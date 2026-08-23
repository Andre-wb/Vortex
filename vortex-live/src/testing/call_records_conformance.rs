use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;

use crate::call::call_id::CallId;
use crate::call::kind::CallKind;
use crate::call::participant::CallParticipant;
use crate::call::record::{seated, Call, CallState};
use crate::call::topology::Topology;
use crate::identity::person::Person;
use crate::ports::call_records::CallRecords;
use crate::store::swapped::Swapped;
use crate::testing::{blink, until, BASE, BLINK, BLINK_MILLIS};

pub type CallRecordsFactory = dyn Fn() -> Arc<dyn CallRecords>;

fn call_id() -> CallId {
    CallId::parse("abcd1234").expect("идентификатор звонка валиден")
}

fn call(until: f64) -> Call {
    Call {
        call_id: "abcd1234".to_owned(),
        room_id: 1,
        initiator_id: 7,
        kind: CallKind::Audio,
        state: CallState::Ringing,
        topology: Topology::Mesh,
        participants: seated(vec![(
            7,
            CallParticipant::connecting(
                Person::of(7, "ann", Some("Ann"), None, None),
                "2026-08-04T09:15:30+00:00".to_owned(),
            ),
        )]),
        created_at: "2026-08-04T09:15:30+00:00".to_owned(),
        started_at: None,
        max_participants: 10,
        until,
    }
}

pub fn check_all(make: &CallRecordsFactory) {
    a_call_nobody_opened_is_missing(make);
    an_opened_call_is_found_with_everyone_it_invited(make);
    a_call_is_swapped_only_when_it_did_not_change(make);
    a_call_is_forgotten_only_once(make);
    a_call_nobody_renews_disappears(make);
}

pub fn a_call_nobody_opened_is_missing(make: &CallRecordsFactory) {
    let store = make();
    assert_eq!(store.find(&call_id(), BASE).unwrap(), None);
    assert!(!store.forget(&call_id(), BASE).unwrap());
    assert_eq!(
        store
            .swap(&call_id(), &call(until(BASE)), &call(until(BASE)), BASE)
            .unwrap(),
        Swapped::Missing
    );
}

pub fn an_opened_call_is_found_with_everyone_it_invited(make: &CallRecordsFactory) {
    let store = make();
    store.open(&call(until(BASE)), BASE).unwrap();

    let found = store.find(&call_id(), BASE).unwrap().unwrap();
    assert_eq!(found.initiator_id, 7);
    assert_eq!(found.connected_count(), 1);
    assert_eq!(found.state, CallState::Ringing);
}

pub fn a_call_is_swapped_only_when_it_did_not_change(make: &CallRecordsFactory) {
    let store = make();
    let opened = call(until(BASE));
    store.open(&opened, BASE).unwrap();

    let ended = opened.ended();
    assert_eq!(
        store.swap(&call_id(), &opened, &ended, BASE).unwrap(),
        Swapped::Done
    );
    assert_eq!(
        store.swap(&call_id(), &opened, &ended, BASE).unwrap(),
        Swapped::Changed
    );
    assert_eq!(
        store.find(&call_id(), BASE).unwrap().unwrap().state,
        CallState::Ended
    );
}

pub fn a_call_is_forgotten_only_once(make: &CallRecordsFactory) {
    let store = make();
    store.open(&call(until(BASE)), BASE).unwrap();

    assert!(store.forget(&call_id(), BASE).unwrap());
    assert!(!store.forget(&call_id(), BASE).unwrap());
    assert_eq!(store.find(&call_id(), BASE).unwrap(), None);
}

pub fn a_call_nobody_renews_disappears(make: &CallRecordsFactory) {
    let store = make();
    store.open(&call(blink(BASE)), BASE).unwrap();
    sleep(Duration::from_millis(BLINK_MILLIS));
    assert_eq!(store.find(&call_id(), BASE + BLINK).unwrap(), None);
}

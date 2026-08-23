use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;

use vortex_auth::account::user_id::UserId;

use crate::ports::stage_board::StageBoard;
use crate::stage::record::Stage;
use crate::testing::{blink, until, BASE, BLINK, BLINK_MILLIS};
use vortex_core::room::room_id::RoomId;

pub type StageBoardFactory = dyn Fn() -> Arc<dyn StageBoard>;

fn room() -> RoomId {
    RoomId::of(1).expect("номер комнаты положителен")
}

fn user(value: i64) -> UserId {
    UserId::of(value).expect("номер учётной записи положителен")
}

pub fn check_all(make: &StageBoardFactory) {
    a_stage_nobody_opened_is_closed(make);
    an_opened_stage_names_its_first_speaker(make);
    a_speaker_is_added_and_removed(make);
    removing_the_last_speaker_leaves_the_stage_open(make);
    a_closed_stage_is_closed_only_once(make);
    a_stage_nobody_renews_closes_by_itself(make);
}

pub fn a_stage_nobody_opened_is_closed(make: &StageBoardFactory) {
    let store = make();
    assert_eq!(store.find(room(), BASE).unwrap(), None);
    assert!(!store.close(room(), BASE).unwrap());
    assert_eq!(store.add(room(), user(7), until(BASE), BASE).unwrap(), None);
    assert!(!store.renew(room(), until(BASE), BASE).unwrap());
}

pub fn an_opened_stage_names_its_first_speaker(make: &StageBoardFactory) {
    let store = make();
    store
        .open(room(), &Stage::opened_by(7, until(BASE)), BASE)
        .unwrap();
    assert_eq!(store.find(room(), BASE).unwrap().unwrap().speakers, vec![7]);
}

pub fn a_speaker_is_added_and_removed(make: &StageBoardFactory) {
    let store = make();
    store
        .open(room(), &Stage::opened_by(7, until(BASE)), BASE)
        .unwrap();

    assert_eq!(
        store
            .add(room(), user(8), until(BASE), BASE)
            .unwrap()
            .unwrap()
            .speakers,
        vec![7, 8]
    );
    assert_eq!(
        store
            .remove(room(), user(7), until(BASE), BASE)
            .unwrap()
            .unwrap()
            .speakers,
        vec![8]
    );
}

pub fn removing_the_last_speaker_leaves_the_stage_open(make: &StageBoardFactory) {
    let store = make();
    store
        .open(room(), &Stage::opened_by(7, until(BASE)), BASE)
        .unwrap();
    store.remove(room(), user(7), until(BASE), BASE).unwrap();

    let stage = store.find(room(), BASE).unwrap().unwrap();
    assert!(stage.speakers.is_empty());
}

pub fn a_closed_stage_is_closed_only_once(make: &StageBoardFactory) {
    let store = make();
    store
        .open(room(), &Stage::opened_by(7, until(BASE)), BASE)
        .unwrap();
    assert!(store.close(room(), BASE).unwrap());
    assert!(!store.close(room(), BASE).unwrap());
    assert_eq!(store.find(room(), BASE).unwrap(), None);
}

pub fn a_stage_nobody_renews_closes_by_itself(make: &StageBoardFactory) {
    let store = make();
    store
        .open(room(), &Stage::opened_by(7, blink(BASE)), BASE)
        .unwrap();
    sleep(Duration::from_millis(BLINK_MILLIS));
    assert_eq!(store.find(room(), BASE + BLINK).unwrap(), None);
}

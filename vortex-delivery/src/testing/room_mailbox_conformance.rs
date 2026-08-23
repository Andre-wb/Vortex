use std::sync::Arc;

use vortex_auth::account::user_id::UserId;
use vortex_core::room::room_id::RoomId;

use crate::mailbox::room::service::RoomMailboxService;
use crate::message::payload::Payload;
use crate::ports::room_mailbox::RoomMailbox;

fn room(value: i64) -> RoomId {
    RoomId::of(value).expect("номер комнаты положителен")
}

fn reader(value: i64) -> UserId {
    UserId::of(value).expect("номер учётной записи положителен")
}

pub fn a_deposited_message_is_collected_once(store: Arc<dyn RoomMailbox>) {
    let service = RoomMailboxService::new(store);
    service
        .deposit(room(41), &[reader(7)], &Payload::of("{\"n\":1}"), 1000.0)
        .unwrap();
    assert_eq!(
        service.collect(room(41), reader(7), 1000.0).unwrap(),
        vec!["{\"n\":1}".to_owned()]
    );
    assert!(service
        .collect(room(41), reader(7), 1000.0)
        .unwrap()
        .is_empty());
}

pub fn order_of_deposit_is_the_order_of_collection(store: Arc<dyn RoomMailbox>) {
    let service = RoomMailboxService::new(store);
    for n in 0..4 {
        service
            .deposit(
                room(42),
                &[reader(7)],
                &Payload::of(&format!("{{\"n\":{n}}}")),
                1000.0 + n as f64,
            )
            .unwrap();
    }
    let collected = service.collect(room(42), reader(7), 1010.0).unwrap();
    assert_eq!(
        collected,
        vec![
            "{\"n\":0}".to_owned(),
            "{\"n\":1}".to_owned(),
            "{\"n\":2}".to_owned(),
            "{\"n\":3}".to_owned(),
        ]
    );
}

pub fn one_deposit_reaches_every_named_reader(store: Arc<dyn RoomMailbox>) {
    let service = RoomMailboxService::new(store);
    service
        .deposit(
            room(43),
            &[reader(11), reader(12), reader(13)],
            &Payload::of("{\"all\":true}"),
            1000.0,
        )
        .unwrap();
    for uid in [11, 12, 13] {
        assert_eq!(
            service.collect(room(43), reader(uid), 1000.0).unwrap(),
            vec!["{\"all\":true}".to_owned()]
        );
    }
}

pub fn a_reader_sees_only_their_own_room(store: Arc<dyn RoomMailbox>) {
    let service = RoomMailboxService::new(store);
    service
        .deposit(room(44), &[reader(7)], &Payload::of("{\"r\":44}"), 1000.0)
        .unwrap();
    assert!(service
        .collect(room(45), reader(7), 1000.0)
        .unwrap()
        .is_empty());
    assert!(service
        .collect(room(44), reader(8), 1000.0)
        .unwrap()
        .is_empty());
    assert_eq!(
        service.collect(room(44), reader(7), 1000.0).unwrap(),
        vec!["{\"r\":44}".to_owned()]
    );
}

pub fn a_stale_message_is_not_handed_over(store: Arc<dyn RoomMailbox>) {
    let service = RoomMailboxService::new(store);
    service
        .deposit(
            room(46),
            &[reader(7)],
            &Payload::of("{\"old\":true}"),
            1000.0,
        )
        .unwrap();
    assert!(service
        .collect(room(46), reader(7), 1000.0 + 604_801.0)
        .unwrap()
        .is_empty());
}

pub fn a_full_queue_keeps_the_newest(store: Arc<dyn RoomMailbox>) {
    let depth = 1000usize;
    let service = RoomMailboxService::new(store);
    for n in 0..(depth + 3) {
        service
            .deposit(
                room(47),
                &[reader(7)],
                &Payload::of(&format!("{{\"n\":{n}}}")),
                1000.0,
            )
            .unwrap();
    }
    let collected = service.collect(room(47), reader(7), 1000.0).unwrap();
    assert_eq!(collected.len(), depth);
    assert_eq!(collected[0], format!("{{\"n\":{}}}", 3));
    assert_eq!(collected[depth - 1], format!("{{\"n\":{}}}", depth + 2));
}

pub fn sweeping_removes_only_stale_entries(store: Arc<dyn RoomMailbox>) {
    let service = RoomMailboxService::new(store);
    service
        .deposit(
            room(48),
            &[reader(7)],
            &Payload::of("{\"old\":true}"),
            1000.0,
        )
        .unwrap();
    service
        .deposit(
            room(48),
            &[reader(7)],
            &Payload::of("{\"new\":true}"),
            1000.0 + 604_800.0,
        )
        .unwrap();
    assert_eq!(service.sweep(1000.0 + 604_801.0).unwrap(), 1);
    assert_eq!(
        service
            .collect(room(48), reader(7), 1000.0 + 604_801.0)
            .unwrap(),
        vec!["{\"new\":true}".to_owned()]
    );
}

pub fn a_collected_queue_stops_being_counted(store: Arc<dyn RoomMailbox>) {
    let service = RoomMailboxService::new(store);
    service
        .deposit(
            room(49),
            &[reader(31), reader(32)],
            &Payload::of("{\"c\":1}"),
            1000.0,
        )
        .unwrap();
    assert_eq!(service.tally().unwrap(), (2, 2));
    service.collect(room(49), reader(31), 1000.0).unwrap();
    assert_eq!(
        service.tally().unwrap(),
        (1, 1),
        "выбранная очередь не должна числиться ни в счёте очередей, ни в счёте сообщений"
    );
    service.collect(room(49), reader(32), 1000.0).unwrap();
    assert_eq!(service.tally().unwrap(), (0, 0));
}

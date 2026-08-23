use std::sync::Arc;

use vortex_auth::account::user_id::UserId;

use crate::mailbox::notification::service::NotificationMailboxService;
use crate::message::payload::Payload;
use crate::ports::notification_mailbox::NotificationMailbox;

fn reader(value: i64) -> UserId {
    UserId::of(value).expect("номер учётной записи положителен")
}

pub fn a_deposited_notification_is_collected_once(store: Arc<dyn NotificationMailbox>) {
    let service = NotificationMailboxService::new(store);
    service
        .deposit(reader(21), &Payload::of("{\"n\":1}"), 1000.0)
        .unwrap();
    assert_eq!(
        service.collect(reader(21), 1000.0).unwrap(),
        vec!["{\"n\":1}".to_owned()]
    );
    assert!(service.collect(reader(21), 1000.0).unwrap().is_empty());
}

pub fn order_of_deposit_is_the_order_of_collection(store: Arc<dyn NotificationMailbox>) {
    let service = NotificationMailboxService::new(store);
    for n in 0..3 {
        service
            .deposit(
                reader(22),
                &Payload::of(&format!("{{\"n\":{n}}}")),
                1000.0 + n as f64,
            )
            .unwrap();
    }
    assert_eq!(
        service.collect(reader(22), 1005.0).unwrap(),
        vec![
            "{\"n\":0}".to_owned(),
            "{\"n\":1}".to_owned(),
            "{\"n\":2}".to_owned(),
        ]
    );
}

pub fn a_reader_sees_only_their_own_queue(store: Arc<dyn NotificationMailbox>) {
    let service = NotificationMailboxService::new(store);
    service
        .deposit(reader(23), &Payload::of("{\"mine\":true}"), 1000.0)
        .unwrap();
    assert!(service.collect(reader(24), 1000.0).unwrap().is_empty());
    assert_eq!(
        service.collect(reader(23), 1000.0).unwrap(),
        vec!["{\"mine\":true}".to_owned()]
    );
}

pub fn a_stale_notification_is_not_handed_over(store: Arc<dyn NotificationMailbox>) {
    let service = NotificationMailboxService::new(store);
    service
        .deposit(reader(25), &Payload::of("{\"old\":true}"), 1000.0)
        .unwrap();
    assert!(service
        .collect(reader(25), 1000.0 + 301.0)
        .unwrap()
        .is_empty());
}

pub fn a_full_queue_keeps_the_newest(store: Arc<dyn NotificationMailbox>) {
    let depth = 50usize;
    let service = NotificationMailboxService::new(store);
    for n in 0..(depth + 2) {
        service
            .deposit(reader(26), &Payload::of(&format!("{{\"n\":{n}}}")), 1000.0)
            .unwrap();
    }
    let collected = service.collect(reader(26), 1000.0).unwrap();
    assert_eq!(collected.len(), depth);
    assert_eq!(collected[0], format!("{{\"n\":{}}}", 2));
    assert_eq!(collected[depth - 1], format!("{{\"n\":{}}}", depth + 1));
}

pub fn a_collected_queue_stops_being_counted(store: Arc<dyn NotificationMailbox>) {
    let service = NotificationMailboxService::new(store);
    service
        .deposit(reader(27), &Payload::of("{\"c\":1}"), 1000.0)
        .unwrap();
    service
        .deposit(reader(28), &Payload::of("{\"c\":2}"), 1000.0)
        .unwrap();
    assert_eq!(service.tally().unwrap(), (2, 2));
    service.collect(reader(27), 1000.0).unwrap();
    assert_eq!(
        service.tally().unwrap(),
        (1, 1),
        "выбранная очередь не должна числиться ни в счёте очередей, ни в счёте сообщений"
    );
}

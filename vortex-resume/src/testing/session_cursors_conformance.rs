use std::sync::Arc;

use crate::cursor::identifier::ClientKey;
use crate::cursor::limits;
use crate::cursor::service::SessionCursorService;
use crate::ports::session_cursors::SessionCursors;

fn key(value: &str) -> ClientKey {
    ClientKey::parse(value).unwrap()
}

pub fn a_saved_cursor_is_read_back(store: Arc<dyn SessionCursors>) {
    let service = SessionCursorService::new(store);
    service.save(key("alpha"), 17.5, &[3, 1], 1000.0).unwrap();
    let found = service.find(&key("alpha"), 1000.0).unwrap().unwrap();
    assert_eq!(found.mailbox_stamp(), 17.5);
    assert_eq!(found.rooms(), &[1, 3]);
    assert_eq!(found.saved_at(), 1000.0);
}

pub fn an_unknown_client_names_no_cursor(store: Arc<dyn SessionCursors>) {
    let service = SessionCursorService::new(store);
    assert!(service.find(&key("absent"), 1000.0).unwrap().is_none());
}

pub fn a_later_save_replaces_the_earlier_one(store: Arc<dyn SessionCursors>) {
    let service = SessionCursorService::new(store);
    let before = service.count().unwrap();
    service.save(key("beta"), 1.0, &[1], 1000.0).unwrap();
    service.save(key("beta"), 2.0, &[2], 1001.0).unwrap();
    let found = service.find(&key("beta"), 1001.0).unwrap().unwrap();
    assert_eq!(found.mailbox_stamp(), 2.0);
    assert_eq!(found.rooms(), &[2]);
    assert_eq!(service.count().unwrap(), before + 1);
}

pub fn clients_do_not_shadow_each_other(store: Arc<dyn SessionCursors>) {
    let service = SessionCursorService::new(store);
    let before = service.count().unwrap();
    service.save(key("left"), 1.0, &[1], 1000.0).unwrap();
    service.save(key("right"), 2.0, &[2], 1000.0).unwrap();
    assert_eq!(
        service
            .find(&key("left"), 1000.0)
            .unwrap()
            .unwrap()
            .mailbox_stamp(),
        1.0
    );
    assert_eq!(
        service
            .find(&key("right"), 1000.0)
            .unwrap()
            .unwrap()
            .mailbox_stamp(),
        2.0
    );
    assert_eq!(service.count().unwrap(), before + 2);
}

pub fn a_cursor_past_its_lifetime_is_gone(store: Arc<dyn SessionCursors>) {
    let service = SessionCursorService::new(store);
    let before = service.count().unwrap();
    service.save(key("gamma"), 1.0, &[1], 1000.0).unwrap();
    assert_eq!(service.count().unwrap(), before + 1);
    let past = 1000.0 + limits::CURSOR_LIFETIME_SECONDS;
    assert!(service.find(&key("gamma"), past).unwrap().is_none());
    assert_eq!(service.count().unwrap(), before);
}

pub fn a_forgotten_cursor_is_gone(store: Arc<dyn SessionCursors>) {
    let service = SessionCursorService::new(store);
    service.save(key("delta"), 1.0, &[1], 1000.0).unwrap();
    assert!(service.forget(&key("delta")).unwrap());
    assert!(!service.forget(&key("delta")).unwrap());
    assert!(service.find(&key("delta"), 1000.0).unwrap().is_none());
}

pub fn rooms_are_stored_sorted_and_without_repeats(store: Arc<dyn SessionCursors>) {
    let service = SessionCursorService::new(store);
    service
        .save(key("epsilon"), 1.0, &[9, 3, 9, 1], 1000.0)
        .unwrap();
    let found = service.find(&key("epsilon"), 1000.0).unwrap().unwrap();
    assert_eq!(found.rooms(), &[1, 3, 9]);
}

pub fn a_stamp_before_the_epoch_settles_at_zero(store: Arc<dyn SessionCursors>) {
    let service = SessionCursorService::new(store);
    service.save(key("zeta"), -5.0, &[], 1000.0).unwrap();
    let found = service.find(&key("zeta"), 1000.0).unwrap().unwrap();
    assert_eq!(found.mailbox_stamp(), 0.0);
    assert!(found.rooms().is_empty());
}

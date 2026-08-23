use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;

use crate::identity::person::Person;
use crate::ports::stream_donations::StreamDonations;
use crate::stream::donation::Donation;
use crate::testing::{blink, until, BASE, BLINK, BLINK_MILLIS};
use vortex_core::room::room_id::RoomId;

pub type StreamDonationsFactory = dyn Fn() -> Arc<dyn StreamDonations>;

fn room() -> RoomId {
    RoomId::of(1).expect("номер комнаты положителен")
}

fn donation(amount: &str) -> Donation {
    Donation::from(
        &Person::of(8, "bob", None, None, None),
        amount,
        "RUB",
        "спасибо",
        "2026-08-04T09:15:30+00:00".to_owned(),
    )
}

pub fn check_all(make: &StreamDonationsFactory) {
    a_stream_nobody_paid_has_no_donations(make);
    donations_are_kept_in_the_order_they_came(make);
    clearing_forgets_every_donation(make);
    a_log_nobody_renews_disappears(make);
}

pub fn a_stream_nobody_paid_has_no_donations(make: &StreamDonationsFactory) {
    let log = make();
    assert!(log.list(room(), BASE).unwrap().is_empty());
    assert!(!log.renew(room(), until(BASE), BASE).unwrap());
}

pub fn donations_are_kept_in_the_order_they_came(make: &StreamDonationsFactory) {
    let log = make();
    log.add(room(), &donation("100"), until(BASE), BASE)
        .unwrap();
    log.add(room(), &donation("500"), until(BASE), BASE)
        .unwrap();

    let kept = log.list(room(), BASE).unwrap();
    assert_eq!(kept.len(), 2);
    assert_eq!(kept[0].amount, "100");
    assert_eq!(kept[1].amount, "500");
}

pub fn clearing_forgets_every_donation(make: &StreamDonationsFactory) {
    let log = make();
    log.add(room(), &donation("100"), until(BASE), BASE)
        .unwrap();
    log.clear(room(), BASE).unwrap();
    assert!(log.list(room(), BASE).unwrap().is_empty());
}

pub fn a_log_nobody_renews_disappears(make: &StreamDonationsFactory) {
    let log = make();
    log.add(room(), &donation("100"), blink(BASE), BASE)
        .unwrap();
    sleep(Duration::from_millis(BLINK_MILLIS));
    assert!(log.list(room(), BASE + BLINK).unwrap().is_empty());
}

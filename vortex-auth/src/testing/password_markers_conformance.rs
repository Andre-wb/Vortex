use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;

use crate::account::user_id::UserId;
use crate::ports::password_markers::PasswordMarkers;
use crate::token::ttl::Ttl;

pub type MarkersFactory = dyn Fn() -> Arc<dyn PasswordMarkers>;

const BASE: f64 = 1_000.0;

fn user(value: i64) -> UserId {
    UserId::of(value).expect("номер учётной записи в наборе соответствия должен быть валиден")
}

fn five_minutes() -> Ttl {
    Ttl::seconds(300).expect("пять минут — ненулевое время жизни")
}

pub fn check_all(make: &MarkersFactory) {
    an_account_nobody_marked_is_not_armed(make);
    an_armed_marker_is_seen(make);
    peeking_twice_does_not_burn_the_marker(make);
    a_burned_marker_is_gone(make);
    two_accounts_never_answer_for_each_other(make);
    a_marker_disappears_when_its_window_closes(make);
}

pub fn an_account_nobody_marked_is_not_armed(make: &MarkersFactory) {
    let markers = make();
    assert!(!markers.armed(user(4_100), BASE));
}

pub fn an_armed_marker_is_seen(make: &MarkersFactory) {
    let markers = make();
    markers.arm(user(4_101), five_minutes(), BASE).unwrap();
    assert!(markers.armed(user(4_101), BASE));
}

pub fn peeking_twice_does_not_burn_the_marker(make: &MarkersFactory) {
    let markers = make();
    markers.arm(user(4_102), five_minutes(), BASE).unwrap();
    assert!(markers.armed(user(4_102), BASE));
    assert!(markers.armed(user(4_102), BASE));
}

pub fn a_burned_marker_is_gone(make: &MarkersFactory) {
    let markers = make();
    markers.arm(user(4_103), five_minutes(), BASE).unwrap();
    markers.disarm(user(4_103)).unwrap();
    assert!(!markers.armed(user(4_103), BASE));
}

pub fn two_accounts_never_answer_for_each_other(make: &MarkersFactory) {
    let markers = make();
    markers.arm(user(4_104), five_minutes(), BASE).unwrap();
    assert!(markers.armed(user(4_104), BASE));
    assert!(!markers.armed(user(4_105), BASE));
}

pub fn a_marker_disappears_when_its_window_closes(make: &MarkersFactory) {
    let markers = make();
    markers
        .arm(user(4_106), Ttl::seconds(1).unwrap(), BASE)
        .unwrap();
    sleep(Duration::from_millis(1_500));
    assert!(!markers.armed(user(4_106), BASE + 1.5));
}

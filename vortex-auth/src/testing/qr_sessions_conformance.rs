use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;

use crate::account::user_id::UserId;
use crate::challenge::id::ChallengeId;
use crate::ports::qr_sessions::QrSessions;
use crate::qr::confirmation::Confirmation;
use crate::qr::handover::Handover;
use crate::qr::record::QrSession;
use crate::qr::session_id::QrSessionId;
use crate::token::ttl::Ttl;

pub type QrSessionsFactory = dyn Fn() -> Arc<dyn QrSessions>;

const BASE: f64 = 1_000.0;

fn session(value: &str) -> QrSessionId {
    QrSessionId::parse(value).expect("сессия в наборе соответствия должна быть валидна")
}

fn record() -> QrSession {
    QrSession::pending(
        ChallengeId::parse("0123456789abcdef0123456789abcdef").expect("челлендж валиден"),
    )
}

fn user() -> UserId {
    UserId::of(7).expect("номер учётной записи положителен")
}

fn minute() -> Ttl {
    Ttl::seconds(60).expect("минута — ненулевое время жизни")
}

pub fn check_all(make: &QrSessionsFactory) {
    a_session_nobody_opened_is_missing_everywhere(make);
    an_opened_session_is_found_pending(make);
    a_pending_session_is_not_handed_over(make);
    a_session_is_confirmed_once(make);
    a_confirmed_session_is_handed_over_once(make);
    confirming_keeps_the_challenge_the_session_was_opened_with(make);
    a_session_disappears_when_its_lifetime_runs_out(make);
}

pub fn a_session_nobody_opened_is_missing_everywhere(make: &QrSessionsFactory) {
    let store = make();
    assert_eq!(store.find(&session("never-opened"), BASE).unwrap(), None);
    assert_eq!(
        store
            .confirm(&session("never-opened"), user(), BASE)
            .unwrap(),
        Confirmation::Missing
    );
    assert_eq!(
        store.hand_over(&session("never-opened"), BASE).unwrap(),
        Handover::Missing
    );
}

pub fn an_opened_session_is_found_pending(make: &QrSessionsFactory) {
    let store = make();
    store
        .open(&session("opened"), &record(), minute(), BASE)
        .unwrap();
    assert_eq!(
        store.find(&session("opened"), BASE).unwrap(),
        Some(record())
    );
}

pub fn a_pending_session_is_not_handed_over(make: &QrSessionsFactory) {
    let store = make();
    store
        .open(&session("pending"), &record(), minute(), BASE)
        .unwrap();
    assert_eq!(
        store.hand_over(&session("pending"), BASE).unwrap(),
        Handover::Pending
    );
}

pub fn a_session_is_confirmed_once(make: &QrSessionsFactory) {
    let store = make();
    store
        .open(&session("confirmed"), &record(), minute(), BASE)
        .unwrap();
    assert_eq!(
        store.confirm(&session("confirmed"), user(), BASE).unwrap(),
        Confirmation::Confirmed
    );
    assert_eq!(
        store.confirm(&session("confirmed"), user(), BASE).unwrap(),
        Confirmation::AlreadyConfirmed
    );
}

pub fn a_confirmed_session_is_handed_over_once(make: &QrSessionsFactory) {
    let store = make();
    store
        .open(&session("handed"), &record(), minute(), BASE)
        .unwrap();
    store.confirm(&session("handed"), user(), BASE).unwrap();

    assert_eq!(
        store.hand_over(&session("handed"), BASE).unwrap(),
        Handover::Taken(user())
    );
    assert_eq!(
        store.hand_over(&session("handed"), BASE).unwrap(),
        Handover::Missing
    );
}

pub fn confirming_keeps_the_challenge_the_session_was_opened_with(make: &QrSessionsFactory) {
    let store = make();
    store
        .open(&session("kept"), &record(), minute(), BASE)
        .unwrap();
    store.confirm(&session("kept"), user(), BASE).unwrap();

    let found = store.find(&session("kept"), BASE).unwrap().unwrap();
    assert_eq!(found.challenge(), record().challenge());
    assert_eq!(found.state().confirmed_by(), Some(user()));
}

pub fn a_session_disappears_when_its_lifetime_runs_out(make: &QrSessionsFactory) {
    let store = make();
    store
        .open(&session("short"), &record(), Ttl::seconds(1).unwrap(), BASE)
        .unwrap();
    sleep(Duration::from_millis(1_100));
    assert_eq!(store.find(&session("short"), BASE + 1.2).unwrap(), None);
}

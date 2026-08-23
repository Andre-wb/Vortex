use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;

use crate::ports::replay::ReplayGuard;
use crate::token::jti::Jti;
use crate::token::ttl::Ttl;

pub type ReplayGuardFactory = dyn Fn() -> Arc<dyn ReplayGuard>;

const BASE: f64 = 1_000.0;

fn jti(value: &str) -> Jti {
    Jti::parse(value).expect("идентификатор токена в наборе соответствия должен быть валиден")
}

fn minute() -> Ttl {
    Ttl::seconds(60).expect("минута — ненулевое время жизни")
}

pub fn check_all(make: &ReplayGuardFactory) {
    a_token_nobody_spent_is_not_seen(make);
    the_first_arrival_is_recorded(make);
    the_second_arrival_of_the_same_token_is_refused(make);
    two_tokens_never_answer_for_each_other(make);
    the_memory_of_a_token_expires(make);
}

pub fn a_token_nobody_spent_is_not_seen(make: &ReplayGuardFactory) {
    let guard = make();
    assert!(!guard.seen(&jti("never-spent"), BASE).unwrap());
}

pub fn the_first_arrival_is_recorded(make: &ReplayGuardFactory) {
    let guard = make();
    let once = jti("spent-once");
    assert!(guard.remember_if_new(&once, minute(), BASE).unwrap());
    assert!(guard.seen(&once, BASE).unwrap());
}

pub fn the_second_arrival_of_the_same_token_is_refused(make: &ReplayGuardFactory) {
    let guard = make();
    let twice = jti("spent-twice");
    assert!(guard.remember_if_new(&twice, minute(), BASE).unwrap());
    assert!(!guard.remember_if_new(&twice, minute(), BASE).unwrap());
}

pub fn two_tokens_never_answer_for_each_other(make: &ReplayGuardFactory) {
    let guard = make();
    guard
        .remember_if_new(&jti("spent-token"), minute(), BASE)
        .unwrap();
    assert!(guard.seen(&jti("spent-token"), BASE).unwrap());
    assert!(!guard.seen(&jti("fresh-token"), BASE).unwrap());
}

pub fn the_memory_of_a_token_expires(make: &ReplayGuardFactory) {
    let guard = make();
    let short = jti("spent-for-a-second");
    guard
        .remember_if_new(&short, Ttl::seconds(1).unwrap(), BASE)
        .unwrap();
    sleep(Duration::from_millis(1_100));
    assert!(!guard.seen(&short, BASE + 1.2).unwrap());
    assert!(guard
        .remember_if_new(&short, Ttl::seconds(1).unwrap(), BASE + 1.2)
        .unwrap());
}

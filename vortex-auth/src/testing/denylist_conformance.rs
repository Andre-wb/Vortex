use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;

use crate::ports::denylist::Denylist;
use crate::token::jti::Jti;
use crate::token::ttl::Ttl;

pub type DenylistFactory = dyn Fn() -> Arc<dyn Denylist>;

const BASE: f64 = 1_000.0;

fn jti(value: &str) -> Jti {
    Jti::parse(value).expect("идентификатор токена в наборе соответствия должен быть валиден")
}

fn minute() -> Ttl {
    Ttl::seconds(60).expect("минута — ненулевое время жизни")
}

pub fn check_all(make: &DenylistFactory) {
    a_token_nobody_revoked_is_not_held(make);
    a_revoked_token_is_held(make);
    two_tokens_never_answer_for_each_other(make);
    revoking_the_same_token_twice_is_not_an_error(make);
    a_revocation_disappears_when_the_token_would_have_expired(make);
}

pub fn a_token_nobody_revoked_is_not_held(make: &DenylistFactory) {
    let list = make();
    assert!(!list.holds(&jti("never-revoked"), BASE));
}

pub fn a_revoked_token_is_held(make: &DenylistFactory) {
    let list = make();
    list.remember(&jti("revoked-once"), minute(), BASE).unwrap();
    assert!(list.holds(&jti("revoked-once"), BASE));
}

pub fn two_tokens_never_answer_for_each_other(make: &DenylistFactory) {
    let list = make();
    list.remember(&jti("revoked-token"), minute(), BASE)
        .unwrap();
    assert!(list.holds(&jti("revoked-token"), BASE));
    assert!(!list.holds(&jti("live-token"), BASE));
}

pub fn revoking_the_same_token_twice_is_not_an_error(make: &DenylistFactory) {
    let list = make();
    let repeated = jti("revoked-twice");
    list.remember(&repeated, minute(), BASE).unwrap();
    list.remember(&repeated, minute(), BASE).unwrap();
    assert!(list.holds(&repeated, BASE));
}

pub fn a_revocation_disappears_when_the_token_would_have_expired(make: &DenylistFactory) {
    let list = make();
    let short = jti("revoked-for-a-second");
    list.remember(&short, Ttl::seconds(1).unwrap(), BASE)
        .unwrap();
    sleep(Duration::from_millis(1_500));
    assert!(!list.holds(&short, BASE + 1.5));
}

use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;

use crate::call::call_id::CallId;
use crate::ports::ring_claims::RingClaims;
use crate::testing::{blink, until, BASE, BLINK, BLINK_MILLIS};

pub type RingClaimsFactory = dyn Fn() -> Arc<dyn RingClaims>;

fn call(value: &str) -> CallId {
    CallId::parse(value).expect("идентификатор звонка валиден")
}

pub fn check_all(make: &RingClaimsFactory) {
    a_ring_is_claimed_by_exactly_one_worker(make);
    two_calls_never_share_a_claim(make);
    a_claim_that_expired_may_be_taken_again(make);
}

pub fn a_ring_is_claimed_by_exactly_one_worker(make: &RingClaimsFactory) {
    let claims = make();
    assert!(claims.claim(&call("abcd"), until(BASE), BASE).unwrap());
    assert!(!claims.claim(&call("abcd"), until(BASE), BASE).unwrap());
}

pub fn two_calls_never_share_a_claim(make: &RingClaimsFactory) {
    let claims = make();
    assert!(claims.claim(&call("first"), until(BASE), BASE).unwrap());
    assert!(claims.claim(&call("second"), until(BASE), BASE).unwrap());
}

pub fn a_claim_that_expired_may_be_taken_again(make: &RingClaimsFactory) {
    let claims = make();
    assert!(claims.claim(&call("abcd"), blink(BASE), BASE).unwrap());
    sleep(Duration::from_millis(BLINK_MILLIS));
    assert!(claims
        .claim(&call("abcd"), until(BASE + BLINK), BASE + BLINK)
        .unwrap());
}

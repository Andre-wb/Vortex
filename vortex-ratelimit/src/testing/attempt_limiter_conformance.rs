use std::sync::Arc;

use crate::attempt::limit::Limit;
use crate::attempt::subject::Subject;
use crate::attempt::window::Window;
use crate::ports::attempt_limiter::AttemptLimiter;

pub type LimiterFactory = dyn Fn() -> Arc<dyn AttemptLimiter>;

const BASE: f64 = 1_000.0;
const BUCKET: &str = "entry-attempts";

fn three() -> Limit {
    Limit::of(3).expect("три попытки — ненулевой предел")
}

fn minute() -> Window {
    Window::seconds(60).expect("минута — ненулевое окно")
}

fn subject(member: &str) -> Subject {
    Subject::of(BUCKET, member)
}

pub fn check_all(make: &LimiterFactory) {
    a_subject_nobody_counted_is_allowed(make);
    the_attempt_after_the_limit_is_refused(make);
    a_refused_attempt_does_not_push_the_window_forward(make);
    two_subjects_never_answer_for_each_other(make);
    two_buckets_never_share_one_window(make);
    the_window_slides_forward_with_the_clock(make);
}

pub fn a_subject_nobody_counted_is_allowed(make: &LimiterFactory) {
    let limiter = make();
    assert!(limiter
        .allow(&subject("5100"), three(), minute(), BASE)
        .unwrap());
}

pub fn the_attempt_after_the_limit_is_refused(make: &LimiterFactory) {
    let limiter = make();
    for _ in 0..3 {
        assert!(limiter
            .allow(&subject("5101"), three(), minute(), BASE)
            .unwrap());
    }
    assert!(!limiter
        .allow(&subject("5101"), three(), minute(), BASE)
        .unwrap());
}

pub fn a_refused_attempt_does_not_push_the_window_forward(make: &LimiterFactory) {
    let limiter = make();
    for _ in 0..3 {
        limiter
            .allow(&subject("5102"), three(), minute(), BASE)
            .unwrap();
    }
    assert!(!limiter
        .allow(&subject("5102"), three(), minute(), BASE + 30.0)
        .unwrap());
    assert!(limiter
        .allow(&subject("5102"), three(), minute(), BASE + 60.0)
        .unwrap());
}

pub fn two_subjects_never_answer_for_each_other(make: &LimiterFactory) {
    let limiter = make();
    for _ in 0..3 {
        limiter
            .allow(&subject("5103"), three(), minute(), BASE)
            .unwrap();
    }
    assert!(!limiter
        .allow(&subject("5103"), three(), minute(), BASE)
        .unwrap());
    assert!(limiter
        .allow(&subject("5104"), three(), minute(), BASE)
        .unwrap());
}

pub fn two_buckets_never_share_one_window(make: &LimiterFactory) {
    let limiter = make();
    for _ in 0..3 {
        limiter
            .allow(&Subject::of(BUCKET, "5105"), three(), minute(), BASE)
            .unwrap();
    }
    assert!(limiter
        .allow(
            &Subject::of("totp-attempts", "5105"),
            three(),
            minute(),
            BASE
        )
        .unwrap());
}

pub fn the_window_slides_forward_with_the_clock(make: &LimiterFactory) {
    let limiter = make();
    for _ in 0..3 {
        limiter
            .allow(&subject("5106"), three(), minute(), BASE)
            .unwrap();
    }
    assert!(!limiter
        .allow(&subject("5106"), three(), minute(), BASE + 59.0)
        .unwrap());
    assert!(limiter
        .allow(&subject("5106"), three(), minute(), BASE + 60.0)
        .unwrap());
}

use std::sync::Arc;

use crate::attempt::limit::Limit;
use crate::attempt::subject::Subject;
use crate::attempt::window::Window;
use crate::ports::attempt_limiter::AttemptLimiter;
use crate::ports::window_reset::WindowReset;

pub type WindowFactory = dyn Fn() -> (Arc<dyn AttemptLimiter>, Arc<dyn WindowReset>);

const BASE: f64 = 1_000.0;
const BUCKET: &str = "flood-window";

fn three() -> Limit {
    Limit::of(3).expect("три сообщения — ненулевой предел")
}

fn ten_seconds() -> Window {
    Window::seconds(10).expect("десять секунд — ненулевое окно")
}

fn membership(member: &str) -> Subject {
    Subject::of(BUCKET, member)
}

pub fn check_all(make: &WindowFactory) {
    a_forgotten_window_starts_from_scratch(make);
    forgetting_one_window_leaves_every_other_counted(make);
    forgetting_a_window_nobody_counted_is_not_an_error(make);
}

pub fn a_forgotten_window_starts_from_scratch(make: &WindowFactory) {
    let (limiter, reset) = make();
    for _ in 0..3 {
        assert!(limiter
            .allow(&membership("6200:1"), three(), ten_seconds(), BASE)
            .unwrap());
    }
    assert!(!limiter
        .allow(&membership("6200:1"), three(), ten_seconds(), BASE)
        .unwrap());
    reset.forget(&membership("6200:1")).unwrap();
    assert!(limiter
        .allow(&membership("6200:1"), three(), ten_seconds(), BASE)
        .unwrap());
}

pub fn forgetting_one_window_leaves_every_other_counted(make: &WindowFactory) {
    let (limiter, reset) = make();
    for _ in 0..3 {
        limiter
            .allow(&membership("6201:1"), three(), ten_seconds(), BASE)
            .unwrap();
        limiter
            .allow(&membership("6201:2"), three(), ten_seconds(), BASE)
            .unwrap();
    }
    reset.forget(&membership("6201:1")).unwrap();
    assert!(!limiter
        .allow(&membership("6201:2"), three(), ten_seconds(), BASE)
        .unwrap());
}

pub fn forgetting_a_window_nobody_counted_is_not_an_error(make: &WindowFactory) {
    let (_, reset) = make();
    reset.forget(&membership("6202:1")).unwrap();
}

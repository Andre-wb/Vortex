//! Общий контракт истории обращений: прогоняется и по памяти, и по Redis.

use std::sync::Arc;

use crate::domain::client_ip::ClientIp;
use crate::domain::timestamp::Timestamp;
use crate::ports::request_history::RequestHistory;

pub const NOW_SECS: i64 = 1_700_000_000;
pub const WINDOW_SECS: u64 = 60;

pub type HistoryFactory = dyn Fn() -> Arc<dyn RequestHistory>;

fn ip(value: &str) -> ClientIp {
    ClientIp::new(value)
}

fn at(offset_secs: i64) -> Timestamp {
    Timestamp::from_unix_secs(NOW_SECS + offset_secs)
}

pub fn check_all(make: &HistoryFactory) {
    requests_under_the_limit_are_recorded(make);
    the_request_after_the_limit_is_reported_with_the_wait(make);
    a_refused_request_is_not_recorded(make);
    the_window_slides_forward_with_the_clock(make);
    clients_do_not_share_their_history(make);
    the_window_counts_only_recent_requests(make);
    stale_clients_are_forgotten(make);
}

pub fn requests_under_the_limit_are_recorded(make: &HistoryFactory) {
    let history = make();
    for _ in 0..3 {
        assert!(history
            .register(&ip("1.1.1.1"), at(0), 3, WINDOW_SECS)
            .is_none());
    }
    assert_eq!(
        history.hits_in_window(&ip("1.1.1.1"), at(0), WINDOW_SECS),
        3
    );
}

pub fn the_request_after_the_limit_is_reported_with_the_wait(make: &HistoryFactory) {
    let history = make();
    for _ in 0..3 {
        history.register(&ip("1.1.1.2"), at(0), 3, WINDOW_SECS);
    }
    let refused = history.register(&ip("1.1.1.2"), at(10), 3, WINDOW_SECS);
    let (hits, wait) = refused.expect("превышение лимита должно быть замечено");
    assert_eq!(hits, 3);
    assert!((wait - 50.0).abs() < 0.001, "ожидание {wait} вместо 50");
}

pub fn a_refused_request_is_not_recorded(make: &HistoryFactory) {
    let history = make();
    for _ in 0..3 {
        history.register(&ip("1.1.1.3"), at(0), 3, WINDOW_SECS);
    }
    history.register(&ip("1.1.1.3"), at(0), 3, WINDOW_SECS);
    assert_eq!(
        history.hits_in_window(&ip("1.1.1.3"), at(0), WINDOW_SECS),
        3
    );
}

pub fn the_window_slides_forward_with_the_clock(make: &HistoryFactory) {
    let history = make();
    for _ in 0..3 {
        history.register(&ip("1.1.1.4"), at(0), 3, WINDOW_SECS);
    }
    assert!(history
        .register(&ip("1.1.1.4"), at(59), 3, WINDOW_SECS)
        .is_some());
    assert!(history
        .register(&ip("1.1.1.4"), at(61), 3, WINDOW_SECS)
        .is_none());
}

pub fn clients_do_not_share_their_history(make: &HistoryFactory) {
    let history = make();
    for _ in 0..3 {
        history.register(&ip("1.1.1.5"), at(0), 3, WINDOW_SECS);
    }
    assert!(history
        .register(&ip("1.1.1.5"), at(0), 3, WINDOW_SECS)
        .is_some());
    assert!(history
        .register(&ip("1.1.1.6"), at(0), 3, WINDOW_SECS)
        .is_none());
}

pub fn the_window_counts_only_recent_requests(make: &HistoryFactory) {
    let history = make();
    history.register(&ip("1.1.1.7"), at(0), 10, WINDOW_SECS);
    assert_eq!(
        history.hits_in_window(&ip("1.1.1.7"), at(59), WINDOW_SECS),
        1
    );
    assert_eq!(
        history.hits_in_window(&ip("1.1.1.7"), at(61), WINDOW_SECS),
        0
    );
}

pub fn stale_clients_are_forgotten(make: &HistoryFactory) {
    let history = make();
    history.register(&ip("1.1.1.8"), at(0), 10, WINDOW_SECS);
    assert_eq!(history.tracked_clients(), 1);
    assert_eq!(history.forget_stale(at(121), WINDOW_SECS * 2), 1);
    assert_eq!(history.tracked_clients(), 0);
}

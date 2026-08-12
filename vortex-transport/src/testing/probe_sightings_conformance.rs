use std::sync::Arc;

use crate::ports::probe_sightings::ProbeSightings;

pub type SightingsFactory = dyn Fn(usize, f64) -> Arc<dyn ProbeSightings>;

pub const ROOM: usize = 1000;
pub const MEMORY: f64 = 300.0;

pub fn check_all(make: &SightingsFactory) {
    a_request_seen_for_the_first_time_has_no_moment_before_it(make);
    the_same_request_seen_again_reports_when_it_was_seen_before(make);
    the_moment_reported_is_the_last_one_and_not_the_first(make);
    two_different_requests_never_answer_for_each_other(make);
    a_store_nobody_wrote_to_is_empty(make);
    what_is_older_than_the_cutoff_is_forgotten(make);
    what_is_newer_than_the_cutoff_is_kept(make);
    forgetting_an_empty_store_is_not_an_error(make);
    a_request_remembered_again_after_it_was_forgotten_looks_new(make);
    the_store_never_grows_past_the_room_it_was_given(make);
}

pub fn a_request_seen_for_the_first_time_has_no_moment_before_it(make: &SightingsFactory) {
    let seen = make(ROOM, MEMORY);
    assert_eq!(seen.remember("aaaa", 1000.0), None);
    assert_eq!(seen.len(), 1);
}

pub fn the_same_request_seen_again_reports_when_it_was_seen_before(make: &SightingsFactory) {
    let seen = make(ROOM, MEMORY);
    seen.remember("aaaa", 1000.0);
    assert_eq!(seen.remember("aaaa", 1000.5), Some(1000.0));
}

pub fn the_moment_reported_is_the_last_one_and_not_the_first(make: &SightingsFactory) {
    let seen = make(ROOM, MEMORY);
    seen.remember("aaaa", 1000.0);
    seen.remember("aaaa", 1001.0);
    assert_eq!(seen.remember("aaaa", 1002.0), Some(1001.0));
}

pub fn two_different_requests_never_answer_for_each_other(make: &SightingsFactory) {
    let seen = make(ROOM, MEMORY);
    seen.remember("aaaa", 1000.0);
    assert_eq!(seen.remember("bbbb", 1001.0), None);
    assert_eq!(seen.remember("aaaa", 1002.0), Some(1000.0));
    assert_eq!(seen.len(), 2);
}

pub fn a_store_nobody_wrote_to_is_empty(make: &SightingsFactory) {
    let seen = make(ROOM, MEMORY);
    assert_eq!(seen.len(), 0);
    assert!(seen.is_empty());
}

pub fn what_is_older_than_the_cutoff_is_forgotten(make: &SightingsFactory) {
    let seen = make(ROOM, MEMORY);
    seen.remember("aaaa", 1000.0);
    seen.forget_stale(1000.0);
    assert!(seen.is_empty());
    assert_eq!(seen.remember("aaaa", 1500.0), None);
}

pub fn what_is_newer_than_the_cutoff_is_kept(make: &SightingsFactory) {
    let seen = make(ROOM, MEMORY);
    seen.remember("aaaa", 1000.0);
    seen.remember("bbbb", 2000.0);
    seen.forget_stale(1500.0);
    assert_eq!(seen.len(), 1);
    assert_eq!(seen.remember("bbbb", 2001.0), Some(2000.0));
}

pub fn forgetting_an_empty_store_is_not_an_error(make: &SightingsFactory) {
    let seen = make(ROOM, MEMORY);
    seen.forget_stale(1000.0);
    assert!(seen.is_empty());
}

pub fn a_request_remembered_again_after_it_was_forgotten_looks_new(make: &SightingsFactory) {
    let seen = make(ROOM, MEMORY);
    seen.remember("aaaa", 1000.0);
    seen.forget_stale(1500.0);
    assert_eq!(seen.remember("aaaa", 1600.0), None);
    assert_eq!(seen.remember("aaaa", 1600.5), Some(1600.0));
}

pub fn the_store_never_grows_past_the_room_it_was_given(make: &SightingsFactory) {
    let room = 16;
    let memory = 10.0;
    let seen = make(room, memory);
    for tick in 0..400 {
        seen.remember(&format!("fp{tick:04}"), 5000.0 + tick as f64);
    }
    assert!(
        seen.len() <= room * 2,
        "хранилище выросло до {} при пределе {room}",
        seen.len()
    );
}

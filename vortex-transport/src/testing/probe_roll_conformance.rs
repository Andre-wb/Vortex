use std::sync::Arc;

use crate::ports::probe_roll::ProbeRoll;

pub type RollFactory = dyn Fn(usize, f64) -> Arc<dyn ProbeRoll>;

pub const ROOM: usize = 1000;
pub const MEMORY: f64 = 86_400.0;

pub fn check_all(make: &RollFactory) {
    a_peer_recorded_once_is_known_afterwards(make);
    recording_the_same_peer_twice_does_not_count_it_twice(make);
    a_peer_nobody_recorded_is_not_known(make);
    a_roll_nobody_wrote_to_is_empty(make);
    what_is_older_than_the_cutoff_is_forgotten(make);
    what_is_newer_than_the_cutoff_is_kept(make);
    a_peer_recorded_again_after_it_was_forgotten_looks_new(make);
    two_peers_never_answer_for_each_other(make);
    the_roll_never_grows_past_the_room_it_was_given(make);
}

pub fn a_peer_recorded_once_is_known_afterwards(make: &RollFactory) {
    let roll = make(ROOM, MEMORY);
    assert!(roll.record("203.0.113.7", 1000.0));
    assert!(roll.holds("203.0.113.7"));
    assert_eq!(roll.len(), 1);
}

pub fn recording_the_same_peer_twice_does_not_count_it_twice(make: &RollFactory) {
    let roll = make(ROOM, MEMORY);
    assert!(roll.record("203.0.113.7", 1000.0));
    assert!(!roll.record("203.0.113.7", 2000.0));
    assert_eq!(roll.len(), 1);
}

pub fn a_peer_nobody_recorded_is_not_known(make: &RollFactory) {
    let roll = make(ROOM, MEMORY);
    roll.record("203.0.113.7", 1000.0);
    assert!(!roll.holds("203.0.113.8"));
}

pub fn a_roll_nobody_wrote_to_is_empty(make: &RollFactory) {
    let roll = make(ROOM, MEMORY);
    assert!(roll.is_empty());
    assert_eq!(roll.len(), 0);
}

pub fn what_is_older_than_the_cutoff_is_forgotten(make: &RollFactory) {
    let roll = make(ROOM, MEMORY);
    roll.record("203.0.113.7", 1000.0);
    roll.forget_stale(1000.0);
    assert!(!roll.holds("203.0.113.7"));
    assert!(roll.is_empty());
}

pub fn what_is_newer_than_the_cutoff_is_kept(make: &RollFactory) {
    let roll = make(ROOM, MEMORY);
    roll.record("203.0.113.7", 1000.0);
    roll.record("203.0.113.8", 2000.0);
    roll.forget_stale(1500.0);
    assert!(!roll.holds("203.0.113.7"));
    assert!(roll.holds("203.0.113.8"));
    assert_eq!(roll.len(), 1);
}

pub fn a_peer_recorded_again_after_it_was_forgotten_looks_new(make: &RollFactory) {
    let roll = make(ROOM, MEMORY);
    roll.record("203.0.113.7", 1000.0);
    roll.forget_stale(1500.0);
    assert!(roll.record("203.0.113.7", 1600.0));
}

pub fn two_peers_never_answer_for_each_other(make: &RollFactory) {
    let roll = make(ROOM, MEMORY);
    roll.record("203.0.113.7", 1000.0);
    roll.record("2001:db8::1", 1000.0);
    assert!(roll.holds("203.0.113.7"));
    assert!(roll.holds("2001:db8::1"));
    assert!(!roll.holds("203.0.113.9"));
    assert_eq!(roll.len(), 2);
}

pub fn the_roll_never_grows_past_the_room_it_was_given(make: &RollFactory) {
    let room = 16;
    let roll = make(room, MEMORY);
    for tick in 0..400 {
        roll.record(&format!("198.51.100.{tick}"), 5000.0 + tick as f64);
    }
    assert!(
        roll.len() <= room * 2,
        "список вырос до {} при пределе {room}",
        roll.len()
    );
}

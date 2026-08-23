use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;

use crate::ports::stream_tally::StreamTally;
use crate::testing::{blink, until, BASE, BLINK, BLINK_MILLIS};
use vortex_core::room::room_id::RoomId;

pub type StreamTallyFactory = dyn Fn() -> Arc<dyn StreamTally>;

fn room() -> RoomId {
    RoomId::of(1).expect("номер комнаты положителен")
}

pub fn check_all(make: &StreamTallyFactory) {
    a_stream_nobody_reacted_to_counts_nothing(make);
    reactions_are_counted_by_emoji(make);
    the_peak_only_ever_grows(make);
    clearing_forgets_every_count(make);
    a_tally_nobody_renews_disappears(make);
}

pub fn a_stream_nobody_reacted_to_counts_nothing(make: &StreamTallyFactory) {
    let tally = make();
    assert!(tally.reactions(room(), BASE).unwrap().is_empty());
    assert_eq!(tally.peak(room(), BASE).unwrap(), 0);
    assert!(!tally.renew(room(), until(BASE), BASE).unwrap());
}

pub fn reactions_are_counted_by_emoji(make: &StreamTallyFactory) {
    let tally = make();
    tally
        .count_reaction(room(), "\u{2764}", until(BASE), BASE)
        .unwrap();
    tally
        .count_reaction(room(), "\u{2764}", until(BASE), BASE)
        .unwrap();
    tally
        .count_reaction(room(), "\u{1f525}", until(BASE), BASE)
        .unwrap();

    let counted = tally.reactions(room(), BASE).unwrap();
    assert_eq!(counted["\u{2764}"], 2);
    assert_eq!(counted["\u{1f525}"], 1);
}

pub fn the_peak_only_ever_grows(make: &StreamTallyFactory) {
    let tally = make();
    assert_eq!(tally.raise_peak(room(), 3, until(BASE), BASE).unwrap(), 3);
    assert_eq!(tally.raise_peak(room(), 5, until(BASE), BASE).unwrap(), 5);
    assert_eq!(tally.raise_peak(room(), 2, until(BASE), BASE).unwrap(), 5);
    assert_eq!(tally.peak(room(), BASE).unwrap(), 5);
}

pub fn clearing_forgets_every_count(make: &StreamTallyFactory) {
    let tally = make();
    tally
        .count_reaction(room(), "\u{2764}", until(BASE), BASE)
        .unwrap();
    tally.raise_peak(room(), 5, until(BASE), BASE).unwrap();

    tally.clear(room(), BASE).unwrap();
    assert!(tally.reactions(room(), BASE).unwrap().is_empty());
    assert_eq!(tally.peak(room(), BASE).unwrap(), 0);
}

pub fn a_tally_nobody_renews_disappears(make: &StreamTallyFactory) {
    let tally = make();
    tally
        .count_reaction(room(), "\u{2764}", blink(BASE), BASE)
        .unwrap();
    tally.raise_peak(room(), 5, blink(BASE), BASE).unwrap();
    sleep(Duration::from_millis(BLINK_MILLIS));

    assert!(tally.reactions(room(), BASE + BLINK).unwrap().is_empty());
    assert_eq!(tally.peak(room(), BASE + BLINK).unwrap(), 0);
}

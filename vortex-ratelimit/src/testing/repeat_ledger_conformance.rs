use std::sync::Arc;

use crate::antispam::digest::Digest;
use crate::attempt::subject::Subject;
use crate::attempt::window::Window;
use crate::ports::repeat_ledger::RepeatLedger;
use crate::ports::window_reset::WindowReset;

pub type LedgerFactory = dyn Fn() -> (Arc<dyn RepeatLedger>, Arc<dyn WindowReset>);

const BASE: f64 = 1_000.0;
const BUCKET: &str = "antispam-repeats";

fn window() -> Window {
    Window::seconds(30).expect("полминуты — ненулевое окно")
}

fn membership(member: &str) -> Subject {
    Subject::of(BUCKET, member)
}

pub fn check_all(make: &LedgerFactory) {
    a_membership_nobody_counted_starts_at_one(make);
    every_copy_of_one_message_raises_the_running_count(make);
    a_different_message_never_counts_towards_a_repeat(make);
    a_copy_older_than_the_window_is_forgotten(make);
    two_memberships_never_answer_for_each_other(make);
    forgetting_a_membership_clears_every_message_it_sent(make);
}

pub fn a_membership_nobody_counted_starts_at_one(make: &LedgerFactory) {
    let (ledger, _) = make();
    assert_eq!(
        ledger
            .record(&membership("7100:1"), &Digest::of("stop"), window(), BASE)
            .unwrap(),
        1
    );
}

pub fn every_copy_of_one_message_raises_the_running_count(make: &LedgerFactory) {
    let (ledger, _) = make();
    let text = Digest::of("stop");
    for expected in 1..=3 {
        assert_eq!(
            ledger
                .record(&membership("7101:1"), &text, window(), BASE)
                .unwrap(),
            expected
        );
    }
}

pub fn a_different_message_never_counts_towards_a_repeat(make: &LedgerFactory) {
    let (ledger, _) = make();
    ledger
        .record(&membership("7102:1"), &Digest::of("stop"), window(), BASE)
        .unwrap();
    assert_eq!(
        ledger
            .record(&membership("7102:1"), &Digest::of("start"), window(), BASE)
            .unwrap(),
        1
    );
}

pub fn a_copy_older_than_the_window_is_forgotten(make: &LedgerFactory) {
    let (ledger, _) = make();
    let text = Digest::of("stop");
    ledger
        .record(&membership("7103:1"), &text, window(), BASE)
        .unwrap();
    assert_eq!(
        ledger
            .record(&membership("7103:1"), &text, window(), BASE + 30.0)
            .unwrap(),
        1
    );
}

pub fn two_memberships_never_answer_for_each_other(make: &LedgerFactory) {
    let (ledger, _) = make();
    let text = Digest::of("stop");
    ledger
        .record(&membership("7104:1"), &text, window(), BASE)
        .unwrap();
    ledger
        .record(&membership("7104:1"), &text, window(), BASE)
        .unwrap();
    assert_eq!(
        ledger
            .record(&membership("7104:2"), &text, window(), BASE)
            .unwrap(),
        1
    );
    assert_eq!(
        ledger
            .record(&membership("7105:1"), &text, window(), BASE)
            .unwrap(),
        1
    );
}

pub fn forgetting_a_membership_clears_every_message_it_sent(make: &LedgerFactory) {
    let (ledger, reset) = make();
    let first = Digest::of("stop");
    let second = Digest::of("start");
    ledger
        .record(&membership("7106:1"), &first, window(), BASE)
        .unwrap();
    ledger
        .record(&membership("7106:1"), &second, window(), BASE)
        .unwrap();
    reset.forget(&membership("7106:1")).unwrap();
    assert_eq!(
        ledger
            .record(&membership("7106:1"), &first, window(), BASE)
            .unwrap(),
        1
    );
    assert_eq!(
        ledger
            .record(&membership("7106:1"), &second, window(), BASE)
            .unwrap(),
        1
    );
}

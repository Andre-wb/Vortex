use std::sync::Arc;

use crate::attempt::subject::Subject;
use crate::ports::strike_ledger::StrikeLedger;

pub type LedgerFactory = dyn Fn() -> Arc<dyn StrikeLedger>;

const BUCKET: &str = "flood-strikes";

fn membership(member: &str) -> Subject {
    Subject::of(BUCKET, member)
}

pub fn check_all(make: &LedgerFactory) {
    a_membership_nobody_penalised_starts_at_one(make);
    every_penalty_raises_the_running_count(make);
    two_memberships_never_answer_for_each_other(make);
}

pub fn a_membership_nobody_penalised_starts_at_one(make: &LedgerFactory) {
    let ledger = make();
    assert_eq!(ledger.strike(&membership("6100:1")).unwrap(), 1);
}

pub fn every_penalty_raises_the_running_count(make: &LedgerFactory) {
    let ledger = make();
    assert_eq!(ledger.strike(&membership("6101:1")).unwrap(), 1);
    assert_eq!(ledger.strike(&membership("6101:1")).unwrap(), 2);
    assert_eq!(ledger.strike(&membership("6101:1")).unwrap(), 3);
}

pub fn two_memberships_never_answer_for_each_other(make: &LedgerFactory) {
    let ledger = make();
    ledger.strike(&membership("6102:1")).unwrap();
    ledger.strike(&membership("6102:1")).unwrap();
    assert_eq!(ledger.strike(&membership("6102:2")).unwrap(), 1);
    assert_eq!(ledger.strike(&membership("6103:1")).unwrap(), 1);
}

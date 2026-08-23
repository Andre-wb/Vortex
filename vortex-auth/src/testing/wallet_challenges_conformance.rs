use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;

use crate::account::user_id::UserId;
use crate::challenge::secret::ChallengeSecret;
use crate::ports::wallet_challenges::WalletChallenges;
use crate::random::fixed_entropy::FixedEntropy;
use crate::token::ttl::Ttl;

pub type WalletChallengesFactory = dyn Fn() -> Arc<dyn WalletChallenges>;

const BASE: f64 = 1_000.0;

fn user(value: i64) -> UserId {
    UserId::of(value).expect("номер учётной записи в наборе соответствия должен быть положительным")
}

fn secret(first: u8) -> ChallengeSecret {
    ChallengeSecret::draw(&FixedEntropy::counting_from(first))
}

fn minute() -> Ttl {
    Ttl::seconds(60).expect("минута — ненулевое время жизни")
}

pub fn check_all(make: &WalletChallengesFactory) {
    an_account_that_asked_for_nothing_holds_no_challenge(make);
    a_remembered_challenge_is_found_by_its_account(make);
    two_accounts_never_answer_for_each_other(make);
    asking_again_replaces_the_challenge(make);
    a_burnt_challenge_is_gone(make);
    a_challenge_disappears_when_its_lifetime_runs_out(make);
}

pub fn an_account_that_asked_for_nothing_holds_no_challenge(make: &WalletChallengesFactory) {
    let store = make();
    assert_eq!(store.find(user(1), BASE).unwrap(), None);
}

pub fn a_remembered_challenge_is_found_by_its_account(make: &WalletChallengesFactory) {
    let store = make();
    let issued = secret(1);
    store.remember(user(1), &issued, minute(), BASE).unwrap();
    assert_eq!(store.find(user(1), BASE).unwrap(), Some(issued));
}

pub fn two_accounts_never_answer_for_each_other(make: &WalletChallengesFactory) {
    let store = make();
    store.remember(user(1), &secret(1), minute(), BASE).unwrap();
    assert!(store.find(user(1), BASE).unwrap().is_some());
    assert!(store.find(user(2), BASE).unwrap().is_none());
}

pub fn asking_again_replaces_the_challenge(make: &WalletChallengesFactory) {
    let store = make();
    store.remember(user(1), &secret(1), minute(), BASE).unwrap();
    let second = secret(100);
    store.remember(user(1), &second, minute(), BASE).unwrap();
    assert_eq!(store.find(user(1), BASE).unwrap(), Some(second));
}

pub fn a_burnt_challenge_is_gone(make: &WalletChallengesFactory) {
    let store = make();
    store.remember(user(1), &secret(1), minute(), BASE).unwrap();
    store.burn(user(1)).unwrap();
    assert_eq!(store.find(user(1), BASE).unwrap(), None);
}

pub fn a_challenge_disappears_when_its_lifetime_runs_out(make: &WalletChallengesFactory) {
    let store = make();
    store
        .remember(user(1), &secret(1), Ttl::seconds(1).unwrap(), BASE)
        .unwrap();
    sleep(Duration::from_millis(1_100));
    assert_eq!(store.find(user(1), BASE + 1.2).unwrap(), None);
}

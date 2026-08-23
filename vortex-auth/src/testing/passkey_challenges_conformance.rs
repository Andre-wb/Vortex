use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;

use crate::account::user_id::UserId;
use crate::challenge::secret::ChallengeSecret;
use crate::passkey::purpose::Purpose;
use crate::passkey::record::PasskeyChallenge;
use crate::passkey::session::PasskeySession;
use crate::ports::passkey_challenges::PasskeyChallenges;
use crate::random::fixed_entropy::FixedEntropy;
use crate::token::ttl::Ttl;

pub type PasskeyChallengesFactory = dyn Fn() -> Arc<dyn PasskeyChallenges>;

const BASE: f64 = 1_000.0;

fn session(value: &str) -> PasskeySession {
    PasskeySession::parse(value).expect("сессия в наборе соответствия должна быть валидна")
}

fn record(first: u8, purpose: Purpose) -> PasskeyChallenge {
    PasskeyChallenge::new(
        ChallengeSecret::draw(&FixedEntropy::counting_from(first)),
        purpose,
    )
}

fn account() -> Purpose {
    Purpose::Registration(UserId::of(7).expect("номер учётной записи положителен"))
}

fn minute() -> Ttl {
    Ttl::seconds(60).expect("минута — ненулевое время жизни")
}

pub fn check_all(make: &PasskeyChallengesFactory) {
    a_session_nobody_opened_holds_nothing(make);
    a_registration_challenge_comes_back_whole(make);
    a_login_challenge_comes_back_whole(make);
    a_challenge_is_handed_out_only_once(make);
    two_sessions_never_answer_for_each_other(make);
    a_challenge_disappears_when_its_lifetime_runs_out(make);
}

pub fn a_session_nobody_opened_holds_nothing(make: &PasskeyChallengesFactory) {
    let store = make();
    assert_eq!(store.consume(&session("never-opened"), BASE).unwrap(), None);
}

pub fn a_registration_challenge_comes_back_whole(make: &PasskeyChallengesFactory) {
    let store = make();
    let kept = record(1, account());
    store
        .open(&session("registration"), &kept, minute(), BASE)
        .unwrap();
    assert_eq!(
        store.consume(&session("registration"), BASE).unwrap(),
        Some(kept)
    );
}

pub fn a_login_challenge_comes_back_whole(make: &PasskeyChallengesFactory) {
    let store = make();
    let kept = record(2, Purpose::Login);
    store
        .open(&session("login"), &kept, minute(), BASE)
        .unwrap();
    assert_eq!(store.consume(&session("login"), BASE).unwrap(), Some(kept));
}

pub fn a_challenge_is_handed_out_only_once(make: &PasskeyChallengesFactory) {
    let store = make();
    store
        .open(&session("once"), &record(3, Purpose::Login), minute(), BASE)
        .unwrap();
    assert!(store.consume(&session("once"), BASE).unwrap().is_some());
    assert_eq!(store.consume(&session("once"), BASE).unwrap(), None);
}

pub fn two_sessions_never_answer_for_each_other(make: &PasskeyChallengesFactory) {
    let store = make();
    store
        .open(&session("mine"), &record(4, Purpose::Login), minute(), BASE)
        .unwrap();
    assert_eq!(store.consume(&session("theirs"), BASE).unwrap(), None);
    assert!(store.consume(&session("mine"), BASE).unwrap().is_some());
}

pub fn a_challenge_disappears_when_its_lifetime_runs_out(make: &PasskeyChallengesFactory) {
    let store = make();
    store
        .open(
            &session("short"),
            &record(5, Purpose::Login),
            Ttl::seconds(1).unwrap(),
            BASE,
        )
        .unwrap();
    sleep(Duration::from_millis(1_100));
    assert_eq!(store.consume(&session("short"), BASE + 1.2).unwrap(), None);
}

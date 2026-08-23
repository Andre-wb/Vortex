use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;

use crate::account::user_id::UserId;
use crate::challenge::id::ChallengeId;
use crate::challenge::secret::ChallengeSecret;
use crate::login::binding::Binding;
use crate::login::key::LoginPublicKey;
use crate::login::record::LoginChallenge;
use crate::ports::login_challenges::LoginChallenges;
use crate::qr::session_id::QrSessionId;
use crate::random::fixed_entropy::FixedEntropy;
use crate::token::ttl::Ttl;

pub type LoginChallengesFactory = dyn Fn() -> Arc<dyn LoginChallenges>;

const BASE: f64 = 1_000.0;
const KEY: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn id(value: &str) -> ChallengeId {
    ChallengeId::parse(value).expect("идентификатор в наборе соответствия должен быть валиден")
}

fn record(first: u8, binding: Binding) -> LoginChallenge {
    LoginChallenge::new(
        ChallengeSecret::draw(&FixedEntropy::counting_from(first)),
        binding,
    )
}

fn account() -> Binding {
    Binding::Account {
        user: UserId::of(7).expect("номер учётной записи положителен"),
        pubkey: LoginPublicKey::parse(KEY).expect("ключ в наборе соответствия должен быть валиден"),
    }
}

fn minute() -> Ttl {
    Ttl::seconds(60).expect("минута — ненулевое время жизни")
}

pub fn check_all(make: &LoginChallengesFactory) {
    a_challenge_nobody_opened_is_missing(make);
    a_challenge_bound_to_an_account_comes_back_whole(make);
    a_challenge_bound_to_a_session_comes_back_whole(make);
    a_decoy_comes_back_whole(make);
    a_challenge_is_handed_out_only_once(make);
    two_challenges_never_answer_for_each_other(make);
    a_challenge_disappears_when_its_lifetime_runs_out(make);
}

pub fn a_challenge_nobody_opened_is_missing(make: &LoginChallengesFactory) {
    let store = make();
    assert_eq!(store.consume(&id("never-opened"), BASE).unwrap(), None);
}

pub fn a_challenge_bound_to_an_account_comes_back_whole(make: &LoginChallengesFactory) {
    let store = make();
    let kept = record(1, account());
    store.open(&id("account"), &kept, minute(), BASE).unwrap();
    assert_eq!(store.consume(&id("account"), BASE).unwrap(), Some(kept));
}

pub fn a_challenge_bound_to_a_session_comes_back_whole(make: &LoginChallengesFactory) {
    let store = make();
    let kept = record(
        2,
        Binding::QrSession(QrSessionId::parse("abcdabcd").expect("сессия валидна")),
    );
    store.open(&id("session"), &kept, minute(), BASE).unwrap();
    assert_eq!(store.consume(&id("session"), BASE).unwrap(), Some(kept));
}

pub fn a_decoy_comes_back_whole(make: &LoginChallengesFactory) {
    let store = make();
    let kept = record(3, Binding::Decoy);
    store.open(&id("decoy"), &kept, minute(), BASE).unwrap();
    assert_eq!(store.consume(&id("decoy"), BASE).unwrap(), Some(kept));
}

pub fn a_challenge_is_handed_out_only_once(make: &LoginChallengesFactory) {
    let store = make();
    store
        .open(&id("once"), &record(4, account()), minute(), BASE)
        .unwrap();
    assert!(store.consume(&id("once"), BASE).unwrap().is_some());
    assert_eq!(store.consume(&id("once"), BASE).unwrap(), None);
}

pub fn two_challenges_never_answer_for_each_other(make: &LoginChallengesFactory) {
    let store = make();
    store
        .open(&id("mine"), &record(5, account()), minute(), BASE)
        .unwrap();
    assert_eq!(store.consume(&id("theirs"), BASE).unwrap(), None);
    assert!(store.consume(&id("mine"), BASE).unwrap().is_some());
}

pub fn a_challenge_disappears_when_its_lifetime_runs_out(make: &LoginChallengesFactory) {
    let store = make();
    store
        .open(
            &id("short"),
            &record(6, account()),
            Ttl::seconds(1).unwrap(),
            BASE,
        )
        .unwrap();
    sleep(Duration::from_millis(1_100));
    assert_eq!(store.consume(&id("short"), BASE + 1.2).unwrap(), None);
}

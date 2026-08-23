use std::sync::Arc;

use crate::ports::push_registry::PushRegistry;
use crate::push::category::PushCategory;
use crate::push::endpoint::PushEndpoint;
use crate::push::limits;
use crate::push::service::PushProxyService;
use crate::push::token::PushToken;

fn token(tag: &str) -> PushToken {
    PushToken::parse(&format!("{{\"auth\":\"{tag}-0123456789\"}}")).unwrap()
}

fn endpoint(tag: &str) -> PushEndpoint {
    PushEndpoint::parse(&format!("https://push.example/{tag}")).unwrap()
}

fn category(value: u8) -> PushCategory {
    PushCategory::of(value)
}

pub fn a_registered_token_is_found_in_its_category(store: Arc<dyn PushRegistry>) {
    let service = PushProxyService::new(store);
    service
        .register(&[category(7)], token("a"), endpoint("a"), 1000.0)
        .unwrap();
    let held = service.registrations(category(7), 1000.0).unwrap();
    assert_eq!(held.len(), 1);
    assert_eq!(held[0].token(), &token("a"));
    assert_eq!(held[0].endpoint(), &endpoint("a"));
}

pub fn a_token_reaches_every_category_it_named(store: Arc<dyn PushRegistry>) {
    let service = PushProxyService::new(store);
    service
        .register(
            &[category(1), category(2), category(3)],
            token("b"),
            endpoint("b"),
            1000.0,
        )
        .unwrap();
    for named in [1u8, 2, 3] {
        assert_eq!(
            service
                .registrations(category(named), 1000.0)
                .unwrap()
                .len(),
            1
        );
    }
}

pub fn a_category_nobody_named_is_empty(store: Arc<dyn PushRegistry>) {
    let service = PushProxyService::new(store);
    assert!(service
        .registrations(category(99), 1000.0)
        .unwrap()
        .is_empty());
}

pub fn the_same_token_twice_is_held_once(store: Arc<dyn PushRegistry>) {
    let service = PushProxyService::new(store);
    service
        .register(&[category(11)], token("c"), endpoint("c"), 1000.0)
        .unwrap();
    service
        .register(&[category(11)], token("c"), endpoint("c-new"), 1001.0)
        .unwrap();
    let held = service.registrations(category(11), 1001.0).unwrap();
    assert_eq!(held.len(), 1);
    assert_eq!(held[0].endpoint(), &endpoint("c-new"));
}

pub fn a_stale_registration_is_not_handed_over(store: Arc<dyn PushRegistry>) {
    let service = PushProxyService::new(store);
    service
        .register(&[category(12)], token("d"), endpoint("d"), 1000.0)
        .unwrap();
    let past = 1000.0 + limits::TOKEN_LIFETIME_SECONDS;
    assert!(service
        .registrations(category(12), past)
        .unwrap()
        .is_empty());
}

pub fn a_registration_still_counts_just_before_its_lifetime(store: Arc<dyn PushRegistry>) {
    let service = PushProxyService::new(store);
    service
        .register(&[category(13)], token("e"), endpoint("e"), 1000.0)
        .unwrap();
    let almost = 1000.0 + limits::TOKEN_LIFETIME_SECONDS - 1.0;
    assert_eq!(
        service.registrations(category(13), almost).unwrap().len(),
        1
    );
}

pub fn an_unregistered_token_leaves_every_category(store: Arc<dyn PushRegistry>) {
    let service = PushProxyService::new(store);
    service
        .register(
            &[category(21), category(22)],
            token("f"),
            endpoint("f"),
            1000.0,
        )
        .unwrap();
    assert_eq!(service.unregister(&token("f")).unwrap(), 2);
    for named in [21u8, 22] {
        assert!(service
            .registrations(category(named), 1000.0)
            .unwrap()
            .is_empty());
    }
}

pub fn unregistering_an_unknown_token_removes_nothing(store: Arc<dyn PushRegistry>) {
    let service = PushProxyService::new(store);
    assert_eq!(service.unregister(&token("absent")).unwrap(), 0);
}

pub fn a_full_category_refuses_the_newcomer(store: Arc<dyn PushRegistry>) {
    let service = PushProxyService::new(store);
    service
        .register(&[category(31)], token("held"), endpoint("held"), 1000.0)
        .unwrap();
    service
        .register(&[category(31)], token("late"), endpoint("late"), 1000.0)
        .unwrap();
    let held = service.registrations(category(31), 1000.0).unwrap();
    assert_eq!(held.len(), 1);
    assert_eq!(held[0].token(), &token("held"));
}

pub fn a_full_category_still_refreshes_a_token_it_holds(store: Arc<dyn PushRegistry>) {
    let service = PushProxyService::new(store);
    service
        .register(&[category(32)], token("held"), endpoint("held"), 1000.0)
        .unwrap();
    service
        .register(&[category(32)], token("held"), endpoint("fresh"), 2000.0)
        .unwrap();
    let held = service.registrations(category(32), 2000.0).unwrap();
    assert_eq!(held.len(), 1);
    assert_eq!(held[0].endpoint(), &endpoint("fresh"));
    assert_eq!(held[0].registered_at(), 2000.0);
}

pub fn a_wake_is_counted_and_names_its_category(store: Arc<dyn PushRegistry>) {
    let service = PushProxyService::new(store);
    let before = service.tally().unwrap().wakes();
    service
        .register(&[category(41)], token("g"), endpoint("g"), 1000.0)
        .unwrap();
    let woken = service.woken(category(41), 1000.0).unwrap();
    assert_eq!(woken.len(), 1);
    assert_eq!(service.tally().unwrap().wakes(), before + 1);
}

pub fn a_tally_counts_tokens_and_busy_categories(store: Arc<dyn PushRegistry>) {
    let service = PushProxyService::new(store);
    let before = service.tally().unwrap();
    service
        .register(
            &[category(51), category(52)],
            token("h"),
            endpoint("h"),
            1000.0,
        )
        .unwrap();
    service
        .register(&[category(51)], token("i"), endpoint("i"), 1000.0)
        .unwrap();
    let after = service.tally().unwrap();
    assert_eq!(after.tokens(), before.tokens() + 3);
    assert_eq!(after.categories(), before.categories() + 2);
}

pub fn a_category_is_named_the_way_python_named_it() {
    assert_eq!(
        PushProxyService::categories_of(&[0, 255, 256, -1]).unwrap(),
        vec![category(0), category(255), category(0), category(255)]
    );
}

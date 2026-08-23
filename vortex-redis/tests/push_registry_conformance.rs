mod support;

use std::sync::Arc;

use vortex_bmp::testing::push_registry_conformance as push;
use vortex_redis::bmp::push_registry::RedisPushRegistry;

use support::{backbone, unique_prefix};

#[test]
fn redis_keeps_push_registrations_the_agreed_way() {
    let Some(shared) = backbone(&unique_prefix("bmp-push")) else {
        return;
    };
    push::a_registered_token_is_found_in_its_category(Arc::new(RedisPushRegistry::new(
        shared.clone(),
    )));
    push::a_token_reaches_every_category_it_named(Arc::new(RedisPushRegistry::new(shared.clone())));
    push::a_category_nobody_named_is_empty(Arc::new(RedisPushRegistry::new(shared.clone())));
    push::the_same_token_twice_is_held_once(Arc::new(RedisPushRegistry::new(shared.clone())));
    push::a_stale_registration_is_not_handed_over(Arc::new(RedisPushRegistry::new(shared.clone())));
    push::a_registration_still_counts_just_before_its_lifetime(Arc::new(RedisPushRegistry::new(
        shared.clone(),
    )));
    push::an_unregistered_token_leaves_every_category(Arc::new(RedisPushRegistry::new(
        shared.clone(),
    )));
    push::unregistering_an_unknown_token_removes_nothing(Arc::new(RedisPushRegistry::new(
        shared.clone(),
    )));
    push::a_wake_is_counted_and_names_its_category(Arc::new(RedisPushRegistry::new(
        shared.clone(),
    )));
    push::a_tally_counts_tokens_and_busy_categories(Arc::new(RedisPushRegistry::new(shared)));
    push::a_category_is_named_the_way_python_named_it();
}

#[test]
fn redis_keeps_a_full_category_the_agreed_way() {
    let Some(shared) = backbone(&unique_prefix("bmp-push-full")) else {
        return;
    };
    push::a_full_category_refuses_the_newcomer(Arc::new(RedisPushRegistry::sized(
        shared.clone(),
        1,
        vortex_bmp::push::limits::TOKEN_LIFETIME_SECONDS,
    )));
    push::a_full_category_still_refreshes_a_token_it_holds(Arc::new(RedisPushRegistry::sized(
        shared,
        1,
        vortex_bmp::push::limits::TOKEN_LIFETIME_SECONDS,
    )));
}

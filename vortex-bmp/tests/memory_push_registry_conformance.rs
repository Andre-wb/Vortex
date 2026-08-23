use std::sync::Arc;

use vortex_bmp::push::memory::MemoryPushRegistry;
use vortex_bmp::testing::push_registry_conformance as push;

#[test]
fn memory_keeps_push_registrations_the_agreed_way() {
    push::a_registered_token_is_found_in_its_category(Arc::new(MemoryPushRegistry::new()));
    push::a_token_reaches_every_category_it_named(Arc::new(MemoryPushRegistry::new()));
    push::a_category_nobody_named_is_empty(Arc::new(MemoryPushRegistry::new()));
    push::the_same_token_twice_is_held_once(Arc::new(MemoryPushRegistry::new()));
    push::a_stale_registration_is_not_handed_over(Arc::new(MemoryPushRegistry::new()));
    push::a_registration_still_counts_just_before_its_lifetime(Arc::new(MemoryPushRegistry::new()));
    push::an_unregistered_token_leaves_every_category(Arc::new(MemoryPushRegistry::new()));
    push::unregistering_an_unknown_token_removes_nothing(Arc::new(MemoryPushRegistry::new()));
    push::a_full_category_refuses_the_newcomer(Arc::new(MemoryPushRegistry::sized(1)));
    push::a_full_category_still_refreshes_a_token_it_holds(Arc::new(MemoryPushRegistry::sized(1)));
    push::a_wake_is_counted_and_names_its_category(Arc::new(MemoryPushRegistry::new()));
    push::a_tally_counts_tokens_and_busy_categories(Arc::new(MemoryPushRegistry::new()));
    push::a_category_is_named_the_way_python_named_it();
}

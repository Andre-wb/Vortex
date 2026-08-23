mod support;

use std::sync::Arc;

use vortex_net::testing::peer_registry_conformance as peers;
use vortex_redis::net::peer_registry::RedisPeerRegistry;

use support::{backbone, unique_prefix};

#[test]
fn redis_keeps_the_peer_registry_the_agreed_way() {
    let Some(shared) = backbone(&unique_prefix("net-peers")) else {
        return;
    };
    peers::a_heard_peer_is_found_again(Arc::new(RedisPeerRegistry::new(shared.clone())));
    peers::an_unknown_address_names_no_peer(Arc::new(RedisPeerRegistry::new(shared.clone())));
    peers::hearing_a_known_peer_again_is_not_news(Arc::new(RedisPeerRegistry::new(shared.clone())));
    peers::a_key_survives_a_silent_refresh(Arc::new(RedisPeerRegistry::new(shared.clone())));
    peers::a_key_of_the_wrong_shape_is_not_kept(Arc::new(RedisPeerRegistry::new(shared.clone())));
    peers::only_the_living_are_told(Arc::new(RedisPeerRegistry::new(shared.clone())));
    peers::a_peer_is_alive_until_the_timeout_and_not_at_it(Arc::new(RedisPeerRegistry::new(
        shared.clone(),
    )));
    peers::forgetting_the_dead_removes_them_and_their_rooms(Arc::new(RedisPeerRegistry::new(
        shared.clone(),
    )));
    peers::forgetting_the_dead_keeps_the_living(Arc::new(RedisPeerRegistry::new(shared.clone())));
    peers::rooms_are_told_only_for_living_peers(Arc::new(RedisPeerRegistry::new(shared.clone())));
    peers::a_peer_without_rooms_is_not_told(Arc::new(RedisPeerRegistry::new(shared.clone())));
    peers::a_later_room_list_replaces_the_earlier_one(Arc::new(RedisPeerRegistry::new(
        shared.clone(),
    )));
    peers::peers_do_not_shadow_each_other(Arc::new(RedisPeerRegistry::new(shared.clone())));
    peers::an_address_that_is_not_an_address_is_refused(Arc::new(RedisPeerRegistry::new(
        shared.clone(),
    )));
    peers::a_port_outside_the_range_is_refused(Arc::new(RedisPeerRegistry::new(shared)));
}

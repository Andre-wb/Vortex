use std::sync::Arc;

use vortex_net::registry::memory::MemoryPeerRegistry;
use vortex_net::testing::peer_registry_conformance as peers;

#[test]
fn memory_keeps_the_peer_registry_the_agreed_way() {
    peers::a_heard_peer_is_found_again(Arc::new(MemoryPeerRegistry::new()));
    peers::an_unknown_address_names_no_peer(Arc::new(MemoryPeerRegistry::new()));
    peers::hearing_a_known_peer_again_is_not_news(Arc::new(MemoryPeerRegistry::new()));
    peers::a_key_survives_a_silent_refresh(Arc::new(MemoryPeerRegistry::new()));
    peers::a_key_of_the_wrong_shape_is_not_kept(Arc::new(MemoryPeerRegistry::new()));
    peers::only_the_living_are_told(Arc::new(MemoryPeerRegistry::new()));
    peers::a_peer_is_alive_until_the_timeout_and_not_at_it(Arc::new(MemoryPeerRegistry::new()));
    peers::forgetting_the_dead_removes_them_and_their_rooms(Arc::new(MemoryPeerRegistry::new()));
    peers::forgetting_the_dead_keeps_the_living(Arc::new(MemoryPeerRegistry::new()));
    peers::rooms_are_told_only_for_living_peers(Arc::new(MemoryPeerRegistry::new()));
    peers::a_peer_without_rooms_is_not_told(Arc::new(MemoryPeerRegistry::new()));
    peers::a_later_room_list_replaces_the_earlier_one(Arc::new(MemoryPeerRegistry::new()));
    peers::peers_do_not_shadow_each_other(Arc::new(MemoryPeerRegistry::new()));
    peers::an_address_that_is_not_an_address_is_refused(Arc::new(MemoryPeerRegistry::new()));
    peers::a_port_outside_the_range_is_refused(Arc::new(MemoryPeerRegistry::new()));
}

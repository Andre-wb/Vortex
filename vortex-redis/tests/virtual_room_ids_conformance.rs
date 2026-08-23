mod support;

use std::sync::Arc;

use vortex_net::testing::virtual_room_ids_conformance as ids;
use vortex_redis::net::virtual_room_ids::RedisVirtualRoomIds;

use support::{backbone, unique_prefix};

#[test]
fn redis_hands_out_virtual_room_ids_the_agreed_way() {
    for name in [
        "ids-down",
        "ids-unique",
        "ids-restored",
        "ids-above",
        "ids-local",
    ] {
        let Some(shared) = backbone(&unique_prefix(name)) else {
            return;
        };
        let store = Arc::new(RedisVirtualRoomIds::new(shared));
        match name {
            "ids-down" => ids::ids_are_handed_out_going_down(store),
            "ids-unique" => ids::no_two_callers_get_the_same_id(store),
            "ids-restored" => ids::a_restored_id_is_never_handed_out_again(store),
            "ids-above" => ids::a_restored_id_above_the_counter_changes_nothing(store),
            _ => ids::a_local_room_number_reserves_nothing(store),
        }
    }
}

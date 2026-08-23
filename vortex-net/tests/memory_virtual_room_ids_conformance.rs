use std::sync::Arc;

use vortex_net::federation::memory::MemoryVirtualRoomIds;
use vortex_net::testing::virtual_room_ids_conformance as ids;

#[test]
fn memory_hands_out_virtual_room_ids_the_agreed_way() {
    ids::ids_are_handed_out_going_down(Arc::new(MemoryVirtualRoomIds::new()));
    ids::no_two_callers_get_the_same_id(Arc::new(MemoryVirtualRoomIds::new()));
    ids::a_restored_id_is_never_handed_out_again(Arc::new(MemoryVirtualRoomIds::new()));
    ids::a_restored_id_above_the_counter_changes_nothing(Arc::new(MemoryVirtualRoomIds::new()));
    ids::a_local_room_number_reserves_nothing(Arc::new(MemoryVirtualRoomIds::new()));
}

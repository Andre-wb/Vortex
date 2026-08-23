use std::sync::Arc;

use crate::federation::service::VirtualRoomIdService;
use crate::ports::virtual_room_ids::VirtualRoomIds;

pub fn ids_are_handed_out_going_down(store: Arc<dyn VirtualRoomIds>) {
    let ids = VirtualRoomIdService::new(store);
    let first = ids.next().unwrap().value();
    let second = ids.next().unwrap().value();
    assert!(first < 0);
    assert_eq!(second, first - 1);
}

pub fn no_two_callers_get_the_same_id(store: Arc<dyn VirtualRoomIds>) {
    let ids = VirtualRoomIdService::new(store);
    let handed: Vec<i64> = (0..8).map(|_| ids.next().unwrap().value()).collect();
    let mut sorted = handed.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), handed.len());
}

pub fn a_restored_id_is_never_handed_out_again(store: Arc<dyn VirtualRoomIds>) {
    let ids = VirtualRoomIdService::new(store);
    ids.reserve_below(-50).unwrap();
    assert_eq!(ids.next().unwrap().value(), -51);
}

pub fn a_restored_id_above_the_counter_changes_nothing(store: Arc<dyn VirtualRoomIds>) {
    let ids = VirtualRoomIdService::new(store);
    ids.reserve_below(-30).unwrap();
    ids.reserve_below(-5).unwrap();
    assert_eq!(ids.next().unwrap().value(), -31);
}

pub fn a_local_room_number_reserves_nothing(store: Arc<dyn VirtualRoomIds>) {
    let ids = VirtualRoomIdService::new(store);
    ids.reserve_below(7).unwrap();
    assert!(ids.next().unwrap().value() < 0);
}

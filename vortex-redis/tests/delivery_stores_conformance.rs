mod support;

use std::sync::Arc;

use vortex_delivery::testing::{
    notification_mailbox_conformance as notes, room_mailbox_conformance as rooms,
    seen_messages_conformance as seen,
};
use vortex_redis::delivery::notification_mailbox::RedisNotificationMailbox;
use vortex_redis::delivery::room_mailbox::RedisRoomMailbox;
use vortex_redis::delivery::seen_messages::RedisSeenMessages;

use support::{backbone, unique_prefix};

#[test]
fn redis_remembers_messages_the_agreed_way() {
    let Some(shared) = backbone(&unique_prefix("delivery-seen")) else {
        return;
    };
    seen::a_first_sighting_is_not_a_repeat(Arc::new(RedisSeenMessages::new(shared.clone())));
    seen::a_second_sighting_is_a_repeat(Arc::new(RedisSeenMessages::new(shared.clone())));
    seen::a_sighting_is_forgotten_past_its_lifetime(Arc::new(RedisSeenMessages::new(
        shared.clone(),
    )));
    seen::a_sighting_still_counts_just_before_its_lifetime(Arc::new(RedisSeenMessages::new(
        shared.clone(),
    )));
    seen::different_identifiers_do_not_shadow_each_other(Arc::new(RedisSeenMessages::new(
        shared.clone(),
    )));
    seen::a_full_ledger_admits_the_newcomer_and_drops_the_oldest(Arc::new(
        RedisSeenMessages::sized(shared, 8, 300.0),
    ));
}

#[test]
fn redis_keeps_room_queues_the_agreed_way() {
    let Some(shared) = backbone(&unique_prefix("delivery-rooms")) else {
        return;
    };
    rooms::a_deposited_message_is_collected_once(Arc::new(RedisRoomMailbox::new(shared.clone())));
    rooms::order_of_deposit_is_the_order_of_collection(Arc::new(RedisRoomMailbox::new(
        shared.clone(),
    )));
    rooms::one_deposit_reaches_every_named_reader(Arc::new(RedisRoomMailbox::new(shared.clone())));
    rooms::a_reader_sees_only_their_own_room(Arc::new(RedisRoomMailbox::new(shared.clone())));
    rooms::a_stale_message_is_not_handed_over(Arc::new(RedisRoomMailbox::new(shared.clone())));
    rooms::a_full_queue_keeps_the_newest(Arc::new(RedisRoomMailbox::new(shared.clone())));
    rooms::sweeping_removes_only_stale_entries(Arc::new(RedisRoomMailbox::new(shared.clone())));
    rooms::a_collected_queue_stops_being_counted(Arc::new(RedisRoomMailbox::new(shared)));
}

#[test]
fn redis_keeps_notification_queues_the_agreed_way() {
    let Some(shared) = backbone(&unique_prefix("delivery-notes")) else {
        return;
    };
    notes::a_deposited_notification_is_collected_once(Arc::new(RedisNotificationMailbox::new(
        shared.clone(),
    )));
    notes::order_of_deposit_is_the_order_of_collection(Arc::new(RedisNotificationMailbox::new(
        shared.clone(),
    )));
    notes::a_reader_sees_only_their_own_queue(Arc::new(RedisNotificationMailbox::new(
        shared.clone(),
    )));
    notes::a_stale_notification_is_not_handed_over(Arc::new(RedisNotificationMailbox::new(
        shared.clone(),
    )));
    notes::a_full_queue_keeps_the_newest(Arc::new(RedisNotificationMailbox::new(shared.clone())));
    notes::a_collected_queue_stops_being_counted(Arc::new(RedisNotificationMailbox::new(shared)));
}

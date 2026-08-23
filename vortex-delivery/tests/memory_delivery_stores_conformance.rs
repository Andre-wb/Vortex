use std::sync::Arc;

use vortex_delivery::dedup::memory::MemorySeenMessages;
use vortex_delivery::mailbox::notification::memory::MemoryNotificationMailbox;
use vortex_delivery::mailbox::room::memory::MemoryRoomMailbox;
use vortex_delivery::testing::{
    notification_mailbox_conformance as notes, room_mailbox_conformance as rooms,
    seen_messages_conformance as seen,
};

#[test]
fn memory_remembers_messages_the_agreed_way() {
    seen::a_first_sighting_is_not_a_repeat(Arc::new(MemorySeenMessages::new()));
    seen::a_second_sighting_is_a_repeat(Arc::new(MemorySeenMessages::new()));
    seen::a_sighting_is_forgotten_past_its_lifetime(Arc::new(MemorySeenMessages::new()));
    seen::a_sighting_still_counts_just_before_its_lifetime(Arc::new(MemorySeenMessages::new()));
    seen::different_identifiers_do_not_shadow_each_other(Arc::new(MemorySeenMessages::new()));
    seen::a_full_ledger_admits_the_newcomer_and_drops_the_oldest(Arc::new(
        MemorySeenMessages::sized(8, 300.0),
    ));
}

#[test]
fn memory_keeps_room_queues_the_agreed_way() {
    rooms::a_deposited_message_is_collected_once(Arc::new(MemoryRoomMailbox::new()));
    rooms::order_of_deposit_is_the_order_of_collection(Arc::new(MemoryRoomMailbox::new()));
    rooms::one_deposit_reaches_every_named_reader(Arc::new(MemoryRoomMailbox::new()));
    rooms::a_reader_sees_only_their_own_room(Arc::new(MemoryRoomMailbox::new()));
    rooms::a_stale_message_is_not_handed_over(Arc::new(MemoryRoomMailbox::new()));
    rooms::a_full_queue_keeps_the_newest(Arc::new(MemoryRoomMailbox::new()));
    rooms::sweeping_removes_only_stale_entries(Arc::new(MemoryRoomMailbox::new()));
    rooms::a_collected_queue_stops_being_counted(Arc::new(MemoryRoomMailbox::new()));
}

#[test]
fn memory_keeps_notification_queues_the_agreed_way() {
    notes::a_deposited_notification_is_collected_once(Arc::new(MemoryNotificationMailbox::new()));
    notes::order_of_deposit_is_the_order_of_collection(Arc::new(MemoryNotificationMailbox::new()));
    notes::a_reader_sees_only_their_own_queue(Arc::new(MemoryNotificationMailbox::new()));
    notes::a_stale_notification_is_not_handed_over(Arc::new(MemoryNotificationMailbox::new()));
    notes::a_full_queue_keeps_the_newest(Arc::new(MemoryNotificationMailbox::new()));
    notes::a_collected_queue_stops_being_counted(Arc::new(MemoryNotificationMailbox::new()));
}

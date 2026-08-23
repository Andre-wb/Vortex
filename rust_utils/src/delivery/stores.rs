use std::sync::Arc;

use vortex_delivery::dedup::memory::MemorySeenMessages;
use vortex_delivery::dedup::unavailable::UnavailableSeenMessages;
use vortex_delivery::mailbox::notification::memory::MemoryNotificationMailbox;
use vortex_delivery::mailbox::notification::unavailable::UnavailableNotificationMailbox;
use vortex_delivery::mailbox::room::memory::MemoryRoomMailbox;
use vortex_delivery::mailbox::room::unavailable::UnavailableRoomMailbox;
use vortex_delivery::ports::notification_mailbox::NotificationMailbox;
use vortex_delivery::ports::room_mailbox::RoomMailbox;
use vortex_delivery::ports::seen_messages::SeenMessages;
use vortex_redis::backbone::RedisBackbone;
use vortex_redis::delivery::notification_mailbox::RedisNotificationMailbox;
use vortex_redis::delivery::room_mailbox::RedisRoomMailbox;
use vortex_redis::delivery::seen_messages::RedisSeenMessages;

pub struct Stores {
    pub seen: Arc<dyn SeenMessages>,
    pub rooms: Arc<dyn RoomMailbox>,
    pub notifications: Arc<dyn NotificationMailbox>,
}

impl Stores {
    pub fn in_memory() -> Self {
        Stores {
            seen: Arc::new(MemorySeenMessages::new()),
            rooms: Arc::new(MemoryRoomMailbox::new()),
            notifications: Arc::new(MemoryNotificationMailbox::new()),
        }
    }

    pub fn in_redis(backbone: Arc<RedisBackbone>) -> Self {
        Stores {
            seen: Arc::new(RedisSeenMessages::new(backbone.clone())),
            rooms: Arc::new(RedisRoomMailbox::new(backbone.clone())),
            notifications: Arc::new(RedisNotificationMailbox::new(backbone)),
        }
    }

    pub fn sealed() -> Self {
        Stores {
            seen: Arc::new(UnavailableSeenMessages::new()),
            rooms: Arc::new(UnavailableRoomMailbox::new()),
            notifications: Arc::new(UnavailableNotificationMailbox::new()),
        }
    }
}

use std::collections::HashMap;
use std::collections::VecDeque;

use parking_lot::Mutex;
use vortex_auth::account::user_id::UserId;
use vortex_core::room::room_id::RoomId;

use crate::error::Result;
use crate::mailbox::entry::Entry;
use crate::mailbox::limits;
use crate::message::payload::Payload;
use crate::ports::room_mailbox::RoomMailbox;

pub struct MemoryRoomMailbox {
    queues: Mutex<HashMap<(i64, i64), VecDeque<Entry>>>,
    depth: usize,
    lifetime: f64,
}

impl MemoryRoomMailbox {
    pub fn new() -> Self {
        Self::sized(limits::ROOM_DEPTH, limits::ROOM_LIFETIME_SECONDS)
    }

    pub fn sized(depth: usize, lifetime: f64) -> Self {
        MemoryRoomMailbox {
            queues: Mutex::new(HashMap::new()),
            depth,
            lifetime,
        }
    }
}

impl Default for MemoryRoomMailbox {
    fn default() -> Self {
        Self::new()
    }
}

impl RoomMailbox for MemoryRoomMailbox {
    fn deposit(&self, room: RoomId, readers: &[UserId], payload: &Payload, now: f64) -> Result<()> {
        let mut queues = self.queues.lock();
        for reader in readers {
            let queue = queues.entry((room.value(), reader.value())).or_default();
            queue.push_back(Entry::new(now, payload.clone()));
            while queue.len() > self.depth {
                queue.pop_front();
            }
        }
        Ok(())
    }

    fn collect(&self, room: RoomId, reader: UserId) -> Result<Vec<Entry>> {
        let mut queues = self.queues.lock();
        let queue = queues.remove(&(room.value(), reader.value()));
        Ok(queue.map(Vec::from).unwrap_or_default())
    }

    fn sweep(&self, now: f64) -> Result<usize> {
        let mut queues = self.queues.lock();
        let mut removed = 0;
        queues.retain(|_, queue| {
            while queue.front().is_some_and(|e| e.stale(now, self.lifetime)) {
                queue.pop_front();
                removed += 1;
            }
            !queue.is_empty()
        });
        Ok(removed)
    }

    fn tally(&self) -> Result<(usize, usize)> {
        let queues = self.queues.lock();
        Ok((queues.len(), queues.values().map(VecDeque::len).sum()))
    }
}

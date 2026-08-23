use std::collections::HashMap;
use std::collections::VecDeque;

use parking_lot::Mutex;
use vortex_auth::account::user_id::UserId;

use crate::error::Result;
use crate::mailbox::entry::Entry;
use crate::mailbox::limits;
use crate::message::payload::Payload;
use crate::ports::notification_mailbox::NotificationMailbox;

pub struct MemoryNotificationMailbox {
    queues: Mutex<HashMap<i64, VecDeque<Entry>>>,
    depth: usize,
}

impl MemoryNotificationMailbox {
    pub fn new() -> Self {
        Self::sized(limits::NOTIFICATION_DEPTH)
    }

    pub fn sized(depth: usize) -> Self {
        MemoryNotificationMailbox {
            queues: Mutex::new(HashMap::new()),
            depth,
        }
    }
}

impl Default for MemoryNotificationMailbox {
    fn default() -> Self {
        Self::new()
    }
}

impl NotificationMailbox for MemoryNotificationMailbox {
    fn deposit(&self, reader: UserId, payload: &Payload, now: f64) -> Result<()> {
        let mut queues = self.queues.lock();
        let queue = queues.entry(reader.value()).or_default();
        queue.push_back(Entry::new(now, payload.clone()));
        while queue.len() > self.depth {
            queue.pop_front();
        }
        Ok(())
    }

    fn collect(&self, reader: UserId) -> Result<Vec<Entry>> {
        let mut queues = self.queues.lock();
        Ok(queues
            .remove(&reader.value())
            .map(Vec::from)
            .unwrap_or_default())
    }

    fn tally(&self) -> Result<(usize, usize)> {
        let queues = self.queues.lock();
        Ok((queues.len(), queues.values().map(VecDeque::len).sum()))
    }
}

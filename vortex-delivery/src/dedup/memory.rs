use std::collections::{BTreeSet, HashMap};

use parking_lot::Mutex;

use crate::dedup::limits;
use crate::error::Result;
use crate::message::identifier::MessageId;
use crate::ports::seen_messages::SeenMessages;

struct Ledger {
    stamped: HashMap<MessageId, f64>,
    order: BTreeSet<(u64, MessageId)>,
    tick: u64,
}

pub struct MemorySeenMessages {
    ledger: Mutex<Ledger>,
    capacity: usize,
    lifetime: f64,
}

impl MemorySeenMessages {
    pub fn new() -> Self {
        Self::sized(limits::CAPACITY, limits::LIFETIME_SECONDS)
    }

    pub fn sized(capacity: usize, lifetime: f64) -> Self {
        MemorySeenMessages {
            ledger: Mutex::new(Ledger {
                stamped: HashMap::new(),
                order: BTreeSet::new(),
                tick: 0,
            }),
            capacity,
            lifetime,
        }
    }
}

impl Default for MemorySeenMessages {
    fn default() -> Self {
        Self::new()
    }
}

impl SeenMessages for MemorySeenMessages {
    fn remember(&self, message: &MessageId, now: f64) -> Result<bool> {
        let mut ledger = self.ledger.lock();

        let stale: Vec<(u64, MessageId)> = ledger
            .order
            .iter()
            .take_while(|(_, id)| {
                ledger
                    .stamped
                    .get(id)
                    .is_some_and(|at| now - at > self.lifetime)
            })
            .cloned()
            .collect();
        for entry in stale {
            ledger.stamped.remove(&entry.1);
            ledger.order.remove(&entry);
        }

        if ledger.stamped.contains_key(message) {
            return Ok(false);
        }

        ledger.tick += 1;
        let tick = ledger.tick;
        ledger.stamped.insert(message.clone(), now);
        ledger.order.insert((tick, message.clone()));

        while ledger.stamped.len() > self.capacity {
            let Some(oldest) = ledger.order.iter().next().cloned() else {
                break;
            };
            ledger.stamped.remove(&oldest.1);
            ledger.order.remove(&oldest);
        }

        Ok(true)
    }

    fn count(&self) -> Result<usize> {
        Ok(self.ledger.lock().stamped.len())
    }
}

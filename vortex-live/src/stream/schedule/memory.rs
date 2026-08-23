use std::collections::HashMap;

use parking_lot::RwLock;

use crate::error::Result;
use crate::ports::stream_schedule::StreamSchedule;
use crate::stream::schedule::entry::ScheduleEntry;
use vortex_core::room::room_id::RoomId;

struct Planned {
    entry: ScheduleEntry,
    until: f64,
}

pub struct MemoryStreamSchedule {
    rooms: RwLock<HashMap<i64, Planned>>,
}

impl Default for MemoryStreamSchedule {
    fn default() -> Self {
        MemoryStreamSchedule::new()
    }
}

impl MemoryStreamSchedule {
    pub fn new() -> Self {
        MemoryStreamSchedule {
            rooms: RwLock::new(HashMap::new()),
        }
    }
}

impl StreamSchedule for MemoryStreamSchedule {
    fn put(&self, room: RoomId, entry: &ScheduleEntry, until: f64, now: f64) -> Result<()> {
        let mut rooms = self.rooms.write();
        rooms.retain(|_, planned| planned.until > now);
        rooms.insert(
            room.value(),
            Planned {
                entry: entry.clone(),
                until,
            },
        );
        Ok(())
    }

    fn find(&self, room: RoomId, now: f64) -> Result<Option<ScheduleEntry>> {
        Ok(self
            .rooms
            .read()
            .get(&room.value())
            .filter(|planned| planned.until > now)
            .map(|planned| planned.entry.clone()))
    }

    fn forget(&self, room: RoomId, now: f64) -> Result<bool> {
        Ok(self
            .rooms
            .write()
            .remove(&room.value())
            .is_some_and(|planned| planned.until > now))
    }

    fn claim_due(&self, now: f64) -> Result<Option<ScheduleEntry>> {
        let mut rooms = self.rooms.write();
        rooms.retain(|_, planned| planned.until > now);
        let Some(room_id) = rooms
            .iter()
            .filter(|(_, planned)| planned.entry.due_at(now))
            .min_by(|left, right| left.1.entry.at.cmp(&right.1.entry.at))
            .map(|(room_id, _)| *room_id)
        else {
            return Ok(None);
        };
        Ok(rooms.remove(&room_id).map(|planned| planned.entry))
    }
}

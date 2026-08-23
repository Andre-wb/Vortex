use std::collections::HashMap;

use parking_lot::RwLock;

use crate::error::Result;
use crate::ports::recording_marks::RecordingMarks;
use crate::recording::mark::Mark;
use crate::recording::started::Started;
use vortex_core::room::room_id::RoomId;

pub struct MemoryRecordingMarks {
    running: RwLock<HashMap<i64, Mark>>,
}

impl Default for MemoryRecordingMarks {
    fn default() -> Self {
        MemoryRecordingMarks::new()
    }
}

impl MemoryRecordingMarks {
    pub fn new() -> Self {
        MemoryRecordingMarks {
            running: RwLock::new(HashMap::new()),
        }
    }
}

impl RecordingMarks for MemoryRecordingMarks {
    fn start(&self, room: RoomId, mark: &Mark, now: f64) -> Result<Started> {
        let mut running = self.running.write();
        running.retain(|_, kept| kept.alive_at(now));
        if let Some(kept) = running.get(&room.value()) {
            return Ok(Started::Already(kept.clone()));
        }
        running.insert(room.value(), mark.clone());
        Ok(Started::Fresh(mark.clone()))
    }

    fn stop(&self, room: RoomId, now: f64) -> Result<Option<Mark>> {
        Ok(self
            .running
            .write()
            .remove(&room.value())
            .filter(|kept| kept.alive_at(now)))
    }

    fn find(&self, room: RoomId, now: f64) -> Result<Option<Mark>> {
        Ok(self
            .running
            .read()
            .get(&room.value())
            .filter(|kept| kept.alive_at(now))
            .cloned())
    }

    fn renew(&self, room: RoomId, until: f64, now: f64) -> Result<bool> {
        let mut running = self.running.write();
        let Some(kept) = running.get_mut(&room.value()) else {
            return Ok(false);
        };
        if !kept.alive_at(now) {
            return Ok(false);
        }
        *kept = kept.renewed(until);
        Ok(true)
    }
}

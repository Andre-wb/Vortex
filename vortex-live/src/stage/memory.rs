use std::collections::HashMap;

use parking_lot::RwLock;
use vortex_auth::account::user_id::UserId;

use crate::error::Result;
use crate::ports::stage_board::StageBoard;
use crate::stage::record::Stage;
use vortex_core::room::room_id::RoomId;

pub struct MemoryStageBoard {
    open: RwLock<HashMap<i64, Stage>>,
}

impl Default for MemoryStageBoard {
    fn default() -> Self {
        MemoryStageBoard::new()
    }
}

impl MemoryStageBoard {
    pub fn new() -> Self {
        MemoryStageBoard {
            open: RwLock::new(HashMap::new()),
        }
    }

    fn amended(
        &self,
        room: RoomId,
        now: f64,
        change: impl FnOnce(&Stage) -> Stage,
    ) -> Option<Stage> {
        let mut open = self.open.write();
        let held = open.get(&room.value()).filter(|held| held.alive_at(now))?;
        let changed = change(held);
        open.insert(room.value(), changed.clone());
        Some(changed)
    }
}

impl StageBoard for MemoryStageBoard {
    fn open(&self, room: RoomId, stage: &Stage, now: f64) -> Result<()> {
        let mut open = self.open.write();
        open.retain(|_, held| held.alive_at(now));
        open.insert(room.value(), stage.clone());
        Ok(())
    }

    fn close(&self, room: RoomId, now: f64) -> Result<bool> {
        Ok(self
            .open
            .write()
            .remove(&room.value())
            .is_some_and(|held| held.alive_at(now)))
    }

    fn find(&self, room: RoomId, now: f64) -> Result<Option<Stage>> {
        Ok(self
            .open
            .read()
            .get(&room.value())
            .filter(|held| held.alive_at(now))
            .cloned())
    }

    fn add(&self, room: RoomId, speaker: UserId, until: f64, now: f64) -> Result<Option<Stage>> {
        Ok(self.amended(room, now, |held| held.with(speaker.value(), until)))
    }

    fn remove(&self, room: RoomId, speaker: UserId, until: f64, now: f64) -> Result<Option<Stage>> {
        Ok(self.amended(room, now, |held| held.without(speaker.value(), until)))
    }

    fn renew(&self, room: RoomId, until: f64, now: f64) -> Result<bool> {
        Ok(self
            .amended(room, now, |held| held.renewed(until))
            .is_some())
    }
}

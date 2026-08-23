use std::sync::Arc;

use crate::federation::virtual_room::VirtualRoomId;
use crate::ports::virtual_room_ids::VirtualRoomIds;
use crate::registry::refusal::Result;

pub struct VirtualRoomIdService {
    ids: Arc<dyn VirtualRoomIds>,
}

impl VirtualRoomIdService {
    pub fn new(ids: Arc<dyn VirtualRoomIds>) -> Self {
        VirtualRoomIdService { ids }
    }

    pub fn next(&self) -> Result<VirtualRoomId> {
        self.ids.next()
    }

    pub fn reserve_below(&self, taken: i64) -> Result<()> {
        match VirtualRoomId::of(taken) {
            Some(named) => self.ids.reserve_below(named),
            None => Ok(()),
        }
    }
}

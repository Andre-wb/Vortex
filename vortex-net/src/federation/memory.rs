use parking_lot::Mutex;

use crate::federation::virtual_room::VirtualRoomId;
use crate::ports::virtual_room_ids::VirtualRoomIds;
use crate::registry::refusal::Result;

pub struct MemoryVirtualRoomIds {
    handed: Mutex<i64>,
}

impl MemoryVirtualRoomIds {
    pub fn new() -> Self {
        MemoryVirtualRoomIds {
            handed: Mutex::new(0),
        }
    }
}

impl Default for MemoryVirtualRoomIds {
    fn default() -> Self {
        Self::new()
    }
}

impl VirtualRoomIds for MemoryVirtualRoomIds {
    fn next(&self) -> Result<VirtualRoomId> {
        let mut handed = self.handed.lock();
        *handed -= 1;
        Ok(VirtualRoomId::of(*handed).expect("счётчик выдаёт только отрицательные номера"))
    }

    fn reserve_below(&self, taken: VirtualRoomId) -> Result<()> {
        let mut handed = self.handed.lock();
        if taken.value() < *handed {
            *handed = taken.value();
        }
        Ok(())
    }
}

use crate::federation::virtual_room::VirtualRoomId;
use crate::ports::virtual_room_ids::VirtualRoomIds;
use crate::registry::refusal::{RegistryError, Result};

pub struct UnavailableVirtualRoomIds;

impl UnavailableVirtualRoomIds {
    pub fn new() -> Self {
        UnavailableVirtualRoomIds
    }
}

impl Default for UnavailableVirtualRoomIds {
    fn default() -> Self {
        Self::new()
    }
}

impl VirtualRoomIds for UnavailableVirtualRoomIds {
    fn next(&self) -> Result<VirtualRoomId> {
        Err(RegistryError::Unavailable)
    }

    fn reserve_below(&self, _taken: VirtualRoomId) -> Result<()> {
        Err(RegistryError::Unavailable)
    }
}

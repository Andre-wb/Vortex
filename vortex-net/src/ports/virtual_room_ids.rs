use crate::federation::virtual_room::VirtualRoomId;
use crate::registry::refusal::Result;

pub trait VirtualRoomIds: Send + Sync {
    fn next(&self) -> Result<VirtualRoomId>;

    fn reserve_below(&self, taken: VirtualRoomId) -> Result<()>;
}

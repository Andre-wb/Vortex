use crate::error::Result;
use crate::store::swapped::Swapped;
use crate::stream::record::Stream;
use vortex_core::room::room_id::RoomId;

pub trait StreamRecords: Send + Sync {
    fn open(&self, room: RoomId, stream: &Stream, now: f64) -> Result<bool>;

    fn find(&self, room: RoomId, now: f64) -> Result<Option<Stream>>;

    fn swap(
        &self,
        room: RoomId,
        expected: &Stream,
        replacement: &Stream,
        now: f64,
    ) -> Result<Swapped>;

    fn forget(&self, room: RoomId, now: f64) -> Result<Option<Stream>>;
}

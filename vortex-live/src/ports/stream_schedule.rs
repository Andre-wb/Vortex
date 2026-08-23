use crate::error::Result;
use crate::stream::schedule::entry::ScheduleEntry;
use vortex_core::room::room_id::RoomId;

pub trait StreamSchedule: Send + Sync {
    fn put(&self, room: RoomId, entry: &ScheduleEntry, until: f64, now: f64) -> Result<()>;

    fn find(&self, room: RoomId, now: f64) -> Result<Option<ScheduleEntry>>;

    fn forget(&self, room: RoomId, now: f64) -> Result<bool>;

    fn claim_due(&self, now: f64) -> Result<Option<ScheduleEntry>>;
}

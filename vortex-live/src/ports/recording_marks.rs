use crate::error::Result;
use crate::recording::mark::Mark;
use crate::recording::started::Started;
use vortex_core::room::room_id::RoomId;

pub trait RecordingMarks: Send + Sync {
    fn start(&self, room: RoomId, mark: &Mark, now: f64) -> Result<Started>;

    fn stop(&self, room: RoomId, now: f64) -> Result<Option<Mark>>;

    fn find(&self, room: RoomId, now: f64) -> Result<Option<Mark>>;

    fn renew(&self, room: RoomId, until: f64, now: f64) -> Result<bool>;
}

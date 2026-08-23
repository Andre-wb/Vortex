use vortex_auth::account::user_id::UserId;

use crate::error::Result;
use crate::stage::record::Stage;
use vortex_core::room::room_id::RoomId;

pub trait StageBoard: Send + Sync {
    fn open(&self, room: RoomId, stage: &Stage, now: f64) -> Result<()>;

    fn close(&self, room: RoomId, now: f64) -> Result<bool>;

    fn find(&self, room: RoomId, now: f64) -> Result<Option<Stage>>;

    fn add(&self, room: RoomId, speaker: UserId, until: f64, now: f64) -> Result<Option<Stage>>;

    fn remove(&self, room: RoomId, speaker: UserId, until: f64, now: f64) -> Result<Option<Stage>>;

    fn renew(&self, room: RoomId, until: f64, now: f64) -> Result<bool>;
}

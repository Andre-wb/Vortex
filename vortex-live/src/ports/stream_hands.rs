use vortex_auth::account::user_id::UserId;

use crate::error::Result;
use vortex_core::room::room_id::RoomId;

pub trait StreamHands: Send + Sync {
    fn raise(&self, room: RoomId, user: UserId, at: f64, until: f64, now: f64) -> Result<()>;

    fn lower(&self, room: RoomId, user: UserId, now: f64) -> Result<()>;

    fn queue(&self, room: RoomId, now: f64) -> Result<Vec<i64>>;

    fn clear(&self, room: RoomId, now: f64) -> Result<()>;

    fn renew(&self, room: RoomId, until: f64, now: f64) -> Result<bool>;
}

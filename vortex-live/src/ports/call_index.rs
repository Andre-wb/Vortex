use crate::call::call_id::CallId;
use crate::error::Result;
use vortex_core::room::room_id::RoomId;

pub trait CallIndex: Send + Sync {
    fn claim(&self, room: RoomId, call: &CallId, until: f64, now: f64) -> Result<Option<CallId>>;

    fn find(&self, room: RoomId, now: f64) -> Result<Option<CallId>>;

    fn release(&self, room: RoomId, call: &CallId, now: f64) -> Result<bool>;

    fn renew(&self, room: RoomId, until: f64, now: f64) -> Result<bool>;
}

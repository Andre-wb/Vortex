use vortex_auth::account::user_id::UserId;
use vortex_core::room::room_id::RoomId;

use crate::error::Result;
use crate::mailbox::entry::Entry;
use crate::message::payload::Payload;

pub trait RoomMailbox: Send + Sync {
    fn deposit(&self, room: RoomId, readers: &[UserId], payload: &Payload, now: f64) -> Result<()>;

    fn collect(&self, room: RoomId, reader: UserId) -> Result<Vec<Entry>>;

    fn sweep(&self, now: f64) -> Result<usize>;

    fn tally(&self) -> Result<(usize, usize)>;
}

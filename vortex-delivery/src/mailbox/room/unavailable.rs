use vortex_auth::account::user_id::UserId;
use vortex_core::room::room_id::RoomId;

use crate::error::{Result, StateError};
use crate::mailbox::entry::Entry;
use crate::message::payload::Payload;
use crate::ports::room_mailbox::RoomMailbox;

pub struct UnavailableRoomMailbox;

impl UnavailableRoomMailbox {
    pub fn new() -> Self {
        UnavailableRoomMailbox
    }
}

impl Default for UnavailableRoomMailbox {
    fn default() -> Self {
        Self::new()
    }
}

impl RoomMailbox for UnavailableRoomMailbox {
    fn deposit(
        &self,
        _room: RoomId,
        _readers: &[UserId],
        _payload: &Payload,
        _now: f64,
    ) -> Result<()> {
        Err(StateError::Unavailable)
    }

    fn collect(&self, _room: RoomId, _reader: UserId) -> Result<Vec<Entry>> {
        Err(StateError::Unavailable)
    }

    fn sweep(&self, _now: f64) -> Result<usize> {
        Err(StateError::Unavailable)
    }

    fn tally(&self) -> Result<(usize, usize)> {
        Err(StateError::Unavailable)
    }
}

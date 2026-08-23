use std::sync::Arc;

use vortex_auth::account::user_id::UserId;
use vortex_core::room::room_id::RoomId;

use crate::error::Result;
use crate::mailbox::limits;
use crate::message::payload::Payload;
use crate::ports::room_mailbox::RoomMailbox;

pub struct RoomMailboxService {
    mailbox: Arc<dyn RoomMailbox>,
    lifetime: f64,
}

impl RoomMailboxService {
    pub fn new(mailbox: Arc<dyn RoomMailbox>) -> Self {
        RoomMailboxService {
            mailbox,
            lifetime: limits::ROOM_LIFETIME_SECONDS,
        }
    }

    pub fn deposit(
        &self,
        room: RoomId,
        readers: &[UserId],
        payload: &Payload,
        now: f64,
    ) -> Result<()> {
        if readers.is_empty() {
            return Ok(());
        }
        self.mailbox.deposit(room, readers, payload, now)
    }

    pub fn collect(&self, room: RoomId, reader: UserId, now: f64) -> Result<Vec<String>> {
        let entries = self.mailbox.collect(room, reader)?;
        Ok(entries
            .into_iter()
            .filter(|entry| !entry.stale(now, self.lifetime))
            .map(|entry| entry.payload().written().to_owned())
            .collect())
    }

    pub fn sweep(&self, now: f64) -> Result<usize> {
        self.mailbox.sweep(now)
    }

    pub fn tally(&self) -> Result<(usize, usize)> {
        self.mailbox.tally()
    }
}

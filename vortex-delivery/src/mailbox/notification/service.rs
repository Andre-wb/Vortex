use std::sync::Arc;

use vortex_auth::account::user_id::UserId;

use crate::error::Result;
use crate::mailbox::limits;
use crate::message::payload::Payload;
use crate::ports::notification_mailbox::NotificationMailbox;

pub struct NotificationMailboxService {
    mailbox: Arc<dyn NotificationMailbox>,
    lifetime: f64,
}

impl NotificationMailboxService {
    pub fn new(mailbox: Arc<dyn NotificationMailbox>) -> Self {
        NotificationMailboxService {
            mailbox,
            lifetime: limits::NOTIFICATION_LIFETIME_SECONDS,
        }
    }

    pub fn deposit(&self, reader: UserId, payload: &Payload, now: f64) -> Result<()> {
        self.mailbox.deposit(reader, payload, now)
    }

    pub fn collect(&self, reader: UserId, now: f64) -> Result<Vec<String>> {
        let entries = self.mailbox.collect(reader)?;
        Ok(entries
            .into_iter()
            .filter(|entry| !entry.stale(now, self.lifetime))
            .map(|entry| entry.payload().written().to_owned())
            .collect())
    }

    pub fn tally(&self) -> Result<(usize, usize)> {
        self.mailbox.tally()
    }
}

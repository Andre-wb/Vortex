use vortex_auth::account::user_id::UserId;

use crate::error::{Result, StateError};
use crate::mailbox::entry::Entry;
use crate::message::payload::Payload;
use crate::ports::notification_mailbox::NotificationMailbox;

pub struct UnavailableNotificationMailbox;

impl UnavailableNotificationMailbox {
    pub fn new() -> Self {
        UnavailableNotificationMailbox
    }
}

impl Default for UnavailableNotificationMailbox {
    fn default() -> Self {
        Self::new()
    }
}

impl NotificationMailbox for UnavailableNotificationMailbox {
    fn deposit(&self, _reader: UserId, _payload: &Payload, _now: f64) -> Result<()> {
        Err(StateError::Unavailable)
    }

    fn collect(&self, _reader: UserId) -> Result<Vec<Entry>> {
        Err(StateError::Unavailable)
    }

    fn tally(&self) -> Result<(usize, usize)> {
        Err(StateError::Unavailable)
    }
}

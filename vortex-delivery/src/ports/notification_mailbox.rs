use vortex_auth::account::user_id::UserId;

use crate::error::Result;
use crate::mailbox::entry::Entry;
use crate::message::payload::Payload;

pub trait NotificationMailbox: Send + Sync {
    fn deposit(&self, reader: UserId, payload: &Payload, now: f64) -> Result<()>;

    fn collect(&self, reader: UserId) -> Result<Vec<Entry>>;

    fn tally(&self) -> Result<(usize, usize)>;
}

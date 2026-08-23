use crate::error::Result;
use crate::message::identifier::MessageId;

pub trait SeenMessages: Send + Sync {
    fn remember(&self, message: &MessageId, now: f64) -> Result<bool>;

    fn count(&self) -> Result<usize>;
}

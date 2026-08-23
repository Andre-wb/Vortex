use crate::error::{Result, StateError};
use crate::message::identifier::MessageId;
use crate::ports::seen_messages::SeenMessages;

pub struct UnavailableSeenMessages;

impl UnavailableSeenMessages {
    pub fn new() -> Self {
        UnavailableSeenMessages
    }
}

impl Default for UnavailableSeenMessages {
    fn default() -> Self {
        Self::new()
    }
}

impl SeenMessages for UnavailableSeenMessages {
    fn remember(&self, _message: &MessageId, _now: f64) -> Result<bool> {
        Err(StateError::Unavailable)
    }

    fn count(&self) -> Result<usize> {
        Err(StateError::Unavailable)
    }
}

use std::sync::Arc;

use crate::error::Result;
use crate::message::identifier::MessageId;
use crate::ports::seen_messages::SeenMessages;

pub struct DeduplicationService {
    seen: Arc<dyn SeenMessages>,
}

impl DeduplicationService {
    pub fn new(seen: Arc<dyn SeenMessages>) -> Self {
        DeduplicationService { seen }
    }

    pub fn is_repeat(&self, message: &MessageId, now: f64) -> Result<bool> {
        self.seen.remember(message, now).map(|fresh| !fresh)
    }

    pub fn remembered(&self) -> Result<usize> {
        self.seen.count()
    }
}

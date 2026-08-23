use crate::error::{Result, StateError};
use crate::ports::upload_sessions::UploadSessions;
use crate::upload::chunk::ChunkIndex;
use crate::upload::identifier::UploadId;
use crate::upload::session::Session;

pub struct UnavailableUploadSessions;

impl UnavailableUploadSessions {
    pub fn new() -> Self {
        UnavailableUploadSessions
    }
}

impl Default for UnavailableUploadSessions {
    fn default() -> Self {
        Self::new()
    }
}

impl UploadSessions for UnavailableUploadSessions {
    fn open(&self, _session: &Session) -> Result<()> {
        Err(StateError::Unavailable)
    }

    fn find(&self, _id: &UploadId) -> Result<Option<Session>> {
        Err(StateError::Unavailable)
    }

    fn take_chunk(&self, _id: &UploadId, _chunk: ChunkIndex) -> Result<Option<Session>> {
        Err(StateError::Unavailable)
    }

    fn close(&self, _id: &UploadId) -> Result<bool> {
        Err(StateError::Unavailable)
    }

    fn sweep(&self, _now: f64) -> Result<Vec<UploadId>> {
        Err(StateError::Unavailable)
    }

    fn count(&self) -> Result<usize> {
        Err(StateError::Unavailable)
    }
}

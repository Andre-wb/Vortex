use std::collections::HashMap;

use parking_lot::Mutex;

use crate::error::Result;
use crate::ports::upload_sessions::UploadSessions;
use crate::upload::chunk::ChunkIndex;
use crate::upload::identifier::UploadId;
use crate::upload::session::Session;

pub struct MemoryUploadSessions {
    sessions: Mutex<HashMap<UploadId, Session>>,
}

impl MemoryUploadSessions {
    pub fn new() -> Self {
        MemoryUploadSessions {
            sessions: Mutex::new(HashMap::new()),
        }
    }
}

impl Default for MemoryUploadSessions {
    fn default() -> Self {
        Self::new()
    }
}

impl UploadSessions for MemoryUploadSessions {
    fn open(&self, session: &Session) -> Result<()> {
        self.sessions
            .lock()
            .insert(session.id().clone(), session.clone());
        Ok(())
    }

    fn find(&self, id: &UploadId) -> Result<Option<Session>> {
        Ok(self.sessions.lock().get(id).cloned())
    }

    fn take_chunk(&self, id: &UploadId, chunk: ChunkIndex) -> Result<Option<Session>> {
        let mut sessions = self.sessions.lock();
        let Some(session) = sessions.get_mut(id) else {
            return Ok(None);
        };
        let mut received = session.received().clone();
        received.insert(chunk.value());
        *session = session.clone().with_received(received);
        Ok(Some(session.clone()))
    }

    fn close(&self, id: &UploadId) -> Result<bool> {
        Ok(self.sessions.lock().remove(id).is_some())
    }

    fn sweep(&self, now: f64) -> Result<Vec<UploadId>> {
        let mut sessions = self.sessions.lock();
        let stale: Vec<UploadId> = sessions
            .values()
            .filter(|session| session.stale(now))
            .map(|session| session.id().clone())
            .collect();
        for id in &stale {
            sessions.remove(id);
        }
        Ok(stale)
    }

    fn count(&self) -> Result<usize> {
        Ok(self.sessions.lock().len())
    }
}

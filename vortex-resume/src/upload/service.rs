use std::sync::Arc;

use crate::error::Result;
use crate::ports::upload_sessions::UploadSessions;
use crate::upload::chunk::ChunkIndex;
use crate::upload::identifier::UploadId;
use crate::upload::lookup::{Found, Reception};
use crate::upload::session::Session;

pub struct UploadSessionService {
    sessions: Arc<dyn UploadSessions>,
}

impl UploadSessionService {
    pub fn new(sessions: Arc<dyn UploadSessions>) -> Self {
        UploadSessionService { sessions }
    }

    pub fn open(&self, session: &Session) -> Result<()> {
        self.sessions.open(session)
    }

    pub fn find(&self, id: &UploadId, now: f64) -> Result<Found> {
        let Some(session) = self.sessions.find(id)? else {
            return Ok(Found::Missing);
        };
        if session.stale(now) {
            self.sessions.close(id)?;
            return Ok(Found::Expired);
        }
        Ok(Found::Live(Box::new(session)))
    }

    pub fn receive(&self, id: &UploadId, chunk: ChunkIndex, now: f64) -> Result<Reception> {
        let session = match self.find(id, now)? {
            Found::Live(session) => session,
            Found::Expired => return Ok(Reception::Expired),
            Found::Missing => return Ok(Reception::Missing),
        };

        if !chunk.inside(session.total_chunks()) {
            return Ok(Reception::OutsidePlan {
                total: session.total_chunks(),
            });
        }
        if session.holds(chunk) {
            return Ok(Reception::AlreadyHeld(session.progress()));
        }

        match self.sessions.take_chunk(id, chunk)? {
            Some(session) => Ok(Reception::Accepted(session.progress())),
            None => Ok(Reception::Missing),
        }
    }

    pub fn close(&self, id: &UploadId) -> Result<bool> {
        self.sessions.close(id)
    }

    pub fn sweep(&self, now: f64) -> Result<Vec<UploadId>> {
        self.sessions.sweep(now)
    }

    pub fn count(&self) -> Result<usize> {
        self.sessions.count()
    }
}

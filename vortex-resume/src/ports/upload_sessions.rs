use crate::error::Result;
use crate::upload::chunk::ChunkIndex;
use crate::upload::identifier::UploadId;
use crate::upload::session::Session;

pub trait UploadSessions: Send + Sync {
    fn open(&self, session: &Session) -> Result<()>;

    fn find(&self, id: &UploadId) -> Result<Option<Session>>;

    fn take_chunk(&self, id: &UploadId, chunk: ChunkIndex) -> Result<Option<Session>>;

    fn close(&self, id: &UploadId) -> Result<bool>;

    fn sweep(&self, now: f64) -> Result<Vec<UploadId>>;

    fn count(&self) -> Result<usize>;
}

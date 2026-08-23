use std::collections::BTreeSet;

use vortex_auth::account::user_id::UserId;
use vortex_core::room::room_id::RoomId;

use crate::upload::chunk::ChunkIndex;
use crate::upload::file_name::FileName;
use crate::upload::identifier::UploadId;
use crate::upload::limits;
use crate::upload::progress::Progress;

#[derive(Debug, Clone, PartialEq)]
pub struct Session {
    id: UploadId,
    room: RoomId,
    owner: UserId,
    file_name: FileName,
    file_bytes: u64,
    total_chunks: u32,
    file_digest: String,
    opened_at: f64,
    received: BTreeSet<u32>,
}

impl Session {
    #[allow(clippy::too_many_arguments)]
    pub fn opened(
        id: UploadId,
        room: RoomId,
        owner: UserId,
        file_name: FileName,
        file_bytes: u64,
        total_chunks: u32,
        file_digest: String,
        opened_at: f64,
    ) -> Self {
        Session {
            id,
            room,
            owner,
            file_name,
            file_bytes,
            total_chunks,
            file_digest,
            opened_at,
            received: BTreeSet::new(),
        }
    }

    pub fn with_received(mut self, received: BTreeSet<u32>) -> Self {
        self.received = received;
        self
    }

    pub fn id(&self) -> &UploadId {
        &self.id
    }

    pub fn room(&self) -> RoomId {
        self.room
    }

    pub fn owner(&self) -> UserId {
        self.owner
    }

    pub fn file_name(&self) -> &FileName {
        &self.file_name
    }

    pub fn file_bytes(&self) -> u64 {
        self.file_bytes
    }

    pub fn total_chunks(&self) -> u32 {
        self.total_chunks
    }

    pub fn file_digest(&self) -> &str {
        &self.file_digest
    }

    pub fn opened_at(&self) -> f64 {
        self.opened_at
    }

    pub fn received(&self) -> &BTreeSet<u32> {
        &self.received
    }

    pub fn holds(&self, chunk: ChunkIndex) -> bool {
        self.received.contains(&chunk.value())
    }

    pub fn deadline(&self) -> f64 {
        self.opened_at + limits::SESSION_LIFETIME_SECONDS
    }

    pub fn stale(&self, now: f64) -> bool {
        now >= self.deadline()
    }

    pub fn progress(&self) -> Progress {
        let missing = (0..self.total_chunks)
            .filter(|index| !self.received.contains(index))
            .collect();
        Progress::of(self.received.len() as u32, self.total_chunks, missing)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::Session;
    use crate::upload::chunk::ChunkIndex;
    use crate::upload::file_name::FileName;
    use crate::upload::identifier::UploadId;
    use crate::upload::limits;
    use vortex_auth::account::user_id::UserId;
    use vortex_core::room::room_id::RoomId;

    fn session(opened_at: f64) -> Session {
        Session::opened(
            UploadId::parse("token").unwrap(),
            RoomId::of(3).unwrap(),
            UserId::of(7).unwrap(),
            FileName::parse("a.bin").unwrap(),
            4096,
            4,
            "ab".repeat(32),
            opened_at,
        )
    }

    #[test]
    fn a_fresh_session_holds_no_chunk() {
        let session = session(1000.0);
        assert!(session.received().is_empty());
        assert!(!session.holds(ChunkIndex::of(0)));
        assert_eq!(session.progress().missing(), &[0, 1, 2, 3]);
    }

    #[test]
    fn a_session_goes_stale_at_its_deadline_and_not_before() {
        let session = session(1000.0);
        assert!(!session.stale(1000.0 + limits::SESSION_LIFETIME_SECONDS - 0.001));
        assert!(session.stale(1000.0 + limits::SESSION_LIFETIME_SECONDS));
    }

    #[test]
    fn missing_chunks_are_told_in_order() {
        let session = session(1000.0).with_received(BTreeSet::from([2, 0]));
        assert_eq!(session.progress().missing(), &[1, 3]);
        assert_eq!(session.progress().received(), 2);
    }
}

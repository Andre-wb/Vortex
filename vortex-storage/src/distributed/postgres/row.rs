use time::PrimitiveDateTime;

use crate::distributed::chunk::ChunkPlacement;
use crate::distributed::file::DistributedFile;
use crate::time::stamp::Stamp;

pub struct FileRow {
    pub id: i32,
    pub file_hash: String,
    pub filename: String,
    pub total_size: i32,
    pub chunk_count: i32,
    pub uploader_id: i32,
    pub created_at: Option<PrimitiveDateTime>,
}

impl FileRow {
    pub fn into_file(self, chunks: Vec<ChunkPlacement>, fallback: Stamp) -> DistributedFile {
        DistributedFile {
            file_hash: self.file_hash,
            filename: self.filename,
            total_size: i64::from(self.total_size),
            chunk_count: i64::from(self.chunk_count),
            uploader_id: i64::from(self.uploader_id),
            created_at: self.created_at.map(Stamp::from_reading).unwrap_or(fallback),
            chunks,
        }
    }
}

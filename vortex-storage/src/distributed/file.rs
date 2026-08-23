use crate::distributed::chunk::ChunkPlacement;
use crate::time::stamp::Stamp;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DistributedFile {
    pub file_hash: String,
    pub filename: String,
    pub total_size: i64,
    pub chunk_count: i64,
    pub uploader_id: i64,
    pub created_at: Stamp,
    pub chunks: Vec<ChunkPlacement>,
}

#[cfg(test)]
mod tests {
    use super::DistributedFile;
    use crate::distributed::chunk::ChunkPlacement;
    use crate::time::stamp::Stamp;

    #[test]
    fn a_file_carries_the_chunks_that_make_it_up() {
        let file = DistributedFile {
            file_hash: "cd".repeat(32),
            filename: "notes.txt".to_owned(),
            total_size: 2048,
            chunk_count: 2,
            uploader_id: 7,
            created_at: Stamp::from_unix(1_785_834_930, 0).unwrap(),
            chunks: vec![ChunkPlacement {
                chunk_hash: "ab".repeat(32),
                chunk_index: 0,
                size: 1024,
                node_ip: "10.0.0.1".to_owned(),
                node_port: 9000,
            }],
        };
        assert_eq!(file.chunks.len(), 1);
        assert_eq!(file.chunk_count, 2);
    }
}

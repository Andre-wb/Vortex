use crate::upload::limits;
use crate::upload::refusal::Refusal;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkPlan {
    chunk_bytes: u64,
    total_chunks: u32,
}

impl ChunkPlan {
    pub fn of(file_bytes: u64, asked_chunk_bytes: u64) -> Result<Self, Refusal> {
        if file_bytes == 0 {
            return Err(Refusal::EmptyFile);
        }
        let chunk_bytes = asked_chunk_bytes.clamp(limits::MIN_CHUNK_BYTES, limits::MAX_CHUNK_BYTES);
        let total = file_bytes.div_ceil(chunk_bytes);
        if total > u64::from(limits::MAX_CHUNKS) {
            return Err(Refusal::TooManyChunks { asked: total });
        }
        Ok(ChunkPlan {
            chunk_bytes,
            total_chunks: total as u32,
        })
    }

    pub fn chunk_bytes(self) -> u64 {
        self.chunk_bytes
    }

    pub fn total_chunks(self) -> u32 {
        self.total_chunks
    }
}

#[cfg(test)]
mod tests {
    use super::ChunkPlan;
    use crate::upload::limits;
    use crate::upload::refusal::Refusal;

    #[test]
    fn a_file_shorter_than_one_chunk_still_takes_one() {
        let plan = ChunkPlan::of(1, limits::DEFAULT_CHUNK_BYTES).unwrap();
        assert_eq!(plan.total_chunks(), 1);
    }

    #[test]
    fn a_remainder_takes_a_chunk_of_its_own() {
        let plan =
            ChunkPlan::of(limits::DEFAULT_CHUNK_BYTES + 1, limits::DEFAULT_CHUNK_BYTES).unwrap();
        assert_eq!(plan.total_chunks(), 2);
    }

    #[test]
    fn an_asked_chunk_size_is_kept_inside_the_agreed_bounds() {
        assert_eq!(
            ChunkPlan::of(1_000_000, 1).unwrap().chunk_bytes(),
            limits::MIN_CHUNK_BYTES
        );
        assert_eq!(
            ChunkPlan::of(1_000_000, u64::MAX).unwrap().chunk_bytes(),
            limits::MAX_CHUNK_BYTES
        );
    }

    #[test]
    fn an_empty_file_names_no_plan() {
        assert_eq!(
            ChunkPlan::of(0, limits::DEFAULT_CHUNK_BYTES),
            Err(Refusal::EmptyFile)
        );
    }

    #[test]
    fn a_file_needing_more_chunks_than_allowed_is_refused() {
        let file = limits::MIN_CHUNK_BYTES * u64::from(limits::MAX_CHUNKS) + 1;
        assert_eq!(
            ChunkPlan::of(file, limits::MIN_CHUNK_BYTES),
            Err(Refusal::TooManyChunks {
                asked: u64::from(limits::MAX_CHUNKS) + 1
            })
        );
    }

    #[test]
    fn the_largest_chunk_size_lifts_the_ceiling_on_file_size() {
        let file = limits::MAX_CHUNK_BYTES * u64::from(limits::MAX_CHUNKS);
        assert!(ChunkPlan::of(file, limits::MAX_CHUNK_BYTES).is_ok());
    }
}

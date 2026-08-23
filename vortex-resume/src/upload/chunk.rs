#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ChunkIndex(u32);

impl ChunkIndex {
    pub fn of(value: u32) -> Self {
        ChunkIndex(value)
    }

    pub fn value(self) -> u32 {
        self.0
    }

    pub fn inside(self, total: u32) -> bool {
        self.0 < total
    }
}

#[cfg(test)]
mod tests {
    use super::ChunkIndex;

    #[test]
    fn a_chunk_belongs_to_a_plan_of_at_least_its_successor() {
        assert!(ChunkIndex::of(0).inside(1));
        assert!(ChunkIndex::of(3).inside(4));
    }

    #[test]
    fn a_chunk_past_the_last_one_belongs_to_no_plan() {
        assert!(!ChunkIndex::of(4).inside(4));
        assert!(!ChunkIndex::of(0).inside(0));
    }
}

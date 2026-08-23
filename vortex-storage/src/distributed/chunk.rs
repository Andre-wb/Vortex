#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkPlacement {
    pub chunk_hash: String,
    pub chunk_index: i64,
    pub size: i64,
    pub node_ip: String,
    pub node_port: i64,
}

#[cfg(test)]
mod tests {
    use super::ChunkPlacement;

    fn placement(index: i64) -> ChunkPlacement {
        ChunkPlacement {
            chunk_hash: "ab".repeat(32),
            chunk_index: index,
            size: 1024,
            node_ip: "10.0.0.1".to_owned(),
            node_port: 9000,
        }
    }

    #[test]
    fn a_placement_names_the_node_that_holds_the_chunk() {
        let chunk = placement(0);
        assert_eq!(
            (chunk.node_ip.as_str(), chunk.node_port),
            ("10.0.0.1", 9000)
        );
    }

    #[test]
    fn two_chunks_of_one_file_differ_by_their_index() {
        assert_ne!(placement(0), placement(1));
    }
}

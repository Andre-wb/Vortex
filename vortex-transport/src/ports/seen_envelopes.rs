pub trait SeenEnvelopes: Send + Sync {
    fn prune(&self, now: i64);

    fn remember(&self, envelope: &[u8], expires_at: i64) -> bool;

    fn len(&self) -> usize;

    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

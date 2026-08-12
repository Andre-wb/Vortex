pub trait ProbeSightings: Send + Sync {
    fn remember(&self, fingerprint: &str, now: f64) -> Option<f64>;

    fn forget_stale(&self, cutoff: f64);

    fn len(&self) -> usize;

    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

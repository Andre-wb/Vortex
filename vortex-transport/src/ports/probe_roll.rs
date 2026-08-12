pub trait ProbeRoll: Send + Sync {
    fn record(&self, peer: &str, now: f64) -> bool;

    fn holds(&self, peer: &str) -> bool;

    fn forget_stale(&self, cutoff: f64);

    fn len(&self) -> usize;

    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

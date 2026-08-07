pub trait RateLimiter: Send + Sync {
    fn allow(&self, key: &str, limit: u32) -> bool;

    fn forget_stale(&self);

    fn tracked_keys(&self) -> usize;
}

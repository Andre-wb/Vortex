pub trait Clock: Send + Sync {
    fn monotonic_seconds(&self) -> f64;
}

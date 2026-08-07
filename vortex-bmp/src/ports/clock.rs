pub trait Clock: Send + Sync {
    fn unix_seconds(&self) -> f64;
}

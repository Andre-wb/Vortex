pub trait Clock: Send + Sync {
    fn unix_seconds(&self) -> i64;
}

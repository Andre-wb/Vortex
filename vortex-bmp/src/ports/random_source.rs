pub trait RandomSource: Send + Sync {
    fn fill_bytes(&self, buffer: &mut [u8]);
}

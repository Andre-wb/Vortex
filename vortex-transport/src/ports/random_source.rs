pub trait RandomSource: Send + Sync {
    fn fill_bytes(&self, buffer: &mut [u8]);

    fn bytes(&self, n: usize) -> Vec<u8> {
        let mut buffer = vec![0u8; n];
        self.fill_bytes(&mut buffer);
        buffer
    }
}

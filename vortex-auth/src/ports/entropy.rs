pub trait Entropy: Send + Sync {
    fn fill(&self, into: &mut [u8]);
}

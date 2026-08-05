//! Реализации источника случайности.

pub mod os_random;
pub mod sequence_random;

pub use os_random::OsRandom;
pub use sequence_random::SequenceRandom;

//! Учёт статистики.

pub mod in_memory;
pub mod noop;
pub mod snapshot;

pub use in_memory::InMemoryStats;
pub use noop::NoopStats;
pub use snapshot::StatsSnapshot;

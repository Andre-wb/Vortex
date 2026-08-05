//! Политики принятия решения о блокировке.

pub mod action_based;
pub mod monitor_only;
pub mod severity_threshold;

pub use action_based::DenyListPolicy;
pub use monitor_only::MonitorOnlyPolicy;
pub use severity_threshold::SeverityThresholdPolicy;

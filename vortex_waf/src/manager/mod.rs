//! Управляющее API поверх собранного WAF.

pub mod dto;
pub mod waf_manager;

pub use dto::{BlockedIpView, OperationResult, RuleView};
pub use waf_manager::WafManager;

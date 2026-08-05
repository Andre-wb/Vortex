//! Инспекторы отдельных заголовков.

pub mod referer;
pub mod user_agent;

pub use referer::RefererInspector;
pub use user_agent::UserAgentInspector;

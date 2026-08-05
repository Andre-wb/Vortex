//! Транспортный слой: приём запроса, определение источника, готовые ответы.

pub mod client_ip;
pub mod excluded_paths;
pub mod guard;
pub mod guard_builder;
pub mod outcome;
pub mod raw_request;
pub mod request_factory;
pub mod responses;

pub use excluded_paths::ExcludedPaths;
pub use guard::WafGuard;
pub use guard_builder::GuardBuilder;
pub use outcome::GuardOutcome;
pub use raw_request::RawHttpRequest;
pub use request_factory::RequestFactory;

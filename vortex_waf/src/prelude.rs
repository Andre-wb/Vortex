//! Всё, что нужно для типового использования, одним импортом.
//!
//! ```
//! use vortex_waf::prelude::*;
//!
//! let waf = WafBuilder::new().build().unwrap();
//! let request = RequestBuilder::new()
//!     .client_ip("203.0.113.7")
//!     .path("/search")
//!     .query("q=%27+OR+1%3D1+--+")
//!     .build();
//! assert!(waf.analyze(&request).block);
//! ```

pub use crate::config::{EngineConfig, GuardConfig};
pub use crate::domain::{
    Action, Analysis, ClientIp, Finding, HttpMethod, InspectedRequest, RequestBuilder, RuleId,
    Severity, Timestamp,
};
pub use crate::engine::{WafBuilder, WafEngine, WafRuntime, WafStatsReport};
pub use crate::error::{Result, WafError};
pub use crate::http::{ExcludedPaths, GuardBuilder, GuardOutcome, RawHttpRequest, WafGuard};
pub use crate::manager::WafManager;
pub use crate::ports::{
    BlockPolicy, BodyParser, ChallengeIssuer, ChallengeVerifier, Clock, Inspector, IpBlocker,
    IpGate, Matcher, RateLimiter, Rule, RuleSource, StatsReporter,
};

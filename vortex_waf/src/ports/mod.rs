//! Порты — абстракции, от которых зависит движок (буква D в SOLID).
//!
//! Ни один файл в этом модуле не содержит логики: только трейты и типы их
//! результатов. Реализации живут в соседних модулях-адаптерах.

pub mod block_policy;
pub mod block_store;
pub mod body_parser;
pub mod challenge_issuer;
pub mod challenge_verifier;
pub mod client_ip_resolver;
pub mod clock;
pub mod inspector;
pub mod ip_allow_list;
pub mod ip_blocker;
pub mod ip_deny_list;
pub mod ip_gate;
pub mod matcher;
pub mod prunable;
pub mod random_source;
pub mod rate_limiter;
pub mod rule;
pub mod rule_activity;
pub mod rule_source;
pub mod signer;
pub mod stats_collector;
pub mod stats_reporter;

pub use block_policy::BlockPolicy;
pub use block_store::BlockStore;
pub use body_parser::{BodyParser, ParseOutcome};
pub use challenge_issuer::ChallengeIssuer;
pub use challenge_verifier::ChallengeVerifier;
pub use client_ip_resolver::ClientIpResolver;
pub use clock::Clock;
pub use inspector::Inspector;
pub use ip_allow_list::IpAllowList;
pub use ip_blocker::IpBlocker;
pub use ip_deny_list::IpDenyList;
pub use ip_gate::IpGate;
pub use matcher::Matcher;
pub use prunable::Prunable;
pub use random_source::RandomSource;
pub use rate_limiter::{RateLimitOutcome, RateLimiter};
pub use rule::Rule;
pub use rule_activity::{RuleActivity, RuleActivityRecorder};
pub use rule_source::RuleSource;
pub use signer::Signer;
pub use stats_collector::StatsCollector;
pub use stats_reporter::StatsReporter;

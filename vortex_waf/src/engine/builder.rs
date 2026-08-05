//! Сборка движка со штатным набором компонентов.
//!
//! Проводка зависимостей собрана здесь одним местом, поэтому подмена любой
//! детали — вопрос одного вызова, а не правки движка.

use crate::blocking::allow_list::InMemoryAllowList;
use crate::blocking::deny_list::InMemoryDenyList;
use crate::blocking::memory_store::InMemoryBlockStore;
use crate::blocking::reputation::IpReputation;
use crate::body::parsers::{FormUrlEncodedParser, JsonBodyParser, MultipartParser};
use crate::body::registry::ParserRegistry;
use crate::config::engine_config::EngineConfig;
use crate::engine::maintenance::MaintenanceService;
use crate::engine::runtime::WafRuntime;
use crate::error::Result;
use crate::inspectors::body::BodyInspector;
use crate::inspectors::composite::CompositeInspector;
use crate::inspectors::headers::{RefererInspector, UserAgentInspector};
use crate::inspectors::method::MethodInspector;
use crate::inspectors::params::ParamsInspector;
use crate::inspectors::path::{
    PathExtensionInspector, PathLengthInspector, PathSignatureInspector, PathTraversalInspector,
};
use crate::inspectors::url_length::UrlLengthInspector;
use crate::policy::severity_threshold::SeverityThresholdPolicy;
use crate::ports::block_policy::BlockPolicy;
use crate::ports::clock::Clock;
use crate::ports::inspector::Inspector;
use crate::ports::ip_allow_list::IpAllowList;
use crate::ports::rule_source::RuleSource;
use crate::ratelimit::config::RateLimitConfig;
use crate::ratelimit::sliding_window::SlidingWindowRateLimiter;
use crate::rules::catalog_source::CatalogRuleSource;
use crate::scanning::field_scanner::FieldScanner;
use crate::scanning::safe_params::SafeParams;
use crate::stats::in_memory::InMemoryStats;
use crate::time::system_clock::SystemClock;
use std::sync::Arc;

pub struct WafBuilder {
    config: EngineConfig,
    clock: Arc<dyn Clock>,
    rule_source: Arc<dyn RuleSource>,
    policy: Option<Arc<dyn BlockPolicy>>,
    stats: Arc<InMemoryStats>,
    extra_inspectors: Vec<Arc<dyn Inspector>>,
}

impl Default for WafBuilder {
    fn default() -> Self {
        WafBuilder {
            config: EngineConfig::default(),
            clock: Arc::new(SystemClock::new()),
            rule_source: Arc::new(CatalogRuleSource::new()),
            policy: None,
            stats: Arc::new(InMemoryStats::new()),
            extra_inspectors: Vec::new(),
        }
    }
}

impl WafBuilder {
    pub fn new() -> Self {
        WafBuilder::default()
    }

    pub fn with_config(mut self, config: EngineConfig) -> Self {
        self.config = config;
        self
    }

    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    pub fn with_rule_source(mut self, rule_source: Arc<dyn RuleSource>) -> Self {
        self.rule_source = rule_source;
        self
    }

    pub fn with_policy(mut self, policy: Arc<dyn BlockPolicy>) -> Self {
        self.policy = Some(policy);
        self
    }

    pub fn with_stats(mut self, stats: Arc<InMemoryStats>) -> Self {
        self.stats = stats;
        self
    }

    /// Дополнительный инспектор — выполняется после штатных.
    pub fn with_inspector(mut self, inspector: Arc<dyn Inspector>) -> Self {
        self.extra_inspectors.push(inspector);
        self
    }

    pub fn build(self) -> Result<WafRuntime> {
        let stats = self.stats;

        let allow_list = Arc::new(InMemoryAllowList::with_loopback());
        for ip in &self.config.whitelist_ips {
            allow_list.add(ip.as_str().into());
        }
        let deny_list = Arc::new(InMemoryDenyList::empty());
        let block_store = Arc::new(InMemoryBlockStore::new(self.clock.clone()));
        let reputation = Arc::new(IpReputation::new(
            allow_list.clone(),
            deny_list.clone(),
            block_store.clone(),
            self.clock.clone(),
            stats.clone(),
        ));

        let rate_limiter = Arc::new(SlidingWindowRateLimiter::new(
            RateLimitConfig {
                requests: self.config.rate_limit_requests,
                window_secs: self.config.rate_limit_window_secs,
                ..RateLimitConfig::default()
            },
            self.clock.clone(),
            allow_list.clone(),
            reputation.clone(),
        ));

        let scanner = Arc::new(FieldScanner::new(
            self.rule_source.rules()?,
            SafeParams::new(&self.config.safe_params),
            stats.clone(),
            self.clock.clone(),
        ));

        let registry = ParserRegistry::new()
            .with(Arc::new(MultipartParser::new()))
            .with(Arc::new(JsonBodyParser::new()))
            .with(Arc::new(FormUrlEncodedParser::new()));

        // Порядок инспекторов задаёт порядок находок в ответе.
        let mut composite = CompositeInspector::new()
            .with(Arc::new(MethodInspector::new()))
            .with(Arc::new(UrlLengthInspector::new()))
            .with(Arc::new(UserAgentInspector::new()))
            .with(Arc::new(RefererInspector::new()))
            .with(Arc::new(ParamsInspector::new(scanner.clone())))
            .with(Arc::new(BodyInspector::new(
                registry,
                scanner.clone(),
                self.config.max_content_length,
            )))
            .with(Arc::new(PathTraversalInspector::new()))
            .with(Arc::new(PathExtensionInspector::new()))
            .with(Arc::new(PathLengthInspector::new()))
            .with(Arc::new(PathSignatureInspector::new(scanner.clone())));
        for inspector in self.extra_inspectors {
            composite = composite.with(inspector);
        }

        let policy = self
            .policy
            .unwrap_or_else(|| Arc::new(SeverityThresholdPolicy::new(self.config.block_threshold)));

        let maintenance = MaintenanceService::new(vec![block_store.clone(), rate_limiter.clone()]);

        Ok(WafRuntime::new(
            crate::engine::waf_engine::WafEngine::new(
                reputation.clone(),
                rate_limiter,
                Arc::new(composite),
                policy,
                stats.clone(),
            ),
            reputation,
            allow_list,
            deny_list,
            block_store,
            scanner,
            stats,
            maintenance,
            self.config,
        ))
    }
}

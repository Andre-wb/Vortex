//! Собранный экземпляр WAF: движок вместе со своими компонентами.
//!
//! Существует, чтобы транспорту и управляющему API было к чему обращаться,
//! не пересобирая зависимости самостоятельно.

use crate::blocking::allow_list::InMemoryAllowList;
use crate::blocking::deny_list::InMemoryDenyList;
use crate::blocking::memory_store::InMemoryBlockStore;
use crate::blocking::reputation::IpReputation;
use crate::config::engine_config::EngineConfig;
use crate::domain::analysis::Analysis;
use crate::domain::request::InspectedRequest;
use crate::engine::maintenance::{MaintenanceService, PruneReport};
use crate::engine::waf_engine::WafEngine;
use crate::scanning::field_scanner::FieldScanner;
use crate::stats::in_memory::InMemoryStats;
use std::sync::Arc;

pub struct WafRuntime {
    engine: WafEngine,
    reputation: Arc<IpReputation>,
    allow_list: Arc<InMemoryAllowList>,
    deny_list: Arc<InMemoryDenyList>,
    block_store: Arc<InMemoryBlockStore>,
    scanner: Arc<FieldScanner>,
    stats: Arc<InMemoryStats>,
    maintenance: MaintenanceService,
    config: EngineConfig,
}

impl WafRuntime {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        engine: WafEngine,
        reputation: Arc<IpReputation>,
        allow_list: Arc<InMemoryAllowList>,
        deny_list: Arc<InMemoryDenyList>,
        block_store: Arc<InMemoryBlockStore>,
        scanner: Arc<FieldScanner>,
        stats: Arc<InMemoryStats>,
        maintenance: MaintenanceService,
        config: EngineConfig,
    ) -> Self {
        WafRuntime {
            engine,
            reputation,
            allow_list,
            deny_list,
            block_store,
            scanner,
            stats,
            maintenance,
            config,
        }
    }

    pub fn analyze(&self, request: &InspectedRequest) -> Analysis {
        self.engine.analyze(request)
    }

    pub fn engine(&self) -> &WafEngine {
        &self.engine
    }

    pub fn reputation(&self) -> &Arc<IpReputation> {
        &self.reputation
    }

    pub fn allow_list(&self) -> &Arc<InMemoryAllowList> {
        &self.allow_list
    }

    pub fn deny_list(&self) -> &Arc<InMemoryDenyList> {
        &self.deny_list
    }

    pub fn block_store(&self) -> &Arc<InMemoryBlockStore> {
        &self.block_store
    }

    pub fn scanner(&self) -> &Arc<FieldScanner> {
        &self.scanner
    }

    pub fn stats(&self) -> &Arc<InMemoryStats> {
        &self.stats
    }

    pub fn config(&self) -> &EngineConfig {
        &self.config
    }

    /// Уборка просроченных блокировок и неактивной истории запросов.
    pub fn run_maintenance(&self) -> Vec<PruneReport> {
        self.maintenance.run()
    }
}

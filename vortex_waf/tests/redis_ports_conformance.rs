mod support;

use std::sync::Arc;

use vortex_waf::ports::prunable_block_store::PrunableBlockStore;
use vortex_waf::ports::request_history::RequestHistory;
use vortex_waf::redis::block_store::RedisBlockStore;
use vortex_waf::redis::request_history::RedisRequestHistory;
use vortex_waf::testing::{block_store_conformance, request_history_conformance};
use vortex_waf::time::manual_clock::ManualClock;

#[test]
fn the_redis_block_store_satisfies_the_same_port_contract_as_memory() {
    if support::backbone(&support::unique_prefix("waf-block-probe")).is_none() {
        eprintln!("Redis недоступен — проверка хранилища блокировок пропущена");
        return;
    }
    let make = |clock: Arc<ManualClock>| -> Arc<dyn PrunableBlockStore> {
        let prefix = support::unique_prefix("waf-block");
        Arc::new(RedisBlockStore::new(
            support::backbone(&prefix).unwrap(),
            clock,
        ))
    };
    block_store_conformance::check_all(&make);
}

#[test]
fn the_redis_request_history_satisfies_the_same_port_contract_as_memory() {
    if support::backbone(&support::unique_prefix("waf-rate-probe")).is_none() {
        eprintln!("Redis недоступен — проверка истории обращений пропущена");
        return;
    }
    let make = || -> Arc<dyn RequestHistory> {
        let prefix = support::unique_prefix("waf-rate");
        Arc::new(RedisRequestHistory::new(
            support::backbone(&prefix).unwrap(),
        ))
    };
    request_history_conformance::check_all(&make);
}

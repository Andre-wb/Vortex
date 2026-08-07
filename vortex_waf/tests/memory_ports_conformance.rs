use std::sync::Arc;

use vortex_waf::blocking::memory_store::InMemoryBlockStore;
use vortex_waf::ports::prunable_block_store::PrunableBlockStore;
use vortex_waf::ports::request_history::RequestHistory;
use vortex_waf::ratelimit::memory_history::InMemoryRequestHistory;
use vortex_waf::testing::{block_store_conformance, request_history_conformance};
use vortex_waf::time::manual_clock::ManualClock;

#[test]
fn the_in_memory_block_store_satisfies_the_port_contract() {
    let make = |clock: Arc<ManualClock>| -> Arc<dyn PrunableBlockStore> {
        Arc::new(InMemoryBlockStore::new(clock))
    };
    block_store_conformance::check_all(&make);
}

#[test]
fn the_in_memory_request_history_satisfies_the_port_contract() {
    let make = || -> Arc<dyn RequestHistory> { Arc::new(InMemoryRequestHistory::new()) };
    request_history_conformance::check_all(&make);
}

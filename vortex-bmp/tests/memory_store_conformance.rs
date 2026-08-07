use std::sync::Arc;

use vortex_bmp::config::storage::StorageConfig;
use vortex_bmp::ports::clock::Clock;
use vortex_bmp::ports::mailbox_store::MailboxStore;
use vortex_bmp::store::memory_store::MemoryMailboxStore;
use vortex_bmp::testing::store_conformance;

#[test]
fn the_in_memory_store_satisfies_the_port_contract() {
    let make = |clock: Arc<dyn Clock>, config: StorageConfig| -> Arc<dyn MailboxStore> {
        Arc::new(MemoryMailboxStore::new(clock, config))
    };
    store_conformance::check_all(&make);
}

mod support;

use std::sync::Arc;

use vortex_bmp::config::storage::StorageConfig;
use vortex_bmp::ports::clock::Clock;
use vortex_bmp::ports::mailbox_store::MailboxStore;
use vortex_bmp::testing::store_conformance;
use vortex_redis::bmp::mailbox_store::RedisMailboxStore;

#[test]
fn the_redis_store_satisfies_the_same_port_contract_as_memory() {
    let make = |clock: Arc<dyn Clock>, config: StorageConfig| -> Arc<dyn MailboxStore> {
        let prefix = support::unique_prefix("bmp-store");
        match support::backbone(&prefix) {
            Some(backbone) => Arc::new(RedisMailboxStore::new(backbone, clock, config)),
            None => Arc::new(vortex_bmp::store::memory_store::MemoryMailboxStore::new(
                clock, config,
            )),
        }
    };

    if support::backbone(&support::unique_prefix("bmp-probe")).is_none() {
        eprintln!("Redis недоступен — проверка соответствия Redis-хранилища пропущена");
        return;
    }
    store_conformance::check_all(&make);
}

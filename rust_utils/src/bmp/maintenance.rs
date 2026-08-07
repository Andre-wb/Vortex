use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use vortex_bmp::config::maintenance::MaintenanceConfig;
use vortex_bmp::service::mailbox_service::BmpService;

static RUNNING: AtomicBool = AtomicBool::new(false);

pub fn start(service: Arc<BmpService>, config: MaintenanceConfig) -> bool {
    if RUNNING.swap(true, Ordering::SeqCst) {
        return false;
    }

    thread::spawn(move || loop {
        thread::sleep(Duration::from_secs(config.interval_secs));
        let removed = service.collect_garbage();
        let stats = service.stats();
        let storage = service.storage();
        log::debug!(
            "BMP: убрано {removed}, ящиков {}/{}, занято {}/{} байт, отказов {}, клиентов под учётом {}",
            stats.active_mailboxes,
            storage.max_mailboxes,
            stats.stored_bytes,
            storage.max_stored_bytes,
            stats.total_refused,
            service.tracked_rate_keys()
        );
    });
    true
}

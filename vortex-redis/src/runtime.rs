use std::future::Future;
use std::sync::OnceLock;

use tokio::runtime::{Builder, Runtime};

static RUNTIME: OnceLock<Runtime> = OnceLock::new();

pub fn shared() -> &'static Runtime {
    RUNTIME.get_or_init(|| {
        Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("vortex-redis")
            .enable_all()
            .build()
            .expect("не удалось создать среду выполнения для Redis")
    })
}

pub fn block_on<F: Future>(future: F) -> F::Output {
    shared().block_on(future)
}

#[cfg(test)]
mod tests {
    use super::block_on;

    #[test]
    fn the_shared_runtime_drives_futures_from_a_blocking_caller() {
        assert_eq!(block_on(async { 21 * 2 }), 42);
    }

    #[test]
    fn the_runtime_is_created_once_and_reused() {
        assert!(std::ptr::eq(super::shared(), super::shared()));
    }
}

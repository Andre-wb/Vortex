use std::future::Future;
use std::sync::OnceLock;

use tokio::runtime::{Builder, Runtime};

static RUNTIME: OnceLock<Runtime> = OnceLock::new();

pub fn shared() -> &'static Runtime {
    RUNTIME.get_or_init(|| {
        Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("vortex-storage")
            .enable_all()
            .build()
            .expect("не удалось создать среду выполнения для Postgres")
    })
}

pub fn block_on<F: Future>(future: F) -> F::Output {
    shared().block_on(future)
}

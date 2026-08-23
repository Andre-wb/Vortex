use once_cell::sync::Lazy;
use parking_lot::RwLock;
use vortex_storage::config::dsn::PgConfig;
use vortex_storage::error::{Result, StorageError};
use vortex_storage::pool::handle::PgHandle;

use crate::storage::runtime;

static HANDLE: Lazy<RwLock<Option<PgHandle>>> = Lazy::new(|| RwLock::new(None));

pub fn connect(config: PgConfig) -> Result<()> {
    let handle = runtime::block_on(PgHandle::connect(&config))?;
    *HANDLE.write() = Some(handle);
    Ok(())
}

pub fn is_connected() -> bool {
    HANDLE.read().is_some()
}

pub fn handle() -> Result<PgHandle> {
    HANDLE.read().clone().ok_or(StorageError::Unconfigured)
}

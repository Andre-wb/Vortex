//! Хранилище блокировок, которое умеет само вычищать просроченные записи.
//!
//! Существует, чтобы `WafRuntime` держал реализацию за одним трейт-объектом:
//! управляющему API нужен `BlockStore`, фоновой уборке — `Prunable`.

use crate::ports::block_store::BlockStore;
use crate::ports::prunable::Prunable;

pub trait PrunableBlockStore: BlockStore + Prunable {}

impl<T: BlockStore + Prunable> PrunableBlockStore for T {}

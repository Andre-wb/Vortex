//! Поставщик набора правил.
//!
//! OCP: подключение своего набора (из файла, БД, удалённого фида) — это новая
//! реализация трейта, а не правка движка.

use crate::error::Result;
use crate::ports::rule::Rule;
use std::sync::Arc;

pub trait RuleSource: Send + Sync {
    fn rules(&self) -> Result<Vec<Arc<dyn Rule>>>;
}

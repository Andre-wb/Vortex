//! Политика: превращает набор находок в решение блокировать или пропустить.
//!
//! OCP: режим наблюдения, порог по действию правила или квота по числу находок —
//! это новые реализации, движок не меняется.

use crate::domain::decision::Decision;
use crate::domain::finding::Finding;

pub trait BlockPolicy: Send + Sync {
    fn decide(&self, findings: &[Finding]) -> Decision;
}

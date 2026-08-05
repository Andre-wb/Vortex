//! Учёт срабатываний правил.
//!
//! В Python-версии счётчик жил прямо в объекте правила и мутировался при каждом
//! сопоставлении. Здесь это отдельная ответственность: правило остаётся чистым
//! предикатом.

use crate::domain::rule_id::RuleId;
use crate::domain::timestamp::Timestamp;

/// Сводка по одному правилу.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuleActivity {
    pub trigger_count: u64,
    pub last_triggered: Option<Timestamp>,
}

pub trait RuleActivityRecorder: Send + Sync {
    fn record_match(&self, rule_id: &RuleId, at: Timestamp);
}

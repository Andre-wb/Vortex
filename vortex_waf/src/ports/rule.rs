//! Правило детектирования.
//!
//! Правило не хранит счётчик срабатываний — учёт вынесен в
//! [`crate::ports::rule_activity::RuleActivityRecorder`]. Благодаря этому
//! правило неизменяемо, разделяется между потоками без блокировок и имеет одну
//! причину для изменения (SRP).

use crate::domain::rule_meta::RuleMeta;
use crate::ports::matcher::Matcher;

pub trait Rule: Matcher {
    fn meta(&self) -> &RuleMeta;
}

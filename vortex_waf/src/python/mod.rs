//! Привязка к Python на PyO3.
//!
//! Собирается только с флагом `--features python`. Логики здесь нет: разбор
//! аргументов и сборка результата поверх [`crate::interop`].

pub mod engine;
pub mod extract;
pub mod module;

pub use engine::PyWafEngine;

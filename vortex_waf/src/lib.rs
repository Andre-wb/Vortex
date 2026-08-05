//! Web Application Firewall для Vortex.
//!
//! Крейт разложен по слоям: домен ничего не знает о хранилищах, движок зависит
//! только от трейтов в [`ports`], а конкретные реализации собираются в
//! [`engine::builder`]. Разбор архитектуры и соответствие принципам SOLID —
//! в `README.md`.

#![forbid(unsafe_code)]

pub mod blocking;
pub mod body;
pub mod captcha;
pub mod config;
pub mod domain;
pub mod engine;
pub mod error;
pub mod http;
pub mod inspectors;
pub mod interop;
pub mod manager;
pub mod observability;
pub mod policy;
pub mod ports;
pub mod prelude;
#[cfg(feature = "python")]
pub mod python;
pub mod random;
pub mod ratelimit;
pub mod rules;
pub mod scanning;
pub mod stats;
pub mod time;
pub mod util;

pub use engine::builder::WafBuilder;
pub use engine::runtime::WafRuntime;
pub use error::{Result, WafError};

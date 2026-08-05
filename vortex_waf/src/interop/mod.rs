//! Слой взаимодействия с внешним миром в примитивных типах.
//!
//! Отделён от языковых привязок намеренно: вся логика преобразования и фасад
//! проверяются обычными тестами крейта, а на долю привязки остаётся только
//! разбор аргументов.

pub mod config_spec;
pub mod facade;
pub mod finding_map;
pub mod request_spec;
pub mod stats_view;

pub use config_spec::ConfigSpec;
pub use facade::{resolve_client_ip, WafFacade};
pub use finding_map::{AnalysisView, FlatMap};
pub use request_spec::RequestSpec;
pub use stats_view::StatsView;
